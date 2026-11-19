#!/usr/bin/env bash
#
# mayhem/test.sh — RUN Mooncake's own gtest unit tests (built by mayhem/build.sh, normal flags).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream gtest binaries covering the code the harnesses fuzz (handshake framing, segment
# descriptor decode/validation, topology, TCP address validation, oplog + snapshot codecs,
# config loading). Filters keep only tests that need no etcd/redis/RDMA hardware.
B="$SRC/mayhem/build/test"
TESTS=(
  "mooncake-transfer-engine/tests/transfer_metadata_test|TransferMetadataVersionTest.*:TransferMetadataPublicationTest.*:TransferMetadataValidationTest.*:HandshakeFrameTest.*:HandshakeNotifyTest.*:TransferMetadataStaleSegmentInvalidationTest.*:TransferMetadataPollingTest.*"
  "mooncake-transfer-engine/tests/topology_test|*"
  "mooncake-transfer-engine/tests/tcp_address_validation_test|*"
  "mooncake-store/tests/oplog_batch_codec_test|*"
  "mooncake-store/tests/batch_oplog_snapshot_codec_test|*"
  "mooncake-common/tests/default_config_test|*"
)

passed=0 failed=0 skipped=0
for entry in "${TESTS[@]}"; do
  bin="$B/${entry%%|*}" filter="${entry#*|}"
  if [ ! -x "$bin" ]; then
    echo "MISSING test binary $bin (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)); continue
  fi
  log="$(mktemp)"
  (cd "$(dirname "$bin")" && timeout 600 "$bin" --gtest_filter="$filter" --gtest_color=no) >"$log" 2>&1
  rc=$?
  # Count the per-test result lines gtest prints; a run that printed no summary (crash,
  # no-op binary) counts as one failure.
  p=$(grep -cE '^\[       OK \] ' "$log" || true)
  f=$(grep -cE '^\[  FAILED  \] [^ ]+\.[^ ]+( \(|$)' "$log" || true)
  s=$(grep -cE '^\[  SKIPPED \] [^ ]+\.[^ ]+ \(' "$log" || true)
  if ! grep -qE '^\[==========\] [0-9]+ tests? from .* ran\.' "$log" || [ "$p" -eq 0 ]; then
    echo "FAIL $(basename "$bin"): no gtest summary / nothing passed (rc=$rc)"; tail -20 "$log"
    f=$((f + 1))
  elif [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
    echo "FAIL $(basename "$bin"): exit $rc"; tail -20 "$log"; f=1
  fi
  echo "$(basename "$bin"): passed=$p failed=$f skipped=$s"
  passed=$((passed + p)) failed=$((failed + f)) skipped=$((skipped + s))
  rm -f "$log"
done

emit_ctrf "gtest" "$passed" "$failed" "$skipped"
