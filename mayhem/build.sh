#!/usr/bin/env bash
#
# mayhem/build.sh — build Mooncake's fuzz harnesses and the unit tests mayhem/test.sh runs.
#
# Runs in the commit image as `mayhem` in /mayhem, offline-capable: every dependency upstream's
# CMake would download is pre-fetched by mayhem/Dockerfile under /opt/toolchains/deps and fed to
# FetchContent with FETCHCONTENT_FULLY_DISCONNECTED=ON. Re-running is incremental (ninja).
#
#  1) mayhem/build/fuzz: upstream's own top-level CMake build (transfer engine with the TCP
#     transport + mooncake-store), the WHOLE project compiled with $SANITIZER_FLAGS,
#     -fsanitize=fuzzer-no-link (coverage) and $DEBUG_FLAGS. The harness targets are injected
#     with CMAKE_PROJECT_mooncake_INCLUDE (mayhem/fuzz_targets.cmake), so no upstream file is
#     edited. Each harness is linked as /mayhem/fuzz_<name> (libFuzzer) and
#     /mayhem/fuzz_<name>-standalone (run-once reproducer); both link mayhem/lsan_off.cc
#     (LeakSanitizer off at build time, ASan/UBSan stay on).
#  2) mayhem/build/test: a separate build with upstream's normal flags and BUILD_UNIT_TESTS=ON,
#     of only the gtest binaries mayhem/test.sh runs.
#
# Both build dirs are under mayhem/build/, which upstream's .gitignore ("build") ignores.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

DEPS=/opt/toolchains/deps
YLT_SRC="$DEPS/yalantinglibs-54f9c06/src"
GTEST_SRC="$DEPS/googletest-1.17.0/src"
PYBIND11_SRC="$DEPS/pybind11-58c382a/src"

# Upstream's top-level CMakeLists.txt add_subdirectory()s the extern/pybind11 submodule
# unconditionally. A checkout made without submodules leaves it empty: fill it from the
# pinned copy of the same commit.
if [ ! -f extern/pybind11/CMakeLists.txt ]; then
  mkdir -p extern/pybind11
  cp -a "$PYBIND11_SRC/." extern/pybind11/
fi

# Options shared by both builds: TCP-only transfer engine + store, no examples/benchmarks,
# no Rust bindings, no HTTP metadata plugin (needs a live server), offline FetchContent.
# -Wno-error=thread-safety: upstream turns clang's thread-safety analysis into errors, and
# clang 19 flags storage_backend.h:933 (an upstream annotation issue, not a build input).
COMMON_ARGS=(
  -G Ninja
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARK=OFF
  -DWITH_TE=ON -DWITH_STORE=ON -DWITH_STORE_RUST=OFF -DUSE_HTTP=OFF
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON
  -DFETCHCONTENT_SOURCE_DIR_YALANTINGLIBS="$YLT_SRC"
  -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="$GTEST_SRC"
)

# 1) Sanitized + coverage-instrumented project and harnesses. ENABLE_DEBUG_SYMBOLS=OFF drops
#    upstream's trailing plain -g (DWARF 5 on clang 19); $DEBUG_FLAGS supplies -gdwarf-3.
FUZZ_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -S . -B mayhem/build/fuzz "${COMMON_ARGS[@]}" \
  -DBUILD_UNIT_TESTS=OFF -DENABLE_DEBUG_SYMBOLS=OFF \
  -DCMAKE_PROJECT_mooncake_INCLUDE="$SRC/mayhem/fuzz_targets.cmake" \
  -DMAYHEM_LSAN_OFF_SRC="$SRC/mayhem/lsan_off.cc" \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1 $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O1 $DEBUG_FLAGS -Wno-error=thread-safety"
cmake --build mayhem/build/fuzz -j"$MAYHEM_JOBS" --target mayhem_fuzzers

for h in segment_desc handshake_daemon tcp_data_port topology oplog_batch snapshot_codec; do
  install -m 755 "mayhem/build/fuzz/mayhem-fuzz/fuzz_$h" "$SRC/fuzz_$h"
  install -m 755 "mayhem/build/fuzz/mayhem-fuzz/fuzz_$h-standalone" "$SRC/fuzz_$h-standalone"
done

# 2) Unit tests with upstream's normal flags (no sanitizers) for mayhem/test.sh.
cmake -S . -B mayhem/build/test "${COMMON_ARGS[@]}" \
  -DBUILD_UNIT_TESTS=ON \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="-O1" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O1 -Wno-error=thread-safety"
cmake --build mayhem/build/test -j"$MAYHEM_JOBS" --target \
  transfer_metadata_test topology_test tcp_address_validation_test \
  oplog_batch_codec_test batch_oplog_snapshot_codec_test default_config_test
