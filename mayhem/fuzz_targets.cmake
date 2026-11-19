# Injected into upstream's top-level project(mooncake) by mayhem/build.sh via
# -DCMAKE_PROJECT_mooncake_INCLUDE=<this file>. Upstream's CMake is untouched:
# the harness targets are defined by a deferred call that runs after the
# top-level CMakeLists.txt has created transfer_engine and the store libraries.
# DEFER arguments are expanded when the call runs, so bake the path in now.
set(_mayhem_fuzz_defs "${CMAKE_CURRENT_LIST_DIR}/fuzz_targets_defs.cmake")
cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY [[${CMAKE_SOURCE_DIR}]] CALL include [[${_mayhem_fuzz_defs}]])")
