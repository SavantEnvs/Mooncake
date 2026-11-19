# Fuzz harness targets (see fuzz_targets.cmake). Each harness is linked twice:
# with libFuzzer (fuzz_<name>) and with the run-once standalone driver
# (fuzz_<name>-standalone). Both carry lsan_off.cc.
set(MAYHEM_DIR "${CMAKE_SOURCE_DIR}/mayhem")
set(MAYHEM_LIB_FUZZING_ENGINE "$ENV{LIB_FUZZING_ENGINE}")
if(NOT MAYHEM_LIB_FUZZING_ENGINE)
  set(MAYHEM_LIB_FUZZING_ENGINE "-fsanitize=fuzzer")
endif()
set(MAYHEM_STANDALONE_MAIN "$ENV{STANDALONE_FUZZ_MAIN}")

if(NOT MAYHEM_LSAN_OFF_SRC)
  message(FATAL_ERROR "mayhem/build.sh passes -DMAYHEM_LSAN_OFF_SRC=<mayhem/lsan_off.cc>")
endif()
add_library(mayhem_lsan_off OBJECT "${MAYHEM_LSAN_OFF_SRC}")
add_library(mayhem_standalone_main OBJECT "${MAYHEM_STANDALONE_MAIN}")
set_source_files_properties("${MAYHEM_STANDALONE_MAIN}" PROPERTIES LANGUAGE C)

function(mayhem_fuzzer name)
  set(src "${MAYHEM_DIR}/harnesses/fuzz_${name}.cpp")
  add_executable(fuzz_${name} "${src}" $<TARGET_OBJECTS:mayhem_lsan_off>)
  target_link_libraries(fuzz_${name} PRIVATE ${ARGN})
  target_link_options(fuzz_${name} PRIVATE ${MAYHEM_LIB_FUZZING_ENGINE})
  add_executable(fuzz_${name}-standalone "${src}"
                 $<TARGET_OBJECTS:mayhem_lsan_off>
                 $<TARGET_OBJECTS:mayhem_standalone_main>)
  target_link_libraries(fuzz_${name}-standalone PRIVATE ${ARGN})
  foreach(t fuzz_${name} fuzz_${name}-standalone)
    target_include_directories(${t} PRIVATE "${MAYHEM_DIR}/harnesses")
    set_target_properties(${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                          "${CMAKE_BINARY_DIR}/mayhem-fuzz")
  endforeach()
  list(APPEND MAYHEM_FUZZERS fuzz_${name} fuzz_${name}-standalone)
  set(MAYHEM_FUZZERS ${MAYHEM_FUZZERS} PARENT_SCOPE)
endfunction()

set(MAYHEM_FUZZERS)
mayhem_fuzzer(segment_desc transfer_engine)
mayhem_fuzzer(handshake_daemon transfer_engine)
mayhem_fuzzer(tcp_data_port transfer_engine)
mayhem_fuzzer(topology transfer_engine)
mayhem_fuzzer(oplog_batch mooncake_store_master cachelib_memory_allocator yalantinglibs::yalantinglibs
              glog::glog)
mayhem_fuzzer(snapshot_codec mooncake_store_master cachelib_memory_allocator
              yalantinglibs::yalantinglibs glog::glog)
add_custom_target(mayhem_fuzzers DEPENDS ${MAYHEM_FUZZERS})
