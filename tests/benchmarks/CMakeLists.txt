# Non-gating benchmark targets.
#
# These are EXCLUDE_FROM_ALL so a normal build never compiles them and CTest
# never runs them. Build explicitly with:
#
#   cmake --build --preset linux --target users_benchmark
#
# and run the resulting binary by hand. Wall-clock results are diagnostic only
# and are intentionally not registered as CTest pass/fail thresholds.

if(TARGET ww AND UNIX)
  add_executable(bufferstream_optimization_benchmark EXCLUDE_FROM_ALL bufferstream_optimization_benchmark.c)
  target_link_libraries(bufferstream_optimization_benchmark PRIVATE ww)
  get_filename_component(WW_BENCHMARK_BUILD_TREE "${CMAKE_BINARY_DIR}" NAME)
  target_compile_definitions(bufferstream_optimization_benchmark PRIVATE
    WW_BENCHMARK_COMPILER_ID="${CMAKE_C_COMPILER_ID}"
    WW_BENCHMARK_COMPILER_VERSION="${CMAKE_C_COMPILER_VERSION}"
    WW_BENCHMARK_BUILD_TREE="${WW_BENCHMARK_BUILD_TREE}"
    WW_BENCHMARK_BUILD_CONFIG="$<CONFIG>")

  add_executable(device_writer_channel_benchmark EXCLUDE_FROM_ALL device_writer_channel_benchmark.c)
  target_link_libraries(device_writer_channel_benchmark PRIVATE ww)

  add_executable(users_benchmark EXCLUDE_FROM_ALL users_benchmark.c)
  target_link_libraries(users_benchmark PRIVATE ww)

  add_executable(wfrand_benchmark EXCLUDE_FROM_ALL wfrand_benchmark.c)
  target_link_libraries(wfrand_benchmark PRIVATE ww)

  if(TARGET StreamToPackets)
    add_executable(streamtopackets_selection_benchmark EXCLUDE_FROM_ALL streamtopackets_selection_benchmark.c)
    target_link_libraries(streamtopackets_selection_benchmark PRIVATE StreamToPackets ww)
  endif()
endif()
