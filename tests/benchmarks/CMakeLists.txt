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
  add_executable(device_writer_channel_benchmark EXCLUDE_FROM_ALL device_writer_channel_benchmark.c)
  target_link_libraries(device_writer_channel_benchmark PRIVATE ww)

  add_executable(users_benchmark EXCLUDE_FROM_ALL users_benchmark.c)
  target_link_libraries(users_benchmark PRIVATE ww)

  add_executable(worker_message_benchmark EXCLUDE_FROM_ALL worker_message_benchmark.c)
  target_link_libraries(worker_message_benchmark PRIVATE ww)
  execute_process(
    COMMAND git -C ${CMAKE_SOURCE_DIR} rev-parse --short=12 HEAD
    OUTPUT_VARIABLE WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )
  if(NOT WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT)
    set(WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT "unknown")
  endif()
  execute_process(
    COMMAND git -C ${CMAKE_SOURCE_DIR} status --porcelain
    OUTPUT_VARIABLE WW_WORKER_MESSAGE_BENCHMARK_SOURCE_STATUS
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )
  if(WW_WORKER_MESSAGE_BENCHMARK_SOURCE_STATUS)
    set(WW_WORKER_MESSAGE_BENCHMARK_SOURCE_DIRTY 1)
  else()
    set(WW_WORKER_MESSAGE_BENCHMARK_SOURCE_DIRTY 0)
  endif()
  target_compile_definitions(worker_message_benchmark PRIVATE
    "WW_WORKER_MESSAGE_BENCHMARK_COMPILER=\"${CMAKE_C_COMPILER_ID}-${CMAKE_C_COMPILER_VERSION}\""
    "WW_WORKER_MESSAGE_BENCHMARK_BUILD_TYPE=\"$<CONFIG>\""
    "WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT=\"${WW_WORKER_MESSAGE_BENCHMARK_SOURCE_COMMIT}\""
    WW_WORKER_MESSAGE_BENCHMARK_SOURCE_DIRTY=${WW_WORKER_MESSAGE_BENCHMARK_SOURCE_DIRTY}
  )

  if(TARGET StreamToPackets)
    add_executable(streamtopackets_selection_benchmark EXCLUDE_FROM_ALL streamtopackets_selection_benchmark.c)
    target_link_libraries(streamtopackets_selection_benchmark PRIVATE StreamToPackets ww)
  endif()
endif()
