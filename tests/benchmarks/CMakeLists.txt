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

  if(TARGET StreamToPackets)
    add_executable(streamtopackets_selection_benchmark EXCLUDE_FROM_ALL streamtopackets_selection_benchmark.c)
    target_link_libraries(streamtopackets_selection_benchmark PRIVATE StreamToPackets ww)
  endif()
endif()
