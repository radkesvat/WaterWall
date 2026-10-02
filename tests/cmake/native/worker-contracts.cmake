# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(UNIX)
  waterwall_add_native_executable(widle_table_cancellation_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/widle_table_cancellation_test.c)
  target_link_options(widle_table_cancellation_test PRIVATE
    "-Wl,--wrap=abortProgramNow"
    "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer"
    "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit"
    "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer"
    "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer"
    "-Wl,--wrap=sbufDestroy"
  )
  target_link_libraries(widle_table_cancellation_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests widle_table_cancellation_test)
  add_waterwall_unit_test(
    waterwall.widle_table_cancellation_unit
    widle_table_cancellation_test
    "unit;idle-table;worker-message;ownership;shutdown;tsan"
  )
endif()

