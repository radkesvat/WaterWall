if(TARGET rtmp_session)
  foreach(rtmp_suite IN ITEMS protocol pair)
    waterwall_add_native_executable(rtmp_${rtmp_suite}_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rtmp/rtmp_${rtmp_suite}_test.c
      LIBRARIES rtmp_session ww)
    set_target_properties(rtmp_${rtmp_suite}_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
    add_waterwall_unit_test(waterwall.rtmp_${rtmp_suite}_unit rtmp_${rtmp_suite}_test "unit;tunnels;rtmp")
  endforeach()
endif()

if(TARGET rtmp_protocol)
  waterwall_add_native_executable(rtmp_engine_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rtmp/rtmp_engine_test.c
    LIBRARIES rtmp_protocol ww)
  set_target_properties(rtmp_engine_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.rtmp_engine_unit rtmp_engine_test "unit;tunnels;rtmp")
endif()

if(LINUX AND TARGET RtmpClient AND TARGET RtmpServer)
  waterwall_add_native_executable(rtmp_lifecycle_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rtmp/rtmp_lifecycle_test.c
    LIBRARIES RtmpClient RtmpServer rtmp_session ww)
  target_link_options(rtmp_lifecycle_test PRIVATE
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=getHRTimeUs"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  set_target_properties(rtmp_lifecycle_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.rtmp_lifecycle_unit rtmp_lifecycle_test
    "unit;tunnels;rtmp;lifecycle;reentry;pressure;ownership")
endif()
