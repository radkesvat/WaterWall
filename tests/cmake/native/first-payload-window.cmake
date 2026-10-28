if(LINUX AND TARGET ProxyClientCommon)
  waterwall_add_native_executable(first_payload_window_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/proxy_client/first_payload_window_test.c
    LIBRARIES ProxyClientCommon ww)
  target_link_options(first_payload_window_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=wtimerAdd" "-Wl,--wrap=wtimerReset")
  add_dependencies(waterwall_unit_tests first_payload_window_test)
  add_waterwall_unit_test(waterwall.first_payload_window_unit first_payload_window_test
    "unit;tunnels;timers;lifetime;reentrant")
endif()
