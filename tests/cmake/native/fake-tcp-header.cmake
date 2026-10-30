if(BUILD_TESTING AND WW_BUILD_UNIT_TESTS)
  if(TARGET waterwall_unit_tests)
    set(fake_tcp_unit_aggregate waterwall_unit_tests)
  else()
    set(fake_tcp_unit_aggregate waterwall_platform_unit_tests)
  endif()
  if(TARGET FakeTcpHeader)
    waterwall_add_native_executable(fake_tcp_header_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/fake_tcp_header/fake_tcp_header_test.c)
    target_link_libraries(fake_tcp_header_test PRIVATE FakeTcpHeader ww)
    if(TARGET IpManipulator)
      target_link_libraries(fake_tcp_header_test PRIVATE IpManipulator)
      target_include_directories(fake_tcp_header_test PRIVATE
        ${PROJECT_SOURCE_DIR}/tunnels/IpManipulator/common
        ${PROJECT_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator)
      target_compile_definitions(fake_tcp_header_test PRIVATE TEST_FAKE_TCP_FLAGS=1)
    endif()
    set_target_properties(fake_tcp_header_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
    waterwall_register_native_test(waterwall.fake_tcp_header_unit fake_tcp_header_test
      "unit;tunnels;fake-tcp;udp;packet;configuration" AGGREGATE ${fake_tcp_unit_aggregate})
  endif()
  # Linux already registers this target in runtime-address_context.cmake.
  if(TARGET RawSocket AND NOT TARGET rawsocket_config_test)
    waterwall_add_native_executable(rawsocket_config_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rawsocket/rawsocket_config_test.c)
    target_link_libraries(rawsocket_config_test PRIVATE RawSocket ww)
    waterwall_register_native_test(waterwall.rawsocket_config_unit rawsocket_config_test
      "unit;tunnels;rawsocket;configuration" AGGREGATE ${fake_tcp_unit_aggregate})
  endif()
endif()
