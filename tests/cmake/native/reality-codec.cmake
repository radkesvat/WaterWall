# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET RealityCommon)
  waterwall_add_native_executable(reality_config_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_config_test.c)
  target_link_libraries(reality_config_test PRIVATE RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_config_test)

  add_waterwall_unit_test(
    waterwall.reality_config_unit
    reality_config_test
    "unit;tunnels;reality;v2;crypto;configuration"
  )

  waterwall_add_native_executable(reality_v2_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_v2_test.c)
  target_compile_definitions(reality_v2_test PRIVATE
    REALITY_TLS_CLIENT_HANDSHAKE_SOURCE="${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/ssl/handshake_client.cc"
  )
  target_link_libraries(reality_v2_test PRIVATE RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_v2_test)

  add_waterwall_unit_test(waterwall.reality_v2_unit reality_v2_test "unit;tunnels;reality;v2;crypto;replay;direction")
endif()

