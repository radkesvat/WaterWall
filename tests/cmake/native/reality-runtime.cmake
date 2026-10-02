# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET RealityServer)
  waterwall_add_native_executable(reality_tls_binding_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_tls_binding_test.c)
  target_include_directories(reality_tls_binding_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include/RealityServer
  )
  target_link_libraries(reality_tls_binding_test PRIVATE RealityServer RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_tls_binding_test)

  add_waterwall_unit_test(waterwall.reality_tls_binding_unit reality_tls_binding_test "unit;tunnels;reality;v2;tls-parser")
endif()

if(TARGET RealityServer AND TARGET TlsClient)
  waterwall_add_native_executable(reality_tls_binding_interop_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_tls_binding_interop_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_tls_binding_fixture.c)
  target_include_directories(reality_tls_binding_interop_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include/RealityServer
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(reality_tls_binding_interop_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(reality_tls_binding_interop_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(reality_tls_binding_interop_test PRIVATE
    RealityServer RealityCommon TlsClient ww ssl crypto
  )
  add_dependencies(waterwall_unit_tests reality_tls_binding_interop_test)

  add_waterwall_unit_test(
    waterwall.reality_tls_binding_interop_unit
    reality_tls_binding_interop_test
    "unit;tunnels;reality;v2;tls-parser;tls-accessor"
  )
endif()

if(TARGET RealityClient AND TARGET RealityServer AND TARGET TlsClient)
  waterwall_add_native_executable(reality_close_lifecycle_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_close_lifecycle_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_close_lifecycle_client.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_close_lifecycle_server.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/reality/reality_tls_binding_fixture.c)
  target_include_directories(reality_close_lifecycle_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/RealityClient/include
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(reality_close_lifecycle_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(reality_close_lifecycle_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(reality_close_lifecycle_test PRIVATE
    RealityClient RealityServer RealityCommon TlsClient TlsRecordShapingCommon ww ssl crypto
  )
  add_dependencies(waterwall_unit_tests reality_close_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.reality_close_lifecycle_unit
    reality_close_lifecycle_test
    "unit;tunnels;reality;v2;lifecycle;reentry"
  )
endif()

