# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET TlsServer)
  waterwall_add_native_executable(tlsserver_alpn_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsserver_alpn_test.c)
  target_link_libraries(tlsserver_alpn_test PRIVATE TlsServer ww)
  add_dependencies(waterwall_unit_tests tlsserver_alpn_test)

  add_waterwall_unit_test(waterwall.tlsserver_alpn_unit tlsserver_alpn_test "unit;tunnels;tlsserver")

  waterwall_add_native_executable(tlsserver_record_padding_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsserver_record_padding_test.c)
  target_compile_definitions(tlsserver_record_padding_test PRIVATE
    TLSSERVER_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSSERVER_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsserver_record_padding_test PRIVATE TlsServer TlsRecordShapingCommon ww)
  add_dependencies(waterwall_unit_tests tlsserver_record_padding_test)

  add_waterwall_unit_test(
    waterwall.tlsserver_record_padding_unit
    tlsserver_record_padding_test
    "unit;tunnels;tlsserver;tls13_record;padding;openssl"
  )

  waterwall_add_native_executable(tlsserver_record_delay_lifecycle_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsserver_record_delay_lifecycle_test.c)
  target_compile_definitions(tlsserver_record_delay_lifecycle_test PRIVATE
    TLSSERVER_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSSERVER_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsserver_record_delay_lifecycle_test PRIVATE TlsServer TlsRecordShapingCommon ww)
  add_dependencies(waterwall_unit_tests tlsserver_record_delay_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.tlsserver_record_delay_lifecycle_unit
    tlsserver_record_delay_lifecycle_test
    "unit;tunnels;tlsserver;tls13_record;delay;lifecycle;reentry"
  )
endif()

if(TARGET TlsRecordShapingCommon)
  waterwall_add_native_executable(tls13_record_shaping_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tls13_record_shaping_test.c)
  target_link_libraries(tls13_record_shaping_test PRIVATE TlsRecordShapingCommon ww)
  add_dependencies(waterwall_unit_tests tls13_record_shaping_test)

  add_waterwall_unit_test(
    waterwall.tls13_record_shaping_unit
    tls13_record_shaping_test
    "unit;tunnels;tls13_record;configuration;sampler"
  )
endif()

if(TARGET TlsClient)
  waterwall_add_native_executable(tlsclient_record_padding_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsclient_record_padding_test.c)
  target_include_directories(tlsclient_record_padding_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_record_padding_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    TLSCLIENT_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSCLIENT_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_record_padding_test PRIVATE ssl crypto ww)
  add_dependencies(waterwall_unit_tests tlsclient_record_padding_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_record_padding_unit
    tlsclient_record_padding_test
    "unit;tunnels;tlsclient;tls13_record;padding;boringssl"
  )

  waterwall_add_native_executable(tlsclient_alpn_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsclient_alpn_test.c)
  target_include_directories(tlsclient_alpn_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(tlsclient_alpn_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_alpn_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_alpn_test PRIVATE TlsClient ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_alpn_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_alpn_unit
    tlsclient_alpn_test
    "unit;tunnels;tlsclient;configuration;alpn"
  )

  waterwall_add_native_executable(tlsclient_hostname_verification_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsclient_hostname_verification_test.c)
  target_include_directories(tlsclient_hostname_verification_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(tlsclient_hostname_verification_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_hostname_verification_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    TLSCLIENT_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSCLIENT_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_hostname_verification_test PRIVATE TlsClient ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_hostname_verification_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_hostname_verification_unit
    tlsclient_hostname_verification_test
    "unit;tunnels;tlsclient;certificate;hostname"
  )

  waterwall_add_native_executable(tlsclient_close_lifecycle_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsclient_close_lifecycle_test.c)
  target_include_directories(tlsclient_close_lifecycle_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(tlsclient_close_lifecycle_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_close_lifecycle_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_close_lifecycle_test PRIVATE TlsClient ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_close_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_close_lifecycle_unit
    tlsclient_close_lifecycle_test
    "unit;tunnels;tlsclient;lifecycle;reentry"
  )

  if(LINUX)
    waterwall_add_native_executable(tls13_record_delay_lifecycle_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tls13_record_delay_lifecycle_test.c)
    target_include_directories(tls13_record_delay_lifecycle_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
    )
    target_include_directories(tls13_record_delay_lifecycle_test BEFORE PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
      ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
    )
    target_compile_definitions(tls13_record_delay_lifecycle_test PRIVATE BORINGSSL_PREFIX=WW_BSSL)
    target_link_options(tls13_record_delay_lifecycle_test PRIVATE "-Wl,--wrap=WW_BSSL_SSL_version")
    target_link_libraries(tls13_record_delay_lifecycle_test PRIVATE TlsClient TlsRecordShapingCommon ww ssl crypto)
    add_dependencies(waterwall_unit_tests tls13_record_delay_lifecycle_test)

    add_waterwall_unit_test(
      waterwall.tls13_record_delay_lifecycle_unit
      tls13_record_delay_lifecycle_test
      "unit;tunnels;tlsclient;tls13_record;delay;lifecycle;reentry"
    )
  endif()
endif()

