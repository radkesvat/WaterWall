add_custom_target(waterwall_unit_tests)

set(WATERWALL_UNIT_TEST_RUNNER "${CMAKE_CURRENT_SOURCE_DIR}/run_unit_test.cmake")

function(add_waterwall_unit_test test_name target_name labels)
  add_test(
    NAME ${test_name}
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=${target_name}"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:${target_name}>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${WATERWALL_UNIT_TEST_RUNNER}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "${labels}"
      RESOURCE_LOCK waterwall_unit_test_build
  )
endfunction()

if(TARGET ww)
  add_executable(aes256gcm_test aes256gcm_test.c)
  target_link_libraries(aes256gcm_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests aes256gcm_test)

  add_waterwall_unit_test(waterwall.aes256gcm_unit aes256gcm_test "unit;crypto;aes256gcm")

  add_executable(crypto_primitives_test crypto_primitives_test.c)
  target_link_libraries(crypto_primitives_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests crypto_primitives_test)

  add_waterwall_unit_test(waterwall.crypto_primitives_unit crypto_primitives_test "unit;crypto")

  add_executable(wlibc_memcopy_test wlibc_memcopy_test.c)
  target_link_libraries(wlibc_memcopy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wlibc_memcopy_test)

  add_waterwall_unit_test(waterwall.wlibc_memcopy_unit wlibc_memcopy_test "unit;libc;memory")

  add_executable(wfrand_test wfrand_test.c)
  target_link_libraries(wfrand_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wfrand_test)

  add_waterwall_unit_test(waterwall.wfrand_unit wfrand_test "unit;libc;random")

  add_executable(line_user_identifier_test line_user_identifier_test.c)
  target_link_libraries(line_user_identifier_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests line_user_identifier_test)

  add_waterwall_unit_test(waterwall.line_user_identifier_unit line_user_identifier_test "unit;net;line")

  add_executable(line_state_index_test line_state_index_test.c)
  target_link_libraries(line_state_index_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests line_state_index_test)

  add_waterwall_unit_test(waterwall.line_state_index_unit line_state_index_test "unit;net;line;chain")

  add_executable(address_context_test address_context_test.c)
  target_link_libraries(address_context_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests address_context_test)

  add_waterwall_unit_test(waterwall.address_context_unit address_context_test "unit;net;address-context")

  add_executable(wchecksum_test wchecksum_test.c)
  target_link_libraries(wchecksum_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wchecksum_test)

  add_waterwall_unit_test(waterwall.wchecksum_unit wchecksum_test "unit;net;checksum")

  add_executable(packet_tunnel_test packet_tunnel_test.c)
  target_link_libraries(packet_tunnel_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests packet_tunnel_test)

  add_waterwall_unit_test(waterwall.packet_tunnel_unit packet_tunnel_test "unit;net;packet-tunnel")

  if(TARGET TunDevice AND TARGET RawSocket)
    add_executable(packet_adapter_finish_test packet_adapter_finish_test.c)
    target_link_libraries(packet_adapter_finish_test PRIVATE TunDevice RawSocket ww)
    add_dependencies(waterwall_unit_tests packet_adapter_finish_test)

    add_waterwall_unit_test(
      waterwall.packet_adapter_finish_unit
      packet_adapter_finish_test
      "unit;net;packet-tunnel;adapter"
    )
  endif()

  add_executable(users_runtime_migration_test users_runtime_migration_test.c)
  target_link_libraries(users_runtime_migration_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests users_runtime_migration_test)

  add_waterwall_unit_test(waterwall.users_runtime_migration_unit users_runtime_migration_test "unit;objects;users")

  add_executable(socket_manager_rules_test socket_manager_rules_test.c)
  target_link_libraries(socket_manager_rules_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socket_manager_rules_test)

  add_waterwall_unit_test(waterwall.socket_manager_rules_unit socket_manager_rules_test "unit;net;socket-manager")

  add_executable(udp_zero_length_test udp_zero_length_test.c)
  target_link_libraries(udp_zero_length_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests udp_zero_length_test)

  add_waterwall_unit_test(waterwall.udp_zero_length_unit udp_zero_length_test "unit;event;udp")

  if(LINUX)
    add_executable(capture_linux_nfqueue_test capture_linux_nfqueue_test.c)
    target_link_libraries(capture_linux_nfqueue_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests capture_linux_nfqueue_test)

    add_waterwall_unit_test(
      waterwall.capture_linux_nfqueue_unit
      capture_linux_nfqueue_test
      "unit;net;capture;nfqueue"
    )

    add_executable(os_helpers_bbr_test
      os_helpers_bbr_test.c
      ${CMAKE_SOURCE_DIR}/core/os_helpers.c
    )
    target_include_directories(os_helpers_bbr_test PRIVATE ${CMAKE_SOURCE_DIR}/core)
    target_link_libraries(os_helpers_bbr_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests os_helpers_bbr_test)

    add_waterwall_unit_test(
      waterwall.os_helpers_bbr_unit
      os_helpers_bbr_test
      "unit;core;linux;bbr"
    )
  endif()
endif()

if(TARGET tcp_over_udp_fec)
  add_executable(tcp_over_udp_fec_test tcp_over_udp_fec_test.cc)
  target_compile_features(tcp_over_udp_fec_test PRIVATE cxx_std_17)
  target_link_libraries(tcp_over_udp_fec_test PRIVATE tcp_over_udp_fec)
  add_dependencies(waterwall_unit_tests tcp_over_udp_fec_test)

  add_waterwall_unit_test(waterwall.tcp_over_udp_fec_unit tcp_over_udp_fec_test "unit;tunnels;fec")
endif()

if(TARGET nghttp2_static)
  add_executable(nghttp2_large_recv_test nghttp2_large_recv_test.c)
  target_link_libraries(nghttp2_large_recv_test PRIVATE nghttp2_static)
  add_dependencies(waterwall_unit_tests nghttp2_large_recv_test)

  add_waterwall_unit_test(waterwall.nghttp2_large_recv_unit nghttp2_large_recv_test "unit;tunnels;http;nghttp2")
endif()

if(TARGET TlsServer)
  add_executable(tlsserver_alpn_test tlsserver_alpn_test.c)
  target_link_libraries(tlsserver_alpn_test PRIVATE TlsServer ww)
  add_dependencies(waterwall_unit_tests tlsserver_alpn_test)

  add_waterwall_unit_test(waterwall.tlsserver_alpn_unit tlsserver_alpn_test "unit;tunnels;tlsserver")
endif()

if(TARGET TlsClient)
  add_executable(tlsclient_alpn_test tlsclient_alpn_test.c)
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

  add_executable(tlsclient_close_lifecycle_test tlsclient_close_lifecycle_test.c)
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
endif()

if(TARGET RealityCommon)
  add_executable(reality_config_test reality_config_test.c)
  target_link_libraries(reality_config_test PRIVATE RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_config_test)

  add_waterwall_unit_test(
    waterwall.reality_config_unit
    reality_config_test
    "unit;tunnels;reality;v2;crypto;configuration"
  )

  add_executable(reality_v2_test reality_v2_test.c)
  target_compile_definitions(reality_v2_test PRIVATE
    REALITY_TLS_CLIENT_HANDSHAKE_SOURCE="${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/ssl/handshake_client.cc"
  )
  target_link_libraries(reality_v2_test PRIVATE RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_v2_test)

  add_waterwall_unit_test(waterwall.reality_v2_unit reality_v2_test "unit;tunnels;reality;v2;crypto;replay;direction")
endif()

if(TARGET RealityServer)
  add_executable(reality_tls_binding_test reality_tls_binding_test.c)
  target_include_directories(reality_tls_binding_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include/RealityServer
  )
  target_link_libraries(reality_tls_binding_test PRIVATE RealityServer RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_tls_binding_test)

  add_waterwall_unit_test(waterwall.reality_tls_binding_unit reality_tls_binding_test "unit;tunnels;reality;v2;tls-parser")
endif()

if(TARGET RealityServer AND TARGET TlsClient)
  add_executable(reality_tls_binding_interop_test
    reality_tls_binding_interop_test.c
    reality_tls_binding_fixture.c
  )
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
  add_executable(reality_close_lifecycle_test
    reality_close_lifecycle_test.c
    reality_close_lifecycle_client.c
    reality_close_lifecycle_server.c
    reality_tls_binding_fixture.c
  )
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
    RealityClient RealityServer RealityCommon TlsClient ww ssl crypto
  )
  add_dependencies(waterwall_unit_tests reality_close_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.reality_close_lifecycle_unit
    reality_close_lifecycle_test
    "unit;tunnels;reality;v2;lifecycle;reentry"
  )
endif()

if(TARGET SniffRouter)
  add_executable(sniffrouter_classifier_test sniffrouter_classifier_test.c)
  target_include_directories(sniffrouter_classifier_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SniffRouter/include
    ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include
  )
  target_link_libraries(sniffrouter_classifier_test PRIVATE SniffRouter ReverseClient ww)
  add_dependencies(waterwall_unit_tests sniffrouter_classifier_test)

  add_waterwall_unit_test(waterwall.sniffrouter_classifier_unit sniffrouter_classifier_test "unit;tunnels;sniffrouter")
endif()

if(TARGET SniffRouter AND TARGET Router)
  add_executable(router_chain_ownership_test router_chain_ownership_test.c)
  target_include_directories(router_chain_ownership_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SniffRouter/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
  )
  target_link_libraries(router_chain_ownership_test PRIVATE SniffRouter Router ReverseClient ww)
  add_dependencies(waterwall_unit_tests router_chain_ownership_test)

  add_waterwall_unit_test(
    waterwall.router_chain_ownership_unit
    router_chain_ownership_test
    "unit;tunnels;router;sniffrouter;chain;ownership"
  )
endif()

if(TARGET PacketsToStream)
  add_executable(packetstostream_parser_test packetstostream_parser_test.c)
  target_include_directories(packetstostream_parser_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToStream/include
  )
  target_link_libraries(packetstostream_parser_test PRIVATE PacketsToStream ww)
  add_dependencies(waterwall_unit_tests packetstostream_parser_test)

  add_waterwall_unit_test(waterwall.packetstostream_parser_unit packetstostream_parser_test "unit;tunnels;packetstostream")
endif()

if(TARGET IpManipulator)
  add_executable(ipmanipulator_tcpbit_test ipmanipulator_tcpbit_test.c)
  target_include_directories(ipmanipulator_tcpbit_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_tcpbit_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_tcpbit_test)

  add_waterwall_unit_test(waterwall.ipmanipulator_tcpbit_unit ipmanipulator_tcpbit_test "unit;tunnels;ipmanipulator")
endif()

if(TARGET SoftIpLimiter)
  add_executable(softiplimiter_test softiplimiter_test.c)
  target_include_directories(softiplimiter_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SoftIpLimiter/include
  )
  target_link_libraries(softiplimiter_test PRIVATE SoftIpLimiter ww)
  add_dependencies(waterwall_unit_tests softiplimiter_test)

  add_waterwall_unit_test(waterwall.softiplimiter_unit softiplimiter_test "unit;tunnels;softiplimiter")
endif()

set(ROUTER_GEOIP_TEST_DB "")
if(DEFINED maxminddb_SOURCE_DIR)
  set(ROUTER_GEOIP_TEST_DB "${maxminddb_SOURCE_DIR}/t/maxmind-db/test-data/GeoLite2-Country-Test.mmdb")
elseif(DEFINED CPM_PACKAGE_maxminddb_SOURCE_DIR)
  set(ROUTER_GEOIP_TEST_DB "${CPM_PACKAGE_maxminddb_SOURCE_DIR}/t/maxmind-db/test-data/GeoLite2-Country-Test.mmdb")
endif()

if(TARGET Router AND EXISTS "${ROUTER_GEOIP_TEST_DB}")
  add_executable(router_geoip_test router_geoip_test.c)
  target_include_directories(router_geoip_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_compile_definitions(router_geoip_test PRIVATE
    ROUTER_GEOIP_TEST_DB="${ROUTER_GEOIP_TEST_DB}"
  )
  target_link_libraries(router_geoip_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_geoip_test)

  add_waterwall_unit_test(waterwall.router_geoip_unit router_geoip_test "unit;tunnels;router;geoip")
endif()

if(TARGET Router)
  add_executable(router_geosite_test router_geosite_test.c)
  target_include_directories(router_geosite_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_link_libraries(router_geosite_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_geosite_test)

  add_waterwall_unit_test(waterwall.router_geosite_unit router_geosite_test "unit;tunnels;router;geosite")

  add_executable(router_sniffing_test router_sniffing_test.c)
  target_include_directories(router_sniffing_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_compile_definitions(router_sniffing_test PRIVATE
    ROUTER_QUIC_SNI_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/router_quic_sni/vectors"
  )
  target_link_libraries(router_sniffing_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_sniffing_test)

  add_waterwall_unit_test(waterwall.router_sniffing_unit router_sniffing_test "unit;tunnels;router;sniffing")
endif()

add_custom_target(check_waterwall_unit_tests
  COMMAND
    "${CMAKE_CTEST_COMMAND}"
    --test-dir "${CMAKE_BINARY_DIR}"
    -C "$<CONFIG>"
    --output-on-failure
    -L unit
  DEPENDS waterwall_unit_tests
  USES_TERMINAL
)
