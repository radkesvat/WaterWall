find_program(BASH_EXECUTABLE bash REQUIRED)
find_program(PYTHON3_EXECUTABLE python3 REQUIRED)

option(
  WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS
  "Enable integration tests that require root/CAP_NET_ADMIN and TUN device support"
  ON
)

add_subdirectory(unittests)

function(add_waterwall_integration_test_with_timeout test_name case_name timeout_seconds)
  set(case_dir "${CMAKE_CURRENT_SOURCE_DIR}/cases/${case_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_case.sh"
      "$<TARGET_FILE:Waterwall>"
      "${case_dir}"
      "${timeout_seconds}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "integration;tunnels"
  )
endfunction()

function(add_waterwall_integration_test test_name case_name)
  add_waterwall_integration_test_with_timeout(${test_name} ${case_name} 30)
endfunction()

function(add_waterwall_skipped_integration_test test_name skip_message)
  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "-c"
      "printf '%s\n' \"$1\"; exit 77"
      "waterwall-skip"
      "${skip_message}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "integration;tunnels"
      SKIP_RETURN_CODE 77
  )
endfunction()

function(add_waterwall_negative_integration_test test_name case_name)
  add_waterwall_integration_test_with_timeout(${test_name} ${case_name} 10)
  set_tests_properties(
    ${test_name}
    PROPERTIES
      WILL_FAIL TRUE
  )
endfunction()

function(add_waterwall_expected_failure_integration_test test_name case_name expected_output)
  set(case_dir "${CMAKE_CURRENT_SOURCE_DIR}/cases/${case_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_expected_failure_case.sh"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_case.sh"
      "$<TARGET_FILE:Waterwall>"
      "${case_dir}"
      "10"
      "${expected_output}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "integration;tunnels;negative"
  )
endfunction()

function(add_waterwall_probe_integration_test test_name case_name timeout_seconds)
  set(case_dir "${CMAKE_CURRENT_SOURCE_DIR}/cases/${case_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_probe_case.sh"
      "$<TARGET_FILE:Waterwall>"
      "${case_dir}"
      "${timeout_seconds}"
      "${PYTHON3_EXECUTABLE}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "integration;tunnels;probe"
  )
endfunction()

function(add_waterwall_privileged_probe_integration_test test_name case_name timeout_seconds)
  set(case_dir "${CMAKE_CURRENT_SOURCE_DIR}/cases/${case_name}")

  if(WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS)
    add_test(
      NAME ${test_name}
      COMMAND
        "${BASH_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_privileged_probe_case.sh"
        "$<TARGET_FILE:Waterwall>"
        "${case_dir}"
        "${timeout_seconds}"
        "${PYTHON3_EXECUTABLE}"
    )

    set_tests_properties(
      ${test_name}
      PROPERTIES
        TIMEOUT 120
        LABELS "integration;tunnels;probe;privileged;socket-manager"
        SKIP_RETURN_CODE 77
    )
  else()
    add_waterwall_skipped_integration_test(
      ${test_name}
      "privileged integration tests disabled; configure with -DWATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS=ON"
    )
    set_tests_properties(
      ${test_name}
      PROPERTIES
        LABELS "integration;tunnels;probe;privileged;socket-manager"
    )
  endif()
endfunction()

function(add_waterwall_packet_analysis_test test_name case_name)
  set(case_dir "${CMAKE_CURRENT_SOURCE_DIR}/cases/${case_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_packet_analysis_case.sh"
      "$<TARGET_FILE:Waterwall>"
      "${case_dir}"
      "30"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "integration;tunnels;packet-analysis"
  )
endfunction()

function(add_waterwall_speedtest test_name speedtest_name)
  set(speedtest_dir "${CMAKE_CURRENT_SOURCE_DIR}/speedtests/${speedtest_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_speedtest.sh"
      "$<TARGET_FILE:Waterwall>"
      "${speedtest_dir}"
      "45"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "integration;tunnels;speedtest"
  )
endfunction()

add_waterwall_integration_test(waterwall.disturber_passthrough disturber_passthrough)
add_waterwall_integration_test(waterwall.obfuscator_roundtrip obfuscator_roundtrip)
add_waterwall_integration_test(waterwall.obfuscator_tls_record_roundtrip obfuscator_tls_record_roundtrip)
add_waterwall_integration_test(waterwall.encryption_roundtrip encryption_roundtrip)
add_waterwall_integration_test(waterwall.encryption_small_frame_roundtrip encryption_small_frame_roundtrip)
add_waterwall_integration_test(waterwall.bgp4_roundtrip bgp4_roundtrip)
add_waterwall_integration_test(waterwall.keepalive_roundtrip keepalive_roundtrip)
add_waterwall_integration_test(waterwall.tls_roundtrip tls_roundtrip)
add_waterwall_probe_integration_test(waterwall.tlsclient_direct_close_probe tlsclient_direct_close_probe 20)
add_waterwall_integration_test(waterwall.tls_fallback_plaintext_probe_tcp_loopback tls_fallback_plaintext_probe_tcp_loopback)
add_waterwall_integration_test(waterwall.tls_fallback_connector_target_tcp_loopback tls_fallback_connector_target_tcp_loopback)
add_waterwall_probe_integration_test(waterwall.tls_handshake_timeout_slow_drip tls_handshake_timeout_slow_drip 10)
add_waterwall_probe_integration_test(waterwall.tls_tlslike_invalid_probe_does_not_fallback tls_tlslike_invalid_probe_does_not_fallback 10)
add_waterwall_probe_integration_test(waterwall.tls_tlslike_oversized_probe_does_not_fallback tls_tlslike_oversized_probe_does_not_fallback 10)
add_waterwall_negative_integration_test(waterwall.tls_fallback_rejects_sni_gate tls_fallback_rejects_sni_gate)
add_waterwall_integration_test(waterwall.reality_google_roundtrip reality_google_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_roundtrip reality_v2_roundtrip)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_post_handshake reality_v2_tls13_post_handshake 20)
add_waterwall_integration_test(waterwall.reality_v2_tls13_handoff reality_v2_tls13_handoff)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_transition_matrix reality_v2_tls13_transition_matrix 45)
add_waterwall_integration_test(waterwall.reality_v2_tls12_roundtrip reality_v2_tls12_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_cbc_roundtrip reality_v2_tls12_cbc_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_gcm_sequence_roundtrip reality_v2_tls12_gcm_sequence_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_gcm_counter_roundtrip reality_v2_tls12_gcm_counter_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_gcm_random_roundtrip reality_v2_tls12_gcm_random_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_cbc256_roundtrip reality_v2_tls12_cbc256_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_aes_gcm_roundtrip reality_v2_aes_gcm_roundtrip)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls12_gcm_wire_camouflage reality_v2_tls12_gcm_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls12_cbc_wire_camouflage reality_v2_tls12_cbc_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls12_chacha_wire_camouflage reality_v2_tls12_chacha_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_wire_camouflage reality_v2_tls13_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_wire_handoff reality_v2_tls13_wire_handoff 30)
add_waterwall_probe_integration_test(waterwall.reality_v2_cross_connection_replay_rejected reality_v2_replay_protection_probe 15)
add_waterwall_probe_integration_test(waterwall.reality_v2_direct_record_replay_rejected reality_v2_replay_protection_probe 15)
add_waterwall_probe_integration_test(waterwall.reality_v2_wrong_direction_rejected reality_v2_replay_protection_probe 15)
add_waterwall_integration_test(waterwall.reality_visitor_plaintext_probe reality_visitor_plaintext_probe)
add_waterwall_probe_integration_test(
  waterwall.reality_visitor_short_prefix_probe
  reality_visitor_short_prefix_probe
  15
)
add_waterwall_expected_failure_integration_test(
  waterwall.reality_client_rejects_obsolete_max_frame_size
  reality_client_rejects_obsolete_max_frame_size
  "RealityClient: 'max-frame-size' is obsolete"
)
add_waterwall_expected_failure_integration_test(
  waterwall.reality_server_rejects_obsolete_max_frame_size
  reality_server_rejects_obsolete_max_frame_size
  "RealityServer: 'max-frame-size' is obsolete"
)
add_test(
  NAME waterwall.reality_config_startup
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/reality_config_validation_test.py"
    "$<TARGET_FILE:Waterwall>"
)
set_tests_properties(
  waterwall.reality_config_startup
  PROPERTIES
    TIMEOUT 240
    LABELS "integration;tunnels;reality;tlsclient;configuration;negative"
    RESOURCE_LOCK waterwall_reality_configuration
)
add_waterwall_integration_test(waterwall.connection_fisher_roundtrip connection_fisher_roundtrip)
add_waterwall_integration_test(waterwall.connection_fisher_encryption_roundtrip connection_fisher_encryption_roundtrip)
add_waterwall_integration_test(waterwall.sniffrouter_non_http_tcp_loopback sniffrouter_non_http_tcp_loopback)
add_waterwall_integration_test(waterwall.sniffrouter_http_domain_tcp_loopback sniffrouter_http_domain_tcp_loopback)
add_waterwall_integration_test(waterwall.router_connector_rule_target_tcp_loopback router_connector_rule_target_tcp_loopback)
add_waterwall_integration_test(waterwall.router_domainresolver_connector_rule_target_tcp_loopback router_domainresolver_connector_rule_target_tcp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_tcp_loopback socks5_noauth_tcp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_udp_loopback socks5_noauth_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_tcp_loopback socks5_noauth_dest_protocol_tcp_loopback)
add_waterwall_integration_test(waterwall.socks5_dest_context_domain_resolve_udp_loopback socks5_dest_context_domain_resolve_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_udp_loopback socks5_noauth_dest_protocol_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_fallback_tcp_loopback socks5_noauth_dest_protocol_fallback_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_password_tcp_loopback trojan_password_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_local_password_router_tcp_loopback trojan_local_password_router_tcp_loopback)
add_waterwall_negative_integration_test(waterwall.trojan_local_password_router_rejects_wrong_password trojan_local_password_router_rejects_wrong_password)
add_waterwall_integration_test(waterwall.trojan_fallback_invalid_probe_tcp_loopback trojan_fallback_invalid_probe_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_sha224_dest_protocol_tcp_loopback trojan_sha224_dest_protocol_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_dest_context_domain_resolve_tcp_loopback trojan_dest_context_domain_resolve_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_password_udp_loopback trojan_password_udp_loopback)
add_waterwall_integration_test(waterwall.trojan_dest_protocol_udp_loopback trojan_dest_protocol_udp_loopback)
add_waterwall_integration_test(waterwall.vless_uuid_tcp_loopback vless_uuid_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_uuid_domain_tcp_loopback vless_uuid_domain_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_dest_context_domain_resolve_tcp_loopback vless_dest_context_domain_resolve_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_local_username_router_tcp_loopback vless_local_username_router_tcp_loopback)
add_waterwall_negative_integration_test(waterwall.vless_local_username_router_rejects_wrong_password vless_local_username_router_rejects_wrong_password)
add_waterwall_integration_test(waterwall.vless_fallback_invalid_probe_tcp_loopback vless_fallback_invalid_probe_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_uuid_udp_loopback vless_uuid_udp_loopback)
add_waterwall_integration_test(waterwall.vless_auth_tcp_loopback vless_auth_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_auth_udp_loopback vless_auth_udp_loopback)
add_waterwall_integration_test(waterwall.softiplimiter_vless_tcp_loopback softiplimiter_vless_tcp_loopback)
add_waterwall_integration_test(waterwall.softiplimiter_trojan_tcp_loopback softiplimiter_trojan_tcp_loopback)
add_waterwall_probe_integration_test(waterwall.softiplimiter_vless_reject_distinct_ip_probe softiplimiter_vless_reject_distinct_ip_probe 10)
add_waterwall_integration_test(waterwall.softiplimiter_identification_failure_passthrough softiplimiter_identification_failure_passthrough)
add_waterwall_probe_integration_test(waterwall.softiplimiter_identification_failure_close_probe softiplimiter_identification_failure_close_probe 10)
add_waterwall_integration_test(waterwall.udp_over_tcp_roundtrip udp_over_tcp_roundtrip)
add_waterwall_integration_test(waterwall.tcp_over_udp_roundtrip tcp_over_udp_roundtrip)
add_waterwall_integration_test(waterwall.tcp_over_udp_fec_roundtrip tcp_over_udp_fec_roundtrip)
add_waterwall_integration_test(waterwall.tcp_over_udp_disturber_roundtrip tcp_over_udp_disturber_roundtrip)
add_waterwall_integration_test(waterwall.tcp_over_udp_fec_disturber_roundtrip tcp_over_udp_fec_disturber_roundtrip)
add_waterwall_integration_test(waterwall.halfduplex_roundtrip halfduplex_roundtrip)
add_waterwall_integration_test(waterwall.http1_bidirectional_roundtrip http1_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http1_bidirectional_tcp_loopback http1_bidirectional_tcp_loopback)
add_waterwall_integration_test(waterwall.http1_split_roundtrip http1_split_roundtrip)
add_waterwall_integration_test(waterwall.http1_split_tcp_loopback http1_split_tcp_loopback)
add_waterwall_integration_test(waterwall.http1_split_path_cookie_roundtrip http1_split_path_cookie_roundtrip)
add_waterwall_integration_test(waterwall.http2_bidirectional_roundtrip http2_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http2_bidirectional_tcp_loopback http2_bidirectional_tcp_loopback)
add_waterwall_integration_test(waterwall.http_upgrade_h2c_bidirectional_roundtrip http_upgrade_h2c_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http_upgrade_h2c_bidirectional_tcp_loopback http_upgrade_h2c_bidirectional_tcp_loopback)
add_waterwall_negative_integration_test(waterwall.http2_request_validation_rejects_mismatch http2_request_validation_rejects_mismatch)
add_waterwall_integration_test(waterwall.http_websocket_bidirectional_roundtrip http_websocket_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http_websocket_bidirectional_tcp_loopback http_websocket_bidirectional_tcp_loopback)
add_waterwall_integration_test(waterwall.http_upgrade_custom_bidirectional_roundtrip http_upgrade_custom_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http_upgrade_custom_bidirectional_tcp_loopback http_upgrade_custom_bidirectional_tcp_loopback)
add_waterwall_integration_test(waterwall.mux_counter_roundtrip mux_counter_roundtrip)
add_waterwall_integration_test(waterwall.mux_timer_roundtrip mux_timer_roundtrip)
add_waterwall_integration_test(waterwall.mux_fixed_connections_count_roundtrip mux_fixed_connections_count_roundtrip)
add_waterwall_integration_test(waterwall.config_variables_roundtrip config_variables_roundtrip)
add_waterwall_integration_test(waterwall.packets_stream_bridge_roundtrip packets_stream_bridge_roundtrip)
add_waterwall_integration_test(waterwall.packets_stream_bridge_hard_validation_roundtrip packets_stream_bridge_hard_validation_roundtrip)
add_waterwall_integration_test(waterwall.packets_stream_bridge_hard_validation_udp_roundtrip packets_stream_bridge_hard_validation_udp_roundtrip)
add_waterwall_integration_test(waterwall.udp_listener_packet_bridge_roundtrip udp_listener_packet_bridge_roundtrip)
add_waterwall_integration_test(waterwall.udp_connector_packet_balance_mode_roundtrip udp_connector_packet_balance_mode_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_listener_connector_tcp_sandwich_roundtrip tcpudp_listener_connector_tcp_sandwich_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_listener_connector_udp_sandwich_roundtrip tcpudp_listener_connector_udp_sandwich_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_udp_over_tcp_tcp_roundtrip tcpudp_udp_over_tcp_tcp_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_udp_over_tcp_udp_roundtrip tcpudp_udp_over_tcp_udp_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_udp_over_tcp_large_udp_roundtrip tcpudp_udp_over_tcp_large_udp_roundtrip)
add_waterwall_packet_analysis_test(waterwall.udp_connector_listener_packet_loss_multiworker udp_connector_listener_packet_loss_multiworker)
add_waterwall_packet_analysis_test(waterwall.udp_listener_connector_packet_loss_multiworker udp_listener_connector_packet_loss_multiworker)
add_waterwall_packet_analysis_test(waterwall.udp_listener_multiport_socket_packet_loss_multiworker udp_listener_multiport_socket_packet_loss_multiworker)
add_waterwall_integration_test(waterwall.udp_connector_listener_connection_multiworker_roundtrip udp_connector_listener_connection_multiworker_roundtrip)
add_waterwall_integration_test(waterwall.udp_listener_connector_connection_multiworker_roundtrip udp_listener_connector_connection_multiworker_roundtrip)
add_waterwall_integration_test(waterwall.udp_listener_multiport_socket_connection_multiworker_roundtrip udp_listener_multiport_socket_connection_multiworker_roundtrip)
add_waterwall_privileged_probe_integration_test(waterwall.socket_manager_tcp_wildcard_specific_tun socket_manager_tcp_wildcard_specific_tun 15)
add_waterwall_privileged_probe_integration_test(waterwall.socket_manager_udp_wildcard_specific_tun socket_manager_udp_wildcard_specific_tun 15)
add_waterwall_privileged_probe_integration_test(waterwall.socket_manager_tcp_range_socket_wildcard_specific_tun socket_manager_tcp_range_socket_wildcard_specific_tun 15)
add_waterwall_privileged_probe_integration_test(waterwall.socket_manager_udp_range_socket_wildcard_specific_tun socket_manager_udp_range_socket_wildcard_specific_tun 15)
add_waterwall_integration_test(waterwall.ping_new_ip_icmp_roundtrip ping_new_ip_icmp_roundtrip)
add_waterwall_integration_test(waterwall.ping_reuse_ipv4_addresses_roundtrip ping_reuse_ipv4_addresses_roundtrip)
add_waterwall_integration_test(waterwall.ping_only_icmp_roundtrip ping_only_icmp_roundtrip)
add_waterwall_integration_test(waterwall.ping_protocol_swap_roundtrip ping_protocol_swap_roundtrip)
add_waterwall_integration_test(waterwall.ping_identifier_check_disabled_roundtrip ping_identifier_check_disabled_roundtrip)
add_waterwall_negative_integration_test(waterwall.ping_client_rejects_numeric_overflow ping_client_rejects_numeric_overflow)
add_waterwall_negative_integration_test(waterwall.ping_server_rejects_numeric_overflow ping_server_rejects_numeric_overflow)
add_waterwall_integration_test(waterwall.ipmanipulator_tcp_udp_swap_roundtrip ipmanipulator_tcp_udp_swap_roundtrip)
add_waterwall_integration_test(waterwall.ipmanipulator_udp_tcp_swap_roundtrip ipmanipulator_udp_tcp_swap_roundtrip)
add_waterwall_integration_test(waterwall.ipmanipulator_tcp_udp_tcp_transport_roundtrip ipmanipulator_tcp_udp_tcp_transport_roundtrip)
add_waterwall_integration_test(waterwall.ipmanipulator_tcp_udp_tcp_transport_bridge_roundtrip ipmanipulator_tcp_udp_tcp_transport_bridge_roundtrip)
add_waterwall_integration_test(waterwall.reverse_tcp_bridge_roundtrip reverse_tcp_bridge_roundtrip)
add_waterwall_integration_test(waterwall.reverse_custom_secret_tcp_bridge_roundtrip reverse_custom_secret_tcp_bridge_roundtrip)
add_waterwall_integration_test(waterwall.wireguard_udpstateless_packet_roundtrip wireguard_udpstateless_packet_roundtrip)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_ping_roundtrip packet_analysis_ping_roundtrip)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_disturber_loss packet_analysis_disturber_loss)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_receiver_head_bridge packet_analysis_receiver_head_bridge)
add_waterwall_speedtest(waterwall.speedtest_direct_pair direct_pair)
add_waterwall_speedtest(waterwall.speedtest_tcp_loopback tcp_loopback)
add_waterwall_speedtest(waterwall.speedtest_udp_over_tcp_direct_pair udp_over_tcp_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_udp_over_tcp_udp_sandwich udp_over_tcp_udp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_tcp_over_udp_direct_pair tcp_over_udp_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_tcp_over_udp_udp_sandwich tcp_over_udp_udp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_obfuscator_direct_pair obfuscator_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_obfuscator_tcp_sandwich obfuscator_tcp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_tls_direct_pair tls_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_tls_tcp_sandwich tls_tcp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_encryption_direct_pair encryption_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_encryption_tcp_sandwich encryption_tcp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_reality_direct_pair reality_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_reality_tcp_sandwich reality_tcp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_mux_direct_pair mux_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_mux_tcp_sandwich mux_tcp_sandwich)

add_custom_target(check_waterwall_integration_tests
  COMMAND
    "${CMAKE_CTEST_COMMAND}"
    --test-dir "${CMAKE_BINARY_DIR}"
    -C "$<CONFIG>"
    --output-on-failure
    -L integration
  DEPENDS Waterwall
  USES_TERMINAL
)

add_custom_target(check_waterwall_tests
  COMMAND
    "${CMAKE_CTEST_COMMAND}"
    --test-dir "${CMAKE_BINARY_DIR}"
    -C "$<CONFIG>"
    --output-on-failure
  DEPENDS
    Waterwall
    waterwall_unit_tests
  USES_TERMINAL
)
