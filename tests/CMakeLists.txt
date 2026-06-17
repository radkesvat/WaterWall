find_program(BASH_EXECUTABLE bash REQUIRED)

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
add_waterwall_integration_test(waterwall.reality_google_roundtrip reality_google_roundtrip)
add_waterwall_integration_test(waterwall.reality_visitor_plaintext_probe reality_visitor_plaintext_probe)
add_waterwall_integration_test(waterwall.connection_fisher_roundtrip connection_fisher_roundtrip)
add_waterwall_integration_test(waterwall.connection_fisher_encryption_roundtrip connection_fisher_encryption_roundtrip)
add_waterwall_integration_test(waterwall.sniffrouter_non_http_tcp_loopback sniffrouter_non_http_tcp_loopback)
add_waterwall_integration_test(waterwall.sniffrouter_http_domain_tcp_loopback sniffrouter_http_domain_tcp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_tcp_loopback socks5_noauth_tcp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_udp_loopback socks5_noauth_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_tcp_loopback socks5_noauth_dest_protocol_tcp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_udp_loopback socks5_noauth_dest_protocol_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_fallback_tcp_loopback socks5_noauth_dest_protocol_fallback_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_password_tcp_loopback trojan_password_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_sha224_dest_protocol_tcp_loopback trojan_sha224_dest_protocol_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_password_udp_loopback trojan_password_udp_loopback)
add_waterwall_integration_test(waterwall.trojan_dest_protocol_udp_loopback trojan_dest_protocol_udp_loopback)
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
add_waterwall_packet_analysis_test(waterwall.udp_connector_listener_packet_loss_multiworker udp_connector_listener_packet_loss_multiworker)
add_waterwall_packet_analysis_test(waterwall.udp_listener_connector_packet_loss_multiworker udp_listener_connector_packet_loss_multiworker)
add_waterwall_packet_analysis_test(waterwall.udp_listener_multiport_socket_packet_loss_multiworker udp_listener_multiport_socket_packet_loss_multiworker)
add_waterwall_integration_test(waterwall.udp_connector_listener_connection_multiworker_roundtrip udp_connector_listener_connection_multiworker_roundtrip)
add_waterwall_integration_test(waterwall.udp_listener_connector_connection_multiworker_roundtrip udp_listener_connector_connection_multiworker_roundtrip)
add_waterwall_integration_test(waterwall.udp_listener_multiport_socket_connection_multiworker_roundtrip udp_listener_multiport_socket_connection_multiworker_roundtrip)
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
