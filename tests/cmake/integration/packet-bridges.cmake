# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.packets_stream_bridge_roundtrip packets_stream_bridge_roundtrip)
add_waterwall_integration_test(waterwall.packets_stream_bridge_hard_validation_roundtrip packets_stream_bridge_hard_validation_roundtrip)
add_waterwall_integration_test(waterwall.packets_stream_bridge_hard_validation_udp_roundtrip packets_stream_bridge_hard_validation_udp_roundtrip)
add_waterwall_integration_test(waterwall.packets_stream_bridge_tcp_multiworker_roundtrip packets_stream_bridge_tcp_multiworker_roundtrip)
add_waterwall_integration_test(waterwall.udp_listener_packet_bridge_roundtrip udp_listener_packet_bridge_roundtrip)
add_waterwall_integration_test(waterwall.udp_connector_packet_balance_mode_roundtrip udp_connector_packet_balance_mode_roundtrip)
add_waterwall_integration_test(waterwall.connection_to_packets_tcp_bridge_roundtrip connection_to_packets_tcp_bridge_roundtrip)
add_waterwall_integration_test(waterwall.connection_to_packets_tcp_bridge_multiworker_roundtrip connection_to_packets_tcp_bridge_multiworker_roundtrip)
add_waterwall_integration_test(waterwall.connection_to_packets_udp_bridge_roundtrip connection_to_packets_udp_bridge_roundtrip)
add_waterwall_expected_failure_integration_test(
  waterwall.connection_to_packets_fragment_input_rejected connection_to_packets_fragment_input_rejected
  "PacketsToConnection: received an IPv4 fragment")
add_waterwall_integration_test(waterwall.ping_server_packets_to_connection_alignment_roundtrip ping_server_packets_to_connection_alignment_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_listener_connector_tcp_sandwich_roundtrip tcpudp_listener_connector_tcp_sandwich_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_listener_connector_udp_sandwich_roundtrip tcpudp_listener_connector_udp_sandwich_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_udp_over_tcp_udp_roundtrip tcpudp_udp_over_tcp_udp_roundtrip)
add_waterwall_integration_test(waterwall.tcpudp_udp_over_tcp_large_udp_roundtrip tcpudp_udp_over_tcp_large_udp_roundtrip)
if(LINUX AND NOT CMAKE_CROSSCOMPILING AND TARGET UdpOverTcpClient AND TARGET UdpOverTcpServer
   AND TARGET UdpListener AND TARGET UdpConnector AND TARGET TcpListener AND TARGET TcpConnector)
  foreach(splice_mode IN ITEMS true false)
    add_waterwall_isolated_test(waterwall.udpovertcp_udp_splice_${splice_mode}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/udp_over_tcp_splice_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${splice_mode}")
    set_tests_properties(waterwall.udpovertcp_udp_splice_${splice_mode} PROPERTIES TIMEOUT 60)
    add_waterwall_test_labels(waterwall.udpovertcp_udp_splice_${splice_mode} "integration" "tunnels" "splice" "udp")
    add_waterwall_case_resource_lock(waterwall.udpovertcp_udp_splice_${splice_mode} udpovertcp_udp_splice)
  endforeach()
endif()
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
add_waterwall_iptables_recovery_integration_test(waterwall.socket_manager_iptables_crash_recovery)

if(LINUX AND NOT CMAKE_CROSSCOMPILING AND TARGET TcpListener AND TARGET TcpConnector
   AND TARGET UdpListener AND TARGET UdpConnector)
  foreach(protocol IN ITEMS tcp udp)
    # Always isolate: this case creates veth interfaces and nested client namespaces.
    add_test(NAME waterwall.socket_manager_${protocol}_interface_scope
      COMMAND "${BASH_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/run_in_network_namespace.sh"
        "${PYTHON3_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/socket_manager_interface_scope_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${protocol}")
    set_tests_properties(waterwall.socket_manager_${protocol}_interface_scope PROPERTIES
      TIMEOUT 60 LABELS "integration;linux;socket-manager;network-isolated")
  endforeach()
endif()

if(LINUX AND WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS)
  # This test mutates firewall rules, so always isolate it even when ordinary
  # integration tests have explicitly selected host-serial mode.
  add_test(
    NAME waterwall.capture_linux_notrack
    COMMAND "${BASH_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_in_network_namespace.sh"
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/capture_linux_notrack_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
  )
  set_tests_properties(waterwall.capture_linux_notrack PROPERTIES
    TIMEOUT 60
    LABELS "integration;linux;privileged;capture;nfqueue;network-isolated"
  )
  add_test(
    NAME waterwall.capture_linux_conntrack_enabled
    COMMAND "${BASH_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_in_network_namespace.sh"
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/capture_linux_notrack_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" --tracked
  )
  set_tests_properties(waterwall.capture_linux_conntrack_enabled PROPERTIES
    TIMEOUT 60
    LABELS "integration;linux;privileged;capture;nfqueue;conntrack;network-isolated"
  )
  foreach(policy IN ITEMS bypass tracked)
    set(protocol_test_args --exclude-protocols)
    if(policy STREQUAL "tracked")
      list(APPEND protocol_test_args --tracked)
    endif()
    add_test(
      NAME waterwall.capture_linux_protocols_${policy}
      COMMAND "${BASH_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_in_network_namespace.sh"
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/capture_linux_notrack_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" ${protocol_test_args}
    )
    set_tests_properties(waterwall.capture_linux_protocols_${policy} PROPERTIES
      TIMEOUT 60
      LABELS "integration;linux;privileged;capture;nfqueue;conntrack;network-isolated"
    )
  endforeach()
  add_test(
    NAME waterwall.raw_linux_notrack
    COMMAND "${BASH_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_in_network_namespace.sh"
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/raw_linux_notrack_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
  )
  set_tests_properties(waterwall.raw_linux_notrack PROPERTIES
    TIMEOUT 60
    LABELS "integration;linux;privileged;raw;conntrack;network-isolated"
  )
endif()
