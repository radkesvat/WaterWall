# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.wireguard_udpconnector_packet_roundtrip wireguard_udpconnector_packet_roundtrip)
if(LINUX AND NOT CMAKE_CROSSCOMPILING AND WATERWALL_ENABLE_INTEGRATION_TEST_NETNS
   AND INCLUDE_UDP_LISTENER AND INCLUDE_ROUTER AND INCLUDE_WIREGUARD_SERVER
   AND INCLUDE_PACKETS_TO_STREAM AND INCLUDE_TCPCONNECTOR)
  add_waterwall_isolated_test(waterwall.wireguard_server_branch_startup "${PYTHON3_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/wireguard_server_branch_startup.py" "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>")
  set_tests_properties(waterwall.wireguard_server_branch_startup PROPERTIES TIMEOUT 30)
  add_waterwall_test_labels(waterwall.wireguard_server_branch_startup "integration" "tunnels" "wireguard")
endif()
add_waterwall_integration_test(waterwall.wireguard_tcpcarrier_packet_roundtrip wireguard_tcpcarrier_packet_roundtrip)
add_waterwall_test_labels(waterwall.wireguard_tcpcarrier_packet_roundtrip "wireguard")
add_waterwall_integration_test(waterwall.wireguard_tcpcarrier_cookie_roundtrip wireguard_tcpcarrier_packet_roundtrip)
set_tests_properties(waterwall.wireguard_tcpcarrier_cookie_roundtrip PROPERTIES
  ENVIRONMENT "WATERWALL_TEST_FORCE_SYSTEM_LOAD=1")
add_waterwall_test_labels(waterwall.wireguard_tcpcarrier_cookie_roundtrip "wireguard" "cookies" "overload")
add_waterwall_wireguard_cookie_test(waterwall.wireguard_cookie_overload_roundtrip wireguard_cookie_overload_roundtrip)
foreach(workers IN ITEMS 1 4)
  set(test_name "waterwall.wireguard_cookie_source_port_${workers}")
  add_waterwall_isolated_test(${test_name} "${BASH_EXECUTABLE}"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_wireguard_cookie_case.sh"
    "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_case.sh" "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
    "${WATERWALL_TEST_SOURCE_ROOT}/cases/wireguard_cookie_overload_roundtrip" "30" "${PYTHON3_EXECUTABLE}" "endpoint" "${workers}")
  set_tests_properties(${test_name} PROPERTIES TIMEOUT 120 RESOURCE_LOCK waterwall_wireguard_cookie_ports)
  add_waterwall_test_labels(${test_name} "integration" "tunnels" "wireguard" "security" "cookies" "overload")
endforeach()
add_waterwall_packet_analysis_test(waterwall.packet_analysis_ping_roundtrip packet_analysis_ping_roundtrip)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_ping6_roundtrip packet_analysis_ping6_roundtrip)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_ping6_ipv6_in_ipv4_roundtrip packet_analysis_ping6_ipv6_in_ipv4_roundtrip)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_disturber_loss packet_analysis_disturber_loss)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_receiver_head_bridge packet_analysis_receiver_head_bridge)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_all_protocols packet_analysis_all_protocols)
add_waterwall_packet_analysis_test(waterwall.packet_analysis_unexpected_protocol packet_analysis_unexpected_protocol)

add_waterwall_isolated_test(waterwall.wireguard_junk_packet_roundtrip "${BASH_EXECUTABLE}"
  "${WATERWALL_TEST_SOURCE_ROOT}/run_wireguard_cookie_case.sh"
  "${WATERWALL_TEST_SOURCE_ROOT}/run_waterwall_case.sh" "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
  "${WATERWALL_TEST_SOURCE_ROOT}/cases/wireguard_junk_packet_roundtrip" "30" "${PYTHON3_EXECUTABLE}" "junk")
set_tests_properties(waterwall.wireguard_junk_packet_roundtrip PROPERTIES TIMEOUT 120)
add_waterwall_test_labels(waterwall.wireguard_junk_packet_roundtrip "integration" "tunnels" "wireguard")
add_waterwall_integration_test(waterwall.wireguard_auth_tcp_loopback wireguard_auth_tcp_loopback)
add_waterwall_integration_test(waterwall.wireguard_auth_udp_loopback wireguard_auth_udp_loopback)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET WireGuardServer)
  foreach(workers IN ITEMS 1 4)
    set(test_name "waterwall.wireguard_kernel_peer_${workers}")
    add_waterwall_isolated_test(${test_name} "${PYTHON3_EXECUTABLE}"
      "${WATERWALL_TEST_SOURCE_ROOT}/wireguard_kernel_peer.py" "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
      --workers "${workers}")
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 55 SKIP_RETURN_CODE 77)
    add_waterwall_test_labels(${test_name} "integration" "privileged" "wireguard" "interoperability")

    set(rekey_test_name "waterwall.wireguard_kernel_peer_rekey_${workers}")
    add_waterwall_isolated_test(${rekey_test_name} "${PYTHON3_EXECUTABLE}"
      "${WATERWALL_TEST_SOURCE_ROOT}/wireguard_kernel_peer.py" "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
      --workers "${workers}" --rekey)
    set_tests_properties(${rekey_test_name} PROPERTIES TIMEOUT 240 SKIP_RETURN_CODE 77)
    add_waterwall_test_labels(${rekey_test_name} "integration" "privileged" "wireguard" "interoperability")
  endforeach()
endif()

add_waterwall_expected_failure_integration_test(waterwall.wireguard_connection_missing_auth wireguard_connection_missing_auth "WireGuardServer: invalid mode")

add_waterwall_expected_failure_integration_test(waterwall.wireguard_packet_overlapping_ranges wireguard_packet_overlapping_ranges "WireGuardServer: invalid mode")

add_waterwall_expected_failure_integration_test(waterwall.wireguard_server_bad_mode wireguard_server_bad_mode "WireGuardServer: invalid mode")
