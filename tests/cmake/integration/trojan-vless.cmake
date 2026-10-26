# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.trojan_password_tcp_loopback trojan_password_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_local_password_router_tcp_loopback trojan_local_password_router_tcp_loopback)
add_waterwall_expected_failure_integration_test(
  waterwall.trojan_local_password_router_rejects_wrong_password
  trojan_local_password_router_rejects_wrong_password
  "received finish before full response verification"
)
add_waterwall_integration_test(waterwall.trojan_fallback_invalid_probe_tcp_loopback trojan_fallback_invalid_probe_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_sha224_dest_protocol_tcp_loopback trojan_sha224_dest_protocol_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_dest_context_domain_resolve_tcp_loopback trojan_dest_context_domain_resolve_tcp_loopback)
add_waterwall_integration_test(waterwall.trojan_password_udp_loopback trojan_password_udp_loopback)
add_waterwall_integration_test(waterwall.trojan_dest_protocol_udp_loopback trojan_dest_protocol_udp_loopback)
if(TARGET TrojanClient AND TARGET TrojanServer AND TARGET UdpListener AND
   TARGET UdpConnector AND TARGET TcpListener AND TARGET TcpConnector AND
   TARGET TlsClient AND TARGET TlsServer)
  add_waterwall_probe_integration_test(waterwall.trojan_udp_size_probe trojan_udp_size_probe 25)
  add_waterwall_test_labels(waterwall.trojan_udp_size_probe "trojan" "udp" "framing")
endif()
add_waterwall_integration_test(waterwall.vless_uuid_tcp_loopback vless_uuid_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_uuid_domain_tcp_loopback vless_uuid_domain_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_dest_context_domain_resolve_tcp_loopback vless_dest_context_domain_resolve_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_local_username_router_tcp_loopback vless_local_username_router_tcp_loopback)
add_waterwall_expected_failure_integration_test(
  waterwall.vless_local_username_router_rejects_wrong_password
  vless_local_username_router_rejects_wrong_password
  "received finish before full response verification"
)
add_waterwall_integration_test(waterwall.vless_fallback_invalid_probe_tcp_loopback vless_fallback_invalid_probe_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_uuid_udp_loopback vless_uuid_udp_loopback)
add_waterwall_integration_test(waterwall.vless_auth_tcp_loopback vless_auth_tcp_loopback)
add_waterwall_integration_test(waterwall.vless_auth_udp_loopback vless_auth_udp_loopback)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   TARGET TrojanServer AND TARGET VlessServer AND TARGET Socks5Server AND
   TARGET TcpListener AND TARGET TcpUdpListener AND TARGET UdpConnector AND
   TARGET AuthenticationClient AND TARGET AuthenticationServer)
  foreach(protocol IN ITEMS trojan vless socks5)
    set(udp_ip_case waterwall.${protocol}server_udp_distinct_ip_probe)
    add_waterwall_probe_integration_test(${udp_ip_case} authenticated_udp_distinct_ip_probe 25)
    set_tests_properties(${udp_ip_case} PROPERTIES ENVIRONMENT "WATERWALL_AUTH_UDP_PROTOCOL=${protocol}")
    add_waterwall_test_labels(${udp_ip_case} "authentication" "udp")
  endforeach()
endif()
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

# Short independent-peer checks use the same pinned sing-box executable as
# VMess, including builds that omit both VMess nodes.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  include("${CMAKE_CURRENT_LIST_DIR}/SingBoxReference.cmake")
  function(add_waterwall_sing_box_proxy_interop proxy role network)
    waterwall_add_sing_box_reference()
    set(test_name "waterwall.${proxy}_sing_box_${role}_${network}")
    add_waterwall_isolated_test(${test_name}
      "${PYTHON3_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/singbox_proxy_interop.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${WATERWALL_VMESS_SING_BOX_REFERENCE}"
      --proxy "${proxy}" --role "${role}" --network "${network}")
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 25)
    add_waterwall_test_labels(${test_name}
      "integration" "tunnels" "interoperability" "sing-box" "${proxy}" "${role}" "${network}")
    if(NOT WATERWALL_ENABLE_INTEGRATION_TEST_NETNS)
      set_tests_properties(${test_name} PROPERTIES RESOURCE_LOCK waterwall_sing_box_proxy_ports)
    endif()
  endfunction()

  foreach(proxy IN ITEMS trojan vless)
    if(proxy STREQUAL "trojan")
      set(proxy_node Trojan)
    else()
      set(proxy_node Vless)
    endif()
    if(TARGET ${proxy_node}Client AND TARGET TcpConnector AND
       (proxy STREQUAL "vless" OR TARGET TlsClient))
      if(TARGET TcpListener)
        add_waterwall_sing_box_proxy_interop("${proxy}" client tcp)
      endif()
      if(TARGET UdpListener)
        add_waterwall_sing_box_proxy_interop("${proxy}" client udp)
      endif()
    endif()
    if(TARGET ${proxy_node}Server AND TARGET TcpListener AND
       (proxy STREQUAL "vless" OR TARGET TlsServer))
      if(TARGET TcpConnector)
        add_waterwall_sing_box_proxy_interop("${proxy}" server tcp)
      endif()
      if(TARGET UdpConnector)
        add_waterwall_sing_box_proxy_interop("${proxy}" server udp)
      endif()
    endif()
  endforeach()
endif()
