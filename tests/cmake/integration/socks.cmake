# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.socks5_noauth_tcp_loopback socks5_noauth_tcp_loopback)
add_waterwall_probe_integration_test(waterwall.socks5_connect_large_body_probe socks5_connect_large_body_probe 30)
add_waterwall_probe_integration_test(waterwall.socks5_client_large_reply_probe socks5_client_large_reply_probe 30)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   TARGET Socks5Client AND TARGET Socks5Server AND TARGET AuthenticationClient AND TARGET AuthenticationServer)
  foreach(side IN ITEMS client server)
    foreach(auth_mode IN ITEMS noauth auth)
      foreach(splice_mode IN ITEMS true false)
        set(socks_splice_case waterwall.socks5${side}_tcp_${auth_mode}_splice_${splice_mode})
        add_waterwall_isolated_test(${socks_splice_case}
          "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/socks5_splice_integration.py"
          "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${side}" "${splice_mode}" "${auth_mode}")
        set_tests_properties(${socks_splice_case} PROPERTIES TIMEOUT 60)
        add_waterwall_test_labels(${socks_splice_case} "integration" "tunnels" "socks" "splice")
        add_waterwall_case_resource_lock(${socks_splice_case} socks5_splice)
      endforeach()
    endforeach()
  endforeach()
  if(TARGET TcpUdpConnector AND TARGET TcpUdpListener AND TARGET UdpListener AND TARGET UdpConnector)
    foreach(side IN ITEMS client server)
      set(socks_udp_case waterwall.socks5${side}_udp_ordinary_reads)
      add_waterwall_isolated_test(${socks_udp_case}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/socks5_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "udp_${side}" true noauth)
      set_tests_properties(${socks_udp_case} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(${socks_udp_case} "integration" "tunnels" "socks" "udp" "splice")
      add_waterwall_case_resource_lock(${socks_udp_case} socks5_splice)
    endforeach()
    foreach(splice_mode IN ITEMS true false)
      set(socks_udp_case waterwall.socks5server_udp_auth_bandwidth_splice_${splice_mode})
      add_waterwall_isolated_test(${socks_udp_case}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/socks5_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" udp_server "${splice_mode}" auth_bandwidth)
      set_tests_properties(${socks_udp_case} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(${socks_udp_case} "integration" "tunnels" "socks" "udp" "splice")
      add_waterwall_case_resource_lock(${socks_udp_case} socks5_splice)
    endforeach()
  endif()
endif()
add_waterwall_expected_failure_integration_test(
  waterwall.socks5_udp_requires_dynamic_provider
  socks5_udp_requires_dynamic_provider
  "Socks5Server: could not resolve dynamic UDP provider"
)
add_waterwall_probe_integration_test(
  waterwall.socks5_udp_dynamic_endpoint_isolation_probe
  socks5_udp_dynamic_endpoint_isolation_probe
  30
)
add_waterwall_probe_integration_test(
  waterwall.socks5_udp_outbound_pool_probe
  socks5_udp_outbound_pool_probe
  30
)
add_waterwall_probe_integration_test(
  waterwall.socks5_udp_packet_pool_probe
  socks5_udp_packet_pool_probe
  30
)
add_waterwall_probe_integration_test(
  waterwall.socks5_udp_pool_stale_reply_probe
  socks5_udp_pool_stale_reply_probe
  30
)
add_waterwall_integration_test(waterwall.socks5_noauth_udp_loopback socks5_noauth_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_udp_encryption_loopback socks5_noauth_udp_encryption_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_udp_packet_balanced_connector_loopback socks5_noauth_udp_packet_balanced_connector_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_udp_router_connector_loopback socks5_noauth_udp_router_connector_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_tcp_loopback socks5_noauth_dest_protocol_tcp_loopback)
add_waterwall_integration_test(waterwall.socks5_dest_context_domain_resolve_udp_loopback socks5_dest_context_domain_resolve_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_udp_loopback socks5_noauth_dest_protocol_udp_loopback)
add_waterwall_integration_test(waterwall.socks5_noauth_dest_protocol_fallback_tcp_loopback socks5_noauth_dest_protocol_fallback_tcp_loopback)
add_waterwall_isolated_test(waterwall.dns_slow_answer
  "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/dns_slow_answer_test.py"
  "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>")
set_tests_properties(waterwall.dns_slow_answer PROPERTIES TIMEOUT 60)
add_waterwall_test_labels(waterwall.dns_slow_answer "integration" "tunnels" "socks" "dns")
add_waterwall_case_resource_lock(waterwall.dns_slow_answer dns_slow_answer)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   TARGET DomainResolver AND TARGET TcpUdpConnector AND TARGET Socks5Server AND TARGET Router)
  set(dns_behaviour_config_consumers "")
  foreach(consumer IN ITEMS TcpConnector UdpConnector TcpUdpConnector Router Socks5Client
      TrojanClient VlessClient VmessClient HttpProxyClient ConnectionToPackets UdpStatelessSocket)
    if(TARGET ${consumer})
      list(APPEND dns_behaviour_config_consumers ${consumer})
    endif()
  endforeach()
  add_waterwall_isolated_test(waterwall.domainresolver_configuration
    "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/domainresolver_configuration_test.py"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" ${dns_behaviour_config_consumers})
  # The full configuration matrix launches hundreds of processes. Allow cumulative
  # packed startup cost under CI load; each case keeps its 8-second deadlines.
  set_tests_properties(waterwall.domainresolver_configuration PROPERTIES TIMEOUT 600)
  add_waterwall_test_labels(waterwall.domainresolver_configuration "integration" "tunnels" "dns")
  add_waterwall_case_resource_lock(waterwall.domainresolver_configuration domainresolver_transport)
  foreach(mode IN ITEMS omitted native direct direct6 chain chain-sniff chain-default shared shared-explicit shared-vless vless isolation rejected pinned vless-pinned http-pinned http-pinned-resolve ctp-pinned)
    if(mode MATCHES "vless" AND NOT (TARGET VlessClient AND TARGET VlessServer AND TARGET TlsClient AND TARGET TlsServer))
      continue()
    endif()
    if((mode MATCHES "^http-pinned" AND NOT (TARGET HttpProxyClient AND TARGET UdpConnector)) OR
       (mode STREQUAL "ctp-pinned" AND NOT (TARGET ConnectionToPackets AND TARGET PacketsToConnection)))
      continue()
    endif()
    set(resolver_case waterwall.domainresolver_transport_${mode})
    add_waterwall_isolated_test(${resolver_case}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/domainresolver_transport_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${mode}")
    set_tests_properties(${resolver_case} PROPERTIES TIMEOUT 60)
    add_waterwall_test_labels(${resolver_case} "integration" "tunnels" "dns")
    add_waterwall_case_resource_lock(${resolver_case} domainresolver_transport)
  endforeach()
  foreach(consumer IN ITEMS tcp combined router ctp vless vmess trojan socks http)
    if((consumer STREQUAL "ctp" AND NOT (TARGET ConnectionToPackets AND TARGET PacketsToConnection)) OR
       (consumer STREQUAL "vless" AND NOT (TARGET VlessClient AND TARGET VlessServer)) OR
       (consumer STREQUAL "vmess" AND NOT (TARGET VmessClient AND TARGET VmessServer)) OR
       (consumer STREQUAL "trojan" AND NOT (TARGET TrojanClient AND TARGET TrojanServer)) OR
       (consumer STREQUAL "socks" AND NOT (TARGET Socks5Client AND TARGET TcpUdpListener)) OR
       (consumer STREQUAL "http" AND NOT (TARGET HttpProxyClient AND TARGET HttpProxyServer)))
      continue()
    endif()
    foreach(mode IN ITEMS native direct chain disabled)
      set(resolver_case waterwall.dns_behaviour_${consumer}_${mode})
      add_waterwall_isolated_test(${resolver_case}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/domainresolver_transport_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "embedded-${consumer}-${mode}")
      set_tests_properties(${resolver_case} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(${resolver_case} "integration" "tunnels" "dns")
      add_waterwall_case_resource_lock(${resolver_case} domainresolver_transport)
    endforeach()
  endforeach()
  if(TARGET UdpListener AND TARGET UdpConnector)
    foreach(mode IN ITEMS native direct chain disabled)
      set(resolver_case waterwall.dns_behaviour_udp_balancing_${mode})
      add_waterwall_isolated_test(${resolver_case}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/domainresolver_transport_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "udp-balancing-${mode}")
      set_tests_properties(${resolver_case} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(${resolver_case} "integration" "tunnels" "dns" "udp")
      add_waterwall_case_resource_lock(${resolver_case} domainresolver_transport)
    endforeach()
  endif()
endif()
# The protocol peer is socket-connected, so ordinary server/TLS nodes cannot
# mask TrojanClient capability. strace checks actual positive splice transfers.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(protocol IN ITEMS tcp udp)
    foreach(splice_mode IN ITEMS true false)
      add_waterwall_isolated_test(waterwall.trojanclient_${protocol}_splice_${splice_mode}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/trojanclient_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${protocol}" "${splice_mode}")
      set_tests_properties(waterwall.trojanclient_${protocol}_splice_${splice_mode} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(waterwall.trojanclient_${protocol}_splice_${splice_mode} "integration" "tunnels")
      add_waterwall_case_resource_lock(waterwall.trojanclient_${protocol}_splice_${splice_mode} trojanclient_splice)
    endforeach()
  endforeach()
endif()
# The protocol peer is socket-connected, so ordinary server/TLS nodes cannot
# mask VlessClient capability. strace checks actual positive splice transfers.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(protocol IN ITEMS tcp udp)
    foreach(splice_mode IN ITEMS true false)
      add_waterwall_isolated_test(waterwall.vlessclient_${protocol}_splice_${splice_mode}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/vlessclient_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${protocol}" "${splice_mode}")
      set_tests_properties(waterwall.vlessclient_${protocol}_splice_${splice_mode} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(waterwall.vlessclient_${protocol}_splice_${splice_mode} "integration" "tunnels")
      add_waterwall_case_resource_lock(waterwall.vlessclient_${protocol}_splice_${splice_mode} vlessclient_splice)
    endforeach()
  endforeach()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(protocol IN ITEMS tcp tcp_db udp fallback fallback_http)
    foreach(splice_mode IN ITEMS true false)
      add_waterwall_isolated_test(waterwall.trojanserver_${protocol}_splice_${splice_mode}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/trojanserver_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${protocol}" "${splice_mode}")
      set_tests_properties(waterwall.trojanserver_${protocol}_splice_${splice_mode} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(waterwall.trojanserver_${protocol}_splice_${splice_mode} "integration" "tunnels")
      add_waterwall_case_resource_lock(waterwall.trojanserver_${protocol}_splice_${splice_mode} trojanserver_splice)
    endforeach()
  endforeach()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(protocol IN ITEMS tcp tcp_db tcp_db_bandwidth udp udp_db_bandwidth fallback fallback_http)
    if(protocol STREQUAL "tcp_db_bandwidth" AND NOT TARGET APIServer)
      continue()
    endif()
    foreach(splice_mode IN ITEMS true false)
      add_waterwall_isolated_test(waterwall.vlessserver_${protocol}_splice_${splice_mode}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/vlessserver_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${protocol}" "${splice_mode}")
      set_tests_properties(waterwall.vlessserver_${protocol}_splice_${splice_mode} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(waterwall.vlessserver_${protocol}_splice_${splice_mode} "integration" "tunnels")
      add_waterwall_case_resource_lock(waterwall.vlessserver_${protocol}_splice_${splice_mode} vlessserver_splice)
    endforeach()
  endforeach()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(mode IN ITEMS noauth local tracked fallback blocked)
    foreach(splice_mode IN ITEMS true false)
      add_waterwall_isolated_test(waterwall.httpproxyserver_${mode}_splice_${splice_mode}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/httpproxyserver_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${mode}" "${splice_mode}")
      set_tests_properties(waterwall.httpproxyserver_${mode}_splice_${splice_mode} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(waterwall.httpproxyserver_${mode}_splice_${splice_mode} "integration" "http" "proxy")
      add_waterwall_case_resource_lock(waterwall.httpproxyserver_${mode}_splice_${splice_mode} httpproxyserver_splice)
    endforeach()
  endforeach()
endif()
