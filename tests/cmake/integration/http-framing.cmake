# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.halfduplex_roundtrip halfduplex_roundtrip)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(splice_mode IN ITEMS true false)
    add_waterwall_isolated_test(waterwall.halfduplex_tcp_splice_${splice_mode}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/halfduplex_splice_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${splice_mode}")
    set_tests_properties(waterwall.halfduplex_tcp_splice_${splice_mode} PROPERTIES TIMEOUT 60)
    add_waterwall_test_labels(waterwall.halfduplex_tcp_splice_${splice_mode} "integration" "tunnels")
    add_waterwall_case_resource_lock(waterwall.halfduplex_tcp_splice_${splice_mode} halfduplex_splice)
  endforeach()
endif()

add_waterwall_integration_test(waterwall.http1_bidirectional_roundtrip http1_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http1_bidirectional_tcp_loopback http1_bidirectional_tcp_loopback)
add_waterwall_integration_test(waterwall.http1_split_roundtrip http1_split_roundtrip)
add_waterwall_integration_test(waterwall.http1_split_tcp_loopback http1_split_tcp_loopback)
add_waterwall_integration_test(waterwall.http1_split_path_cookie_roundtrip http1_split_path_cookie_roundtrip)
add_waterwall_integration_test(waterwall.http2_bidirectional_roundtrip http2_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http2_bidirectional_tcp_loopback http2_bidirectional_tcp_loopback)
add_waterwall_integration_test(waterwall.http_upgrade_h2c_bidirectional_roundtrip http_upgrade_h2c_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http_upgrade_h2c_bidirectional_tcp_loopback http_upgrade_h2c_bidirectional_tcp_loopback)
add_waterwall_expected_failure_integration_test(
  waterwall.http2_request_validation_rejects_mismatch
  http2_request_validation_rejects_mismatch
  "HttpServer: HTTP/2 method mismatch"
)
add_waterwall_integration_test(waterwall.http_websocket_bidirectional_roundtrip http_websocket_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http_websocket_bidirectional_tcp_loopback http_websocket_bidirectional_tcp_loopback)
add_waterwall_integration_test(waterwall.http_upgrade_custom_bidirectional_roundtrip http_upgrade_custom_bidirectional_roundtrip)
add_waterwall_integration_test(waterwall.http_upgrade_custom_bidirectional_tcp_loopback http_upgrade_custom_bidirectional_tcp_loopback)
# Exercise framed transforms and limiters across real TCP sockets.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND TARGET TcpListener AND TARGET TcpConnector)
  foreach(mode IN ITEMS constant port v1 v2 keepalive keepalive_client keepalive_server keepalive_client_watchdog keepalive_client_timeout
      softiplimiter_vless softiplimiter_trojan speedlimit_line speedlimit_worker speedlimit_all)
    if((mode MATCHES "^keepalive" AND TARGET KeepAliveClient AND TARGET KeepAliveServer)
       OR (mode MATCHES "^(constant|port|v1|v2)$" AND TARGET HeaderServer)
       OR (mode MATCHES "^softiplimiter" AND TARGET SoftIpLimiter)
       OR (mode MATCHES "^speedlimit" AND TARGET SpeedLimit))
      foreach(splice_mode IN ITEMS true false)
        add_waterwall_isolated_test(waterwall.framed_${mode}_splice_${splice_mode}
          "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/framed_splice_integration.py"
          "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${mode}" "${splice_mode}")
        set_tests_properties(waterwall.framed_${mode}_splice_${splice_mode} PROPERTIES TIMEOUT 60)
        add_waterwall_test_labels(waterwall.framed_${mode}_splice_${splice_mode} "integration" "tunnels" "splice")
        add_waterwall_case_resource_lock(waterwall.framed_${mode}_splice_${splice_mode} framed_tcp_splice)
      endforeach()
    endif()
  endforeach()
endif()

# Use a PROXY-aware external peer to check HeaderClient's emitted header bytes.
foreach(splice_mode IN ITEMS true false)
  add_waterwall_isolated_test(waterwall.headerclient_tcp_splice_${splice_mode}
    "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/headerclient_splice_integration.py"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${splice_mode}")
  set_tests_properties(waterwall.headerclient_tcp_splice_${splice_mode} PROPERTIES TIMEOUT 60)
  add_waterwall_test_labels(waterwall.headerclient_tcp_splice_${splice_mode} "integration" "tunnels")
  add_waterwall_case_resource_lock(waterwall.headerclient_tcp_splice_${splice_mode} headerclient_tcp_splice)
endforeach()
# Exercise both real TCP/Mux directions with the same integrity-checked topology.
