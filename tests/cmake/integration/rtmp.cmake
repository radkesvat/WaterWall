if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING
   AND WATERWALL_ENABLE_INTEGRATION_TEST_NETNS AND TARGET RtmpClient AND TARGET RtmpServer
   AND TARGET TcpListener AND TARGET TcpConnector)
  set(rtmp_cases bidirectional_tcp_loopback tcp_upload_eof tcp_download_eof negotiation_timeout)
  if(TARGET VlessClient AND TARGET VlessServer)
    list(APPEND rtmp_cases vless_tcp_loopback)
  endif()
  if(TARGET TlsClient AND TARGET TlsServer)
    list(APPEND rtmp_cases tls_bidirectional_tcp_loopback)
  endif()
  if(TARGET UdpListener AND TARGET UdpConnector AND TARGET UdpOverTcpClient AND TARGET UdpOverTcpServer)
    list(APPEND rtmp_cases udp_over_tcp_roundtrip)
  endif()

  foreach(mode IN LISTS rtmp_cases)
    if(mode STREQUAL "tls_bidirectional_tcp_loopback")
      set(test_name waterwall.rtmps_bidirectional_tcp_loopback)
    else()
      set(test_name waterwall.rtmp_${mode})
    endif()
    add_waterwall_isolated_test(${test_name}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/rtmp_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${mode}")
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 50)
    add_waterwall_test_labels(${test_name} "integration" "tunnels" "rtmp")
  endforeach()
endif()
