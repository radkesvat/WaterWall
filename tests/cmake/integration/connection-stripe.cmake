# Real, private-loopback striping over independent TCP and reliable UDP carriers.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   TARGET ConnectionStripeClient AND TARGET ConnectionStripeServer AND
   TARGET TcpListener AND TARGET TcpConnector)
  foreach(stripe_carrier IN ITEMS tcp tls kcp)
    if((stripe_carrier STREQUAL "tcp") OR
       (stripe_carrier STREQUAL "tls" AND TARGET TlsClient AND TARGET TlsServer) OR
       (stripe_carrier STREQUAL "kcp" AND TARGET KcpClient AND TARGET KcpServer AND
        TARGET UdpListener AND TARGET UdpConnector))
      set(stripe_case waterwall.connection_stripe_${stripe_carrier})
      add_waterwall_isolated_test(${stripe_case}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/connection_stripe_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${stripe_carrier}" --splice true --trace-splice)
      set_tests_properties(${stripe_case} PROPERTIES TIMEOUT 75)
      add_waterwall_test_labels(${stripe_case} "integration" "tunnels" "connection-stripe" "${stripe_carrier}")
      if(stripe_carrier STREQUAL "tcp")
        add_waterwall_test_labels(${stripe_case} "splice")
      endif()
      add_waterwall_case_resource_lock(${stripe_case} connection_stripe)
      if(NOT stripe_carrier STREQUAL "kcp" AND TARGET MuxClient AND TARGET MuxServer)
        set(stripe_mux_case waterwall.connection_stripe_mux_${stripe_carrier})
        add_waterwall_isolated_test(${stripe_mux_case}
          "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/connection_stripe_integration.py"
          "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${stripe_carrier}" --mux --splice true --trace-splice)
        set_tests_properties(${stripe_mux_case} PROPERTIES TIMEOUT 75)
        add_waterwall_test_labels(${stripe_mux_case} "integration" "tunnels" "connection-stripe" "mux" "${stripe_carrier}")
        if(stripe_carrier STREQUAL "tcp")
          add_waterwall_test_labels(${stripe_mux_case} "splice")
        endif()
        add_waterwall_case_resource_lock(${stripe_mux_case} connection_stripe)
      endif()
    endif()
  endforeach()
  # The existing TCP cases above already cover splice-enabled output.
  foreach(stripe_topology IN ITEMS tcp mux_tcp)
    if(stripe_topology STREQUAL "mux_tcp" AND NOT (TARGET MuxClient AND TARGET MuxServer))
      continue()
    endif()
    set(stripe_args --splice false --trace-splice)
    if(stripe_topology STREQUAL "mux_tcp")
      list(APPEND stripe_args --mux)
    endif()
    set(stripe_case waterwall.connection_stripe_${stripe_topology}_splice_false)
    add_waterwall_isolated_test(${stripe_case}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/connection_stripe_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" tcp ${stripe_args})
    set_tests_properties(${stripe_case} PROPERTIES TIMEOUT 75)
    add_waterwall_test_labels(${stripe_case} "integration" "tunnels" "connection-stripe" "tcp" "splice")
    add_waterwall_case_resource_lock(${stripe_case} connection_stripe)
  endforeach()
endif()
