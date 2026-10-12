# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.reverse_tcp_bridge_roundtrip reverse_tcp_bridge_roundtrip)
add_waterwall_integration_test(waterwall.reverse_custom_secret_tcp_bridge_roundtrip reverse_custom_secret_tcp_bridge_roundtrip)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND TARGET ReverseServer AND TARGET Bridge)
  foreach(reverse_workers IN ITEMS 1 2)
    foreach(splice_mode IN ITEMS true false)
      set(reverse_case waterwall.reverseserver_workers_${reverse_workers}_splice_${splice_mode})
      add_waterwall_isolated_test(${reverse_case}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/reverseserver_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${reverse_workers}" "${splice_mode}")
      set_tests_properties(${reverse_case} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(${reverse_case} "integration" "tunnels")
      add_waterwall_case_resource_lock(${reverse_case} reverseserver_splice)
      if(TARGET ReverseClient AND TARGET TcpConnector)
        set(activation_case waterwall.reverse_activation_workers_${reverse_workers}_splice_${splice_mode})
        add_waterwall_isolated_test(${activation_case}
          "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/reverse_activation_integration.py"
          "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${reverse_workers}" "${splice_mode}")
        set_tests_properties(${activation_case} PROPERTIES TIMEOUT 60)
        add_waterwall_test_labels(${activation_case} "integration" "tunnels")
        add_waterwall_case_resource_lock(${activation_case} reverse_activation)
      endif()
    endforeach()
  endforeach()
endif()
