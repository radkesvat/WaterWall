add_test(
  NAME waterwall.enet_vendor_source_policy
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/enet_vendor_source_policy_test.py"
)
set_tests_properties(waterwall.enet_vendor_source_policy PROPERTIES
  TIMEOUT 30 LABELS "unit;policy;source-policy;tunnels;enet;vendor")

# Both peers run in one WaterWall process and are joined directly, so no socket is bound.
if(TARGET EnetClient AND TARGET EnetServer AND
   CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(enet_case IN ITEMS enet_roundtrip enet_disturber_roundtrip)
    add_waterwall_integration_test(waterwall.${enet_case} ${enet_case})
    add_waterwall_test_labels(waterwall.${enet_case} "enet")
  endforeach()
  # The close probes also cross UDP sockets on the namespace's loopback.
  if(TARGET TcpListener AND TARGET TcpConnector AND TARGET UdpListener AND TARGET UdpConnector)
    add_waterwall_probe_integration_test(waterwall.enet_service_close_probe enet_service_close_probe 30)
    add_waterwall_test_labels(waterwall.enet_service_close_probe "enet")
    add_waterwall_probe_integration_test(waterwall.enet_upload_close_probe enet_upload_close_probe 60)
    add_waterwall_test_labels(waterwall.enet_upload_close_probe "enet")
  endif()
  # Fixed serial workloads. The reported rate is diagnostic for the host and is not a threshold.
  if(TARGET SpeedTestClient AND TARGET SpeedTestServer AND TARGET UdpListener AND TARGET UdpConnector)
    foreach(enet_speedtest IN ITEMS enet_direct_pair enet_udp_sandwich)
      add_waterwall_speedtest(waterwall.speedtest_${enet_speedtest} ${enet_speedtest})
      add_waterwall_test_labels(waterwall.speedtest_${enet_speedtest} "enet")
    endforeach()
  endif()
endif()
