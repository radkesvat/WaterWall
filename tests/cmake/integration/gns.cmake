# Both peers run in one WaterWall process and are joined directly, so no socket is bound.
if(TARGET GnsClient AND TARGET GnsServer AND
   CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(gns_case IN ITEMS gns_roundtrip gns_disturber_roundtrip)
    add_waterwall_integration_test(waterwall.${gns_case} ${gns_case})
    add_waterwall_test_labels(waterwall.${gns_case} "gns")
  endforeach()
  # The close probes also cross UDP sockets on the namespace's loopback.
  if(TARGET TcpListener AND TARGET TcpConnector AND TARGET UdpListener AND TARGET UdpConnector)
    add_waterwall_probe_integration_test(waterwall.gns_service_close_probe gns_service_close_probe 30)
    add_waterwall_test_labels(waterwall.gns_service_close_probe "gns")
    add_waterwall_probe_integration_test(waterwall.gns_upload_close_probe gns_upload_close_probe 60)
    add_waterwall_test_labels(waterwall.gns_upload_close_probe "gns")
  endif()
  # Fixed serial workloads. The reported rate is diagnostic for the host and is not a threshold.
  if(TARGET SpeedTestClient AND TARGET SpeedTestServer AND TARGET UdpListener AND TARGET UdpConnector)
    foreach(gns_speedtest IN ITEMS gns_direct_pair gns_udp_sandwich)
      add_waterwall_speedtest(waterwall.speedtest_${gns_speedtest} ${gns_speedtest})
      add_waterwall_test_labels(waterwall.speedtest_${gns_speedtest} "gns")
    endforeach()
  endif()
endif()
