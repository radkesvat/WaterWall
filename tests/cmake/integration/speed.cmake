# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_speedtest(waterwall.speedtest_direct_pair direct_pair)
add_waterwall_speedtest(waterwall.speedtest_tcp_loopback tcp_loopback)
add_waterwall_speedtest(waterwall.speedtest_udp_over_tcp_direct_pair udp_over_tcp_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_udp_over_tcp_udp_sandwich udp_over_tcp_udp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_tcp_over_udp_direct_pair tcp_over_udp_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_tcp_over_udp_udp_sandwich tcp_over_udp_udp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_obfuscator_direct_pair obfuscator_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_obfuscator_tcp_sandwich obfuscator_tcp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_tls_direct_pair tls_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_tls_tcp_sandwich tls_tcp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_encryption_direct_pair encryption_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_encryption_tcp_sandwich encryption_tcp_sandwich)
add_waterwall_external_speedtest(waterwall.speedtest_reality_direct_pair reality_direct_pair)
add_waterwall_external_speedtest(waterwall.speedtest_reality_tcp_sandwich reality_tcp_sandwich)
add_waterwall_speedtest(waterwall.speedtest_mux_direct_pair mux_direct_pair)
add_waterwall_speedtest(waterwall.speedtest_mux_tcp_sandwich mux_tcp_sandwich)

add_custom_target(check_waterwall_integration_tests
  COMMAND
    "${BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_test_lane.sh"
    functional
    "${CMAKE_BINARY_DIR}"
    "$<CONFIG>"
  DEPENDS ${WATERWALL_TEST_TARGET}
  USES_TERMINAL
)

add_custom_target(check_waterwall_external_integration_tests
  COMMAND
    "${BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_test_lane.sh"
    external
    "${CMAKE_BINARY_DIR}"
    "$<CONFIG>"
  DEPENDS ${WATERWALL_TEST_TARGET}
  USES_TERMINAL
)

add_custom_target(check_waterwall_speedtests
  COMMAND
    "${BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_test_lane.sh"
    speed
    "${CMAKE_BINARY_DIR}"
    "$<CONFIG>"
  DEPENDS ${WATERWALL_TEST_TARGET}
  USES_TERMINAL
)
add_custom_target(check_waterwall_support_tests
  COMMAND
    "${BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_test_lane.sh"
    support
    "${CMAKE_BINARY_DIR}"
    "$<CONFIG>"
  DEPENDS ${WATERWALL_TEST_TARGET}
  USES_TERMINAL
)

