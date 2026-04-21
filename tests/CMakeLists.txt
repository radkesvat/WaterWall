find_program(BASH_EXECUTABLE bash REQUIRED)

function(add_waterwall_integration_test test_name case_name)
  set(case_dir "${CMAKE_CURRENT_SOURCE_DIR}/cases/${case_name}")

  add_test(
    NAME ${test_name}
    COMMAND
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/run_waterwall_case.sh"
      "$<TARGET_FILE:Waterwall>"
      "${case_dir}"
      "15"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 18
      LABELS "integration;tunnels"
  )
endfunction()

add_waterwall_integration_test(waterwall.disturber_passthrough disturber_passthrough)
add_waterwall_integration_test(waterwall.obfuscator_roundtrip obfuscator_roundtrip)
add_waterwall_integration_test(waterwall.obfuscator_tls_record_roundtrip obfuscator_tls_record_roundtrip)
add_waterwall_integration_test(waterwall.encryption_roundtrip encryption_roundtrip)
add_waterwall_integration_test(waterwall.encryption_small_frame_roundtrip encryption_small_frame_roundtrip)
add_waterwall_integration_test(waterwall.keepalive_roundtrip keepalive_roundtrip)
add_waterwall_integration_test(waterwall.udp_over_tcp_roundtrip udp_over_tcp_roundtrip)
add_waterwall_integration_test(waterwall.halfduplex_roundtrip halfduplex_roundtrip)
add_waterwall_integration_test(waterwall.mux_counter_roundtrip mux_counter_roundtrip)
add_waterwall_integration_test(waterwall.mux_timer_roundtrip mux_timer_roundtrip)
add_waterwall_integration_test(waterwall.config_variables_roundtrip config_variables_roundtrip)
