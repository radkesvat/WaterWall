# Raw QUIC carriers are explicit; all live endpoints are private loopback peers.
if(TARGET QuicClient AND TARGET QuicServer AND
   CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(quic_mode IN ITEMS direct udp stream udp-impaired shutdown failures)
    string(REPLACE "-" "_" quic_case "waterwall.quic_${quic_mode}")
    add_waterwall_isolated_test(${quic_case}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/quic_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${quic_mode}")
    set_tests_properties(${quic_case} PROPERTIES TIMEOUT 65)
    add_waterwall_test_labels(${quic_case} "integration" "tunnels" "quic")
  endforeach()
  # Each constructor has over a hundred startup cases. Give the roles separate
  # scheduling slots so packed startup cost does not accumulate in one test.
  # Allow cumulative packed launches while keeping per-case startup/shutdown deadlines unchanged.
  foreach(quic_role IN ITEMS client server)
    set(quic_config_case waterwall.quic_config_startup_${quic_role})
    add_waterwall_isolated_test(${quic_config_case}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/quic_config_validation_test.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${quic_role}")
    set_tests_properties(${quic_config_case} PROPERTIES TIMEOUT 360)
    add_waterwall_test_labels(${quic_config_case} "integration" "tunnels" "quic" "configuration" "negative")
  endforeach()
  if(TARGET VlessClient AND TARGET VlessServer AND TARGET SpeedTestClient AND TARGET SpeedTestServer)
    add_waterwall_isolated_test(waterwall.quic_speedtest_vless_udp
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/quic_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "speed")
    set_tests_properties(waterwall.quic_speedtest_vless_udp PROPERTIES TIMEOUT 65 RUN_SERIAL TRUE)
    add_waterwall_test_labels(waterwall.quic_speedtest_vless_udp "integration" "tunnels" "quic" "speedtest")
  endif()
endif()
