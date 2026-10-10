# TLS/Reality, classifier and routing registrations.
add_waterwall_integration_test(waterwall.tls_roundtrip tls_roundtrip)
if(TARGET TlsClient AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  set(tls_fragment_modes tls12 tls13 timed no_wait shaped pending)
  if(TARGET Router)
    list(APPEND tls_fragment_modes branch)
  endif()
  if(TARGET RealityClient AND TARGET RealityServer AND TARGET TlsServer AND TARGET TesterClient AND TARGET TesterServer)
    list(APPEND tls_fragment_modes reality)
  endif()
  foreach(fragment_mode IN LISTS tls_fragment_modes)
    set(fragment_case waterwall.tlsclient_fragment_${fragment_mode})
    add_waterwall_isolated_test(${fragment_case}
      "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tlsclient_fragment_integration.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${fragment_mode}")
    set_tests_properties(${fragment_case} PROPERTIES TIMEOUT 60)
    add_waterwall_test_labels(${fragment_case} "integration" "tunnels" "tlsclient" "fragmenter")
  endforeach()
endif()
add_waterwall_integration_test_with_timeout(
  waterwall.tls13_record_shaping_roundtrip
  tls13_record_shaping_roundtrip
  60
)
add_waterwall_probe_integration_test(waterwall.tlsclient_direct_close_probe tlsclient_direct_close_probe 20)
add_waterwall_probe_integration_test(waterwall.mux_parent_pressure_probe mux_parent_pressure_probe 120)
set_tests_properties(waterwall.mux_parent_pressure_probe PROPERTIES ENVIRONMENT "WATERWALL_TEST_SPLICE=true")
add_waterwall_test_labels(waterwall.mux_parent_pressure_probe "stress")
add_waterwall_probe_integration_test(waterwall.mux_parent_pressure_no_splice_probe mux_parent_pressure_probe 120)
set_tests_properties(waterwall.mux_parent_pressure_no_splice_probe PROPERTIES ENVIRONMENT "WATERWALL_TEST_SPLICE=false")
add_waterwall_test_labels(waterwall.mux_parent_pressure_no_splice_probe "stress")
add_waterwall_probe_integration_test(waterwall.muxserver_admission_idle_probe muxserver_admission_idle_probe 15)
add_waterwall_probe_integration_test(waterwall.mux_udp_boundaries_probe mux_udp_boundaries_probe 15)
set_tests_properties(waterwall.mux_udp_boundaries_probe PROPERTIES ENVIRONMENT "WATERWALL_TEST_SPLICE=true")
add_waterwall_probe_integration_test(waterwall.mux_udp_boundaries_no_splice_probe mux_udp_boundaries_probe 15)
set_tests_properties(waterwall.mux_udp_boundaries_no_splice_probe PROPERTIES ENVIRONMENT "WATERWALL_TEST_SPLICE=false")
add_waterwall_integration_test(waterwall.tls_fallback_plaintext_probe_tcp_loopback tls_fallback_plaintext_probe_tcp_loopback)
add_waterwall_integration_test(waterwall.tls_fallback_connector_target_tcp_loopback tls_fallback_connector_target_tcp_loopback)
add_waterwall_probe_integration_test(waterwall.tls_handshake_timeout_slow_drip tls_handshake_timeout_slow_drip 10)
if(LINUX)
  add_waterwall_probe_integration_test(waterwall.tcpconnector_delayed_fallback_connect tcpconnector_delayed_fallback_connect 45)
endif()
add_waterwall_probe_integration_test(waterwall.tls_tlslike_invalid_probe_does_not_fallback tls_tlslike_invalid_probe_does_not_fallback 10)
add_waterwall_probe_integration_test(waterwall.tls_tlslike_oversized_probe_does_not_fallback tls_tlslike_oversized_probe_does_not_fallback 10)
add_waterwall_probe_integration_test(
  waterwall.tlsserver_sni_fallback_probe
  tlsserver_sni_fallback_probe
  30
)
add_waterwall_external_integration_test(waterwall.reality_google_roundtrip reality_google_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_roundtrip reality_v2_roundtrip)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_post_handshake reality_v2_tls13_post_handshake 20)
add_waterwall_integration_test(waterwall.reality_v2_tls13_handoff reality_v2_tls13_handoff)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_transition_matrix reality_v2_tls13_transition_matrix 45)
add_waterwall_integration_test(waterwall.reality_v2_tls12_roundtrip reality_v2_tls12_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_cbc_roundtrip reality_v2_tls12_cbc_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_gcm_sequence_roundtrip reality_v2_tls12_gcm_sequence_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_gcm_counter_roundtrip reality_v2_tls12_gcm_counter_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_gcm_random_roundtrip reality_v2_tls12_gcm_random_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_tls12_cbc256_roundtrip reality_v2_tls12_cbc256_roundtrip)
add_waterwall_integration_test(waterwall.reality_v2_aes_gcm_roundtrip reality_v2_aes_gcm_roundtrip)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls12_gcm_wire_camouflage reality_v2_tls12_gcm_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls12_cbc_wire_camouflage reality_v2_tls12_cbc_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls12_chacha_wire_camouflage reality_v2_tls12_chacha_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_wire_camouflage reality_v2_tls13_wire_probe 20)
add_waterwall_probe_integration_test(waterwall.reality_v2_tls13_wire_handoff reality_v2_tls13_wire_handoff 30)
# One probe run drives the whole replay-protection sequence: it captures Reality
# records from an original connection, then replays them in the wrong direction,
# directly against the server, and across a fresh connection. The closing
# assertion (the protected chain was opened exactly once) covers all three at
# once, so this is a single test rather than three names for the same command.
add_waterwall_probe_integration_test(waterwall.reality_v2_replay_protection reality_v2_replay_protection_probe 15)
add_waterwall_integration_test(waterwall.reality_visitor_plaintext_probe reality_visitor_plaintext_probe)
add_waterwall_probe_integration_test(
  waterwall.reality_visitor_short_prefix_probe
  reality_visitor_short_prefix_probe
  15
)
add_waterwall_expected_failure_integration_test(
  waterwall.reality_client_rejects_obsolete_max_frame_size
  reality_client_rejects_obsolete_max_frame_size
  "RealityClient: 'max-frame-size' is obsolete"
)
add_waterwall_expected_failure_integration_test(
  waterwall.reality_server_rejects_obsolete_max_frame_size
  reality_server_rejects_obsolete_max_frame_size
  "RealityServer: 'max-frame-size' is obsolete"
)
add_test(
  NAME waterwall.reality_config_startup
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/reality_config_validation_test.py"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
)
set_tests_properties(
  waterwall.reality_config_startup
  PROPERTIES
    TIMEOUT 240
    LABELS "integration;tunnels;reality;tlsclient;configuration;negative"
    RESOURCE_LOCK waterwall_reality_configuration
)
add_test(
  NAME waterwall.restricted_config_input
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/restricted_config_input_test.py" "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
)
set_tests_properties(waterwall.restricted_config_input PROPERTIES
  TIMEOUT 120 LABELS "integration;core;startup;configuration;security")
add_test(
  NAME waterwall.core_json_input
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/core_json_input_test.py"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
)
# Allow sequential packed startups; each child still has a 10-second timeout.
set_tests_properties(
  waterwall.core_json_input
  PROPERTIES
    TIMEOUT 120
    LABELS "integration;core;startup;configuration"
)
add_test(
  NAME waterwall.tunnels_abort_policy_test
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tunnels_abort_policy_test.py"
)
set_tests_properties(
  waterwall.tunnels_abort_policy_test
  PROPERTIES
    TIMEOUT 120
    LABELS "unit;tunnels;policy;source-policy;abort"
)
add_test(
  NAME waterwall.tunnels_orderly_shutdown_policy_test
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tunnels_orderly_shutdown_policy_test.py"
)
set_tests_properties(
  waterwall.tunnels_orderly_shutdown_policy_test
  PROPERTIES
    TIMEOUT 120
    LABELS "unit;tunnels;policy;source-policy;shutdown"
)
add_test(
  NAME waterwall.ipmanipulator_source_policy_test
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/ipmanipulator_source_policy_test.py"
)
set_tests_properties(
  waterwall.ipmanipulator_source_policy_test
  PROPERTIES
    TIMEOUT 30
    LABELS "unit;tunnels;ipmanipulator;policy;source-policy;nonblocking"
)
add_test(
  NAME waterwall.worker_identity_source_policy_test
  COMMAND
    "${PYTHON3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/worker_identity_source_policy_test.py"
)
set_tests_properties(
  waterwall.worker_identity_source_policy_test
  PROPERTIES
    TIMEOUT 60
    LABELS "unit;worker;identity;context;policy;source-policy"
)
add_waterwall_integration_test(waterwall.connection_fisher_roundtrip connection_fisher_roundtrip)
add_waterwall_integration_test(waterwall.connection_fisher_encryption_roundtrip connection_fisher_encryption_roundtrip)
add_waterwall_integration_test(waterwall.sniffrouter_non_http_tcp_loopback sniffrouter_non_http_tcp_loopback)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND TARGET Router AND TARGET SniffRouter)
  foreach(router_mode IN ITEMS router_metadata router_sniff router_resolve sniffrouter)
    foreach(splice_mode IN ITEMS true false)
      set(router_case waterwall.${router_mode}_tcp_splice_${splice_mode})
      add_waterwall_isolated_test(${router_case}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/router_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${router_mode}" "${splice_mode}")
      set_tests_properties(${router_case} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(${router_case} "integration" "tunnels")
      add_waterwall_case_resource_lock(${router_case} router_splice)
    endforeach()
  endforeach()
endif()
add_waterwall_integration_test(waterwall.sniffrouter_http_domain_tcp_loopback sniffrouter_http_domain_tcp_loopback)
add_waterwall_probe_integration_test(
  waterwall.sniffrouter_tls_sni_camouflage_probe
  sniffrouter_tls_sni_camouflage_probe
  30
)
add_waterwall_integration_test(waterwall.router_connector_rule_target_tcp_loopback router_connector_rule_target_tcp_loopback)
add_waterwall_integration_test(waterwall.router_domainresolver_connector_rule_target_tcp_loopback router_domainresolver_connector_rule_target_tcp_loopback)
