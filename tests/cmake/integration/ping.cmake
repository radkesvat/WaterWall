# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.ping_new_ip_icmp_roundtrip ping_new_ip_icmp_roundtrip)
add_waterwall_expected_failure_integration_test(
  waterwall.ping_legacy_settings_rejected
  ping_legacy_settings_rejected
  "PingClient: configuration uses removed Ping wire v1 setting 'strategy'"
)
add_waterwall_expected_failure_integration_test(
  waterwall.ping_server_legacy_settings_rejected
  ping_server_legacy_settings_rejected
  "PingServer: configuration uses removed Ping wire v1 setting 'strategy'"
)
add_waterwall_expected_failure_integration_test(
  waterwall.node_layer_tundevice_tcpconnector_conflict
  node_layer_tundevice_tcpconnector_conflict
  "requires same layer on both sides, but sides resolved to incompatible domains"
)
add_waterwall_expected_failure_integration_test(
  waterwall.node_layer_bridge_l3_l4_conflict
  node_layer_bridge_l3_l4_conflict
  "registered layer relation between node"
)
add_waterwall_expected_failure_integration_test(
  waterwall.bridge_self_pair_rejected
  bridge_self_pair_rejected
  "Bridge: pair node \"bridge-a\" must name a distinct Bridge node"
)
add_waterwall_expected_failure_integration_test(
  waterwall.bridge_nonbridge_pair_rejected
  bridge_nonbridge_pair_rejected
  "Bridge: pair node \"dropper\" must name a distinct Bridge node"
)
add_waterwall_expected_failure_integration_test(
  waterwall.bridge_nonreciprocal_pair_rejected
  bridge_nonreciprocal_pair_rejected
  "Bridge: pair configuration for node \"bridge-a\" is not reciprocal"
)
add_waterwall_expected_failure_integration_test(
  waterwall.udpstatelesssocket_tail_rejected
  udpstatelesssocket_tail_rejected
  "only chain-head placement is supported"
)
add_waterwall_expected_failure_integration_test(
  waterwall.wireguard_transport_direction_removed
  wireguard_transport_direction_removed
  "transport-direction is no longer supported"
)
add_waterwall_expected_failure_integration_test(
  waterwall.wireguard_ambiguous_layers
  wireguard_ambiguous_layers
  "chain layers must resolve exactly one L3 packet side and one L4 transport side"
)
add_waterwall_privileged_probe_integration_test(waterwall.ping_direct_real_adapters_roundtrip ping_direct_real_adapters_roundtrip 15)
add_waterwall_test_labels(waterwall.ping_direct_real_adapters_roundtrip "ping")
add_waterwall_integration_test(
  waterwall.ipmanipulator_tcp_custom_protocol_roundtrip
  ipmanipulator_tcp_custom_protocol_roundtrip
)
add_waterwall_integration_test(
  waterwall.ipmanipulator_udp_custom_protocol_roundtrip
  ipmanipulator_udp_custom_protocol_roundtrip
)
add_waterwall_integration_test(
  waterwall.ipmanipulator_tcp_custom_protocol_transport_roundtrip
  ipmanipulator_tcp_custom_protocol_transport_roundtrip
)
add_waterwall_integration_test(
  waterwall.ipmanipulator_tcp_custom_protocol_transport_bridge_roundtrip
  ipmanipulator_tcp_custom_protocol_transport_bridge_roundtrip
)
