# Explicit integration registrations; preserve namespace and family variants.
add_waterwall_integration_test(waterwall.mux_tcp_splice_roundtrip mux_tcp_splice_roundtrip)
set_tests_properties(waterwall.mux_tcp_splice_roundtrip PROPERTIES ENVIRONMENT "WATERWALL_TEST_SPLICE=true")
add_waterwall_integration_test(waterwall.mux_tcp_no_splice_roundtrip mux_tcp_splice_roundtrip)
set_tests_properties(waterwall.mux_tcp_no_splice_roundtrip PROPERTIES ENVIRONMENT "WATERWALL_TEST_SPLICE=false")
add_waterwall_integration_test(waterwall.mux_counter_roundtrip mux_counter_roundtrip)
add_waterwall_integration_test(waterwall.mux_timer_roundtrip mux_timer_roundtrip)
add_waterwall_integration_test(waterwall.mux_fixed_connections_count_roundtrip mux_fixed_connections_count_roundtrip)
add_waterwall_integration_test(waterwall.mux_parent_buffer_limit_roundtrip mux_parent_buffer_limit_roundtrip)
add_waterwall_integration_test(waterwall.shutdown_production_sequence shutdown_production_sequence)
add_waterwall_integration_test(waterwall.config_variables_roundtrip config_variables_roundtrip)
# StreamToPackets chooses a return carrier per inner flow by rendezvous hashing,
# so adding or removing a stream line remaps some flows to a different carrier and
# a packet may overtake one already in flight on the old carrier. That is a
# documented property of the node, and the tester pair is a strictly ordered
# integrity checker, so every bridge case has to keep one of the two out of play:
#
#   - the three multi-chunk cases below run on one worker (workers.txt), which
#     gives them one stream line and no membership change to reorder around;
#   - the multi-worker case keeps four workers for the affinity contract and uses
#     chunk-count 1, so each worker exchanges a single packet and has no ordering
#     of its own to violate.
#
# Cross-worker ownership and per-flow selection are covered precisely and
# deterministically by streamtopackets_ownership_test and
# packetstostream_bridge_affinity_test.
