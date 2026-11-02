if(LINUX AND TARGET NextInitGate)
  waterwall_add_native_executable(next_init_gate_test SUPPORT
    SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/next_init_gate/next_init_gate_test.c
      ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    LIBRARIES ww)
  # Keep the ledger visible through helper cleanup in optimized builds too.
  waterwall_line_failure_test_use_tunnel(next_init_gate_test NextInitGate)
  target_link_options(next_init_gate_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  add_waterwall_unit_test(waterwall.next_init_gate_unit next_init_gate_test
    "unit;tunnels;startup;reentrant;lifetime;ownership")
endif()
