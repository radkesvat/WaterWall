# Public callback coverage of the complete client/server striping protocol.
if(TARGET ConnectionStripeClient AND TARGET ConnectionStripeServer)
  waterwall_add_native_executable(connectionstripe_session_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/connection_stripe/connectionstripe_session_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(connectionstripe_session_test ConnectionStripeCommon)
  target_link_libraries(connectionstripe_session_test PRIVATE ConnectionStripeClient ConnectionStripeServer ww)
  target_link_options(connectionstripe_session_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  add_waterwall_unit_test(waterwall.connectionstripe_session_unit connectionstripe_session_test
    "unit;tunnels;connectionstripe;framing;flow;reentrant;lifetime" 60)
endif()
