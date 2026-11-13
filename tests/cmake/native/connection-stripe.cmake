# Public callback coverage of the complete client/server striping protocol.
if(TARGET ConnectionStripeClient AND TARGET ConnectionStripeServer)
  waterwall_add_native_executable(connectionstripe_session_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/connection_stripe/connectionstripe_session_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(connectionstripe_session_test ConnectionStripeCommon)
  target_link_libraries(connectionstripe_session_test PRIVATE ConnectionStripeClient ConnectionStripeServer ww)
  target_link_options(connectionstripe_session_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  add_waterwall_unit_test(waterwall.connectionstripe_session_unit connectionstripe_session_test
    "unit;tunnels;connectionstripe;splice;framing;flow;reentrant;lifetime" 60)
  if(LINUX)
    # Compile the actual Stripe and buffer implementations without splice; a
    # fixture-only definition would still exercise splice-enabled ww objects.
    waterwall_add_native_executable(connectionstripe_no_splice_test SUPPORT SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/connection_stripe/connectionstripe_session_test.c
      ${WATERWALL_LINE_FAILURE_WW_SOURCES}
      ${CMAKE_SOURCE_DIR}/ww/bufio/shiftbuffer.c
      ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_pool.c
      ${CMAKE_SOURCE_DIR}/ww/net/chain.c)
    waterwall_line_failure_test_use_tunnel(connectionstripe_no_splice_test ConnectionStripeCommon)
    target_compile_definitions(connectionstripe_no_splice_test PRIVATE WW_HAVE_SPLICE=0)
    target_link_libraries(connectionstripe_no_splice_test PRIVATE ConnectionStripeClient ConnectionStripeServer ww)
    target_link_options(connectionstripe_no_splice_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    add_waterwall_unit_test(waterwall.connectionstripe_no_splice_unit connectionstripe_no_splice_test
      "unit;tunnels;connectionstripe;no-splice;framing;flow;reentrant;lifetime" 60)
  endif()
endif()
