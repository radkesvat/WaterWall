if(TARGET DnsLineClient)
  waterwall_add_native_executable(dnslineclient_codec_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/dnslineclient/dnslineclient_codec_test.c
    LIBRARIES DnsLineClient ww)
  add_dependencies(waterwall_unit_tests dnslineclient_codec_test)
  add_waterwall_unit_test(waterwall.dnslineclient_codec_unit dnslineclient_codec_test "unit;tunnels;dns;codec")
endif()

if(LINUX AND TARGET DnsLineClient)
  waterwall_add_native_executable(dnslineclient_flow_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/dnslineclient/dnslineclient_flow_test.c
    LIBRARIES DnsLineClient ww)
  target_link_options(dnslineclient_flow_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
    "-Wl,--wrap=workerResolveDomainServiceAsync"
    "-Wl,--wrap=getHRTimeUs")
  add_dependencies(waterwall_unit_tests dnslineclient_flow_test)
  add_waterwall_unit_test(waterwall.dnslineclient_flow_unit dnslineclient_flow_test
    "unit;tunnels;dns;flow;lifetime;timers")
endif()
