# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
foreach(orderly_case IN ITEMS
  "TesterClient|testerclient_orderly_shutdown_test|testerclient|OFF|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tester/testerclient_orderly_shutdown_test.c"
  "SpeedTestClient|speedtestclient_orderly_shutdown_test|speedtestclient|OFF|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/speedtest/speedtestclient_orderly_shutdown_test.c"
  "TesterServer|testerserver_orderly_shutdown_test|testerserver|OFF|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tester/testerserver_orderly_shutdown_test.c"
  "PacketsToStream|packetstostream_orderly_shutdown_test|packetstostream|ON|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstostream_orderly_shutdown_test.c"
  "PacketSender|packetsender_orderly_shutdown_test|packetsender|ON|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_io/packetsender_orderly_shutdown_test.c"
  "AuthenticationClient|authenticationclient_orderly_shutdown_test|authenticationclient|ON|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/authentication/authenticationclient_orderly_shutdown_test.c"
  "KeepAliveClient|keepaliveclient_orderly_shutdown_test|keepaliveclient|ON|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/keepalive/keepaliveclient_orderly_shutdown_test.c"
  "UserController|usercontroller_orderly_shutdown_test|usercontroller|ON|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/usercontroller/usercontroller_orderly_shutdown_test.c"
  "WireGuardDevice|wireguarddevice_orderly_shutdown_test|wireguarddevice|OFF|${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguarddevice_orderly_shutdown_test.c"
)
  string(REPLACE "|" ";" orderly_fields "${orderly_case}")
  list(GET orderly_fields 0 orderly_tunnel)
  list(GET orderly_fields 1 orderly_test)
  list(GET orderly_fields 2 orderly_label)
  list(GET orderly_fields 3 orderly_wraps_timer)
  list(GET orderly_fields 4 orderly_source)

  if(TARGET ${orderly_tunnel})
    waterwall_add_native_executable(${orderly_test} SOURCES "${orderly_source}"
      ${WATERWALL_LINE_FAILURE_WW_SOURCES})
    waterwall_line_failure_test_use_tunnel(${orderly_test} ${orderly_tunnel})
    target_link_options(${orderly_test} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    if(orderly_wraps_timer)
      target_link_options(${orderly_test} PRIVATE "-Wl,--wrap=wtimerAdd")
    endif()
    if(orderly_tunnel STREQUAL "PacketsToStream" OR orderly_tunnel STREQUAL "PacketSender")
      target_link_options(${orderly_test} PRIVATE "-Wl,--wrap=wtimerReset")
    endif()
    if(orderly_tunnel STREQUAL "PacketsToStream")
      target_link_options(${orderly_test} PRIVATE "-Wl,--wrap=lineScheduleTask")
    endif()
    if(orderly_tunnel STREQUAL "WireGuardDevice")
      target_sources(${orderly_test} PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice/instance/start.c
      )
      target_link_options(${orderly_test} PRIVATE
        "-Wl,--wrap=memoryAllocateZero"
        "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
        "-Wl,--wrap=wtimerAdd"
      )
    endif()
    if(orderly_tunnel STREQUAL "SpeedTestClient")
      target_link_options(${orderly_test} PRIVATE
        "-Wl,--wrap=memoryAllocate"
        "-Wl,--wrap=memoryFree"
        "-Wl,--wrap=lineScheduleTask"
        "-Wl,--wrap=lineScheduleDelayedTask"
      )
    endif()
    if(orderly_tunnel STREQUAL "TesterServer")
      target_link_options(${orderly_test} PRIVATE
        "-Wl,--wrap=lineScheduleTask"
        "-Wl,--wrap=lineScheduleDelayedTask"
      )
    endif()
    if(orderly_tunnel STREQUAL "TesterClient")
      target_sources(${orderly_test} PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/TesterClient/instance/start.c
      )
      target_compile_definitions(${orderly_test} PRIVATE WW_TESTERCLIENT_START_TEST_SEAM=1)
      target_link_options(${orderly_test} PRIVATE
        "-Wl,--wrap=lineScheduleTask"
        "-Wl,--wrap=lineScheduleDelayedTask"
      )
    endif()
    target_link_libraries(${orderly_test} PRIVATE ww)
    add_dependencies(waterwall_unit_tests ${orderly_test})

    add_waterwall_unit_test(
      waterwall.${orderly_test}_unit
      ${orderly_test}
      "unit;tunnels;${orderly_label};failure;shutdown"
    )
  endif()
endforeach()

# A client-side Payload callback may re-enter Socks5Server and drain the
# response's UDP remote.  Retain that remote across the cross-line callback;
# next/upstream Finish recipients remain borrowers and may not destroy it.
if(TARGET Socks5Server)
  waterwall_add_native_executable(socks5server_udp_close_reentrant_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5server_udp_close_reentrant_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(socks5server_udp_close_reentrant_test Socks5Server)
  target_link_options(socks5server_udp_close_reentrant_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(socks5server_udp_close_reentrant_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socks5server_udp_close_reentrant_test)

  add_waterwall_unit_test(
    waterwall.socks5server_udp_close_reentrant_unit
    socks5server_udp_close_reentrant_test
    "unit;tunnels;socks5server;udp;reentrant;finish;lifetime;ownership;payload"
  )

  waterwall_add_native_executable(socks5server_dynamic_provider_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/socks/socks5server_dynamic_provider_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(socks5server_dynamic_provider_test Socks5Server)
  target_link_options(socks5server_dynamic_provider_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(socks5server_dynamic_provider_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socks5server_dynamic_provider_test)

  add_waterwall_unit_test(
    waterwall.socks5server_dynamic_provider_unit
    socks5server_dynamic_provider_test
    "unit;tunnels;socks5server;udp;dynamic;provider;worker"
  )
endif()

