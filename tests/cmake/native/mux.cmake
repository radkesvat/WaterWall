# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
foreach(mux_side Client Server)
  string(TOLOWER "${mux_side}" mux_side_lower)
  set(mux_target "Mux${mux_side}")
  set(mux_test "mux${mux_side_lower}_frame_encoding_test")

  if(TARGET ${mux_target})
    waterwall_add_native_executable(${mux_test} SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/${mux_test}.c"
      ${WATERWALL_LINE_FAILURE_WW_SOURCES}
      ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/src/mux_wire.c)
    waterwall_line_failure_test_use_tunnel(${mux_test} ${mux_target})
    target_link_options(${mux_test} PRIVATE
      ${WATERWALL_LINE_FAILURE_WRAPS}
      "-Wl,--wrap=memoryAllocate"
      "-Wl,--wrap=memoryReAllocate"
      "-Wl,--wrap=sbufConcat"
      "-Wl,--wrap=sbufSpliceReadToBuffer"
      "-Wl,--wrap=sbufReadRangeToMemory"
      "-Wl,--wrap=sbufSpliceMaterializeToBuffer"
    )
    target_link_libraries(${mux_test} PRIVATE ww)
    add_dependencies(waterwall_unit_tests ${mux_test})

    add_waterwall_unit_test(
      waterwall.${mux_test}_unit
      ${mux_test}
      "unit;tunnels;mux;framing"
    )
  endif()
endforeach()

if(TARGET MuxServer)
  waterwall_add_native_executable(muxserver_admission_reentrancy_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxserver_admission_reentrancy_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/src/mux_wire.c)
  waterwall_line_failure_test_use_tunnel(muxserver_admission_reentrancy_test MuxServer)
  target_link_options(muxserver_admission_reentrancy_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(muxserver_admission_reentrancy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests muxserver_admission_reentrancy_test)

  add_waterwall_unit_test(
    waterwall.muxserver_admission_reentrancy_unit
    muxserver_admission_reentrancy_test
    "unit;tunnels;muxserver;admission;reentrant;lifetime;ownership;sanitizer"
  )

  waterwall_add_native_executable(muxserver_idle_lifecycle_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxserver_idle_lifecycle_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/src/mux_wire.c)
  waterwall_line_failure_test_use_tunnel(muxserver_idle_lifecycle_test MuxServer)
  target_link_options(muxserver_idle_lifecycle_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(muxserver_idle_lifecycle_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests muxserver_idle_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.muxserver_idle_lifecycle_unit
    muxserver_idle_lifecycle_test
    "unit;tunnels;muxserver;idle-table;reentrant;lifetime;ownership;sanitizer"
  )

  waterwall_add_native_executable(muxserver_admission_concurrency_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxserver_admission_concurrency_test.c)
  target_include_directories(muxserver_admission_concurrency_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/MuxServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include
  )
  target_link_libraries(muxserver_admission_concurrency_test PRIVATE MuxServer ww)
  add_dependencies(waterwall_unit_tests muxserver_admission_concurrency_test)

  add_waterwall_unit_test(
    waterwall.muxserver_admission_concurrency_unit
    muxserver_admission_concurrency_test
    "unit;tunnels;muxserver;admission;concurrency;ownership;tsan;sanitizer"
  )
endif()

if(TARGET MuxClient)
  waterwall_add_native_executable(muxclient_capacity_dispatch_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxclient_capacity_dispatch_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/src/mux_wire.c)
  waterwall_line_failure_test_use_tunnel(muxclient_capacity_dispatch_test MuxClient)
  target_link_options(muxclient_capacity_dispatch_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(muxclient_capacity_dispatch_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests muxclient_capacity_dispatch_test)

  add_waterwall_unit_test(
    waterwall.muxclient_capacity_dispatch_unit
    muxclient_capacity_dispatch_test
    "unit;tunnels;muxclient;capacity;cid;dispatch;lifetime;ownership;sanitizer"
  )
endif()

if(LINUX AND TARGET MuxClient AND TARGET TlsServer AND TARGET TlsRecordShapingCommon)
  waterwall_add_native_executable(muxclient_tlsserver_close_backpressure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxclient_tlsserver_close_backpressure_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/mux_tls_close_backpressure_fixture.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxclient_backpressure_fixture.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsserver_backpressure_fixture.c)
  target_include_directories(muxclient_tlsserver_close_backpressure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/MuxClient/include
    ${CMAKE_SOURCE_DIR}/tunnels/TlsServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include
  )
  target_compile_definitions(muxclient_tlsserver_close_backpressure_test PRIVATE
    MXB_TLS_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    MXB_TLS_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(muxclient_tlsserver_close_backpressure_test PRIVATE
    MuxClient TlsServer TlsRecordShapingCommon ww
  )
  add_dependencies(waterwall_unit_tests muxclient_tlsserver_close_backpressure_test)
  add_waterwall_unit_test(
    waterwall.muxclient_tlsserver_close_backpressure_unit
    muxclient_tlsserver_close_backpressure_test
    "unit;tunnels;muxclient;tlsserver;tls13_record;backpressure;lifecycle"
  )
endif()

if(LINUX AND TARGET MuxServer AND TARGET TlsClient AND TARGET TlsRecordShapingCommon)
  waterwall_add_native_executable(muxserver_tlsclient_close_backpressure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxserver_tlsclient_close_backpressure_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/mux_tls_close_backpressure_fixture.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxserver_backpressure_fixture.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tlsclient_backpressure_fixture.c)
  target_include_directories(muxserver_tlsclient_close_backpressure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/MuxServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include
  )
  target_include_directories(muxserver_tlsclient_close_backpressure_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(muxserver_tlsclient_close_backpressure_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    MXB_TLS_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    MXB_TLS_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(muxserver_tlsclient_close_backpressure_test PRIVATE
    MuxServer TlsClient TlsRecordShapingCommon ww ssl crypto
  )
  add_dependencies(waterwall_unit_tests muxserver_tlsclient_close_backpressure_test)
  add_waterwall_unit_test(
    waterwall.muxserver_tlsclient_close_backpressure_unit
    muxserver_tlsclient_close_backpressure_test
    "unit;tunnels;muxserver;tlsclient;tls13_record;backpressure;lifecycle;ownership"
  )
endif()

if(TARGET MuxClient AND TARGET UdpListener)
  waterwall_add_native_executable(udplistener_mux_shutdown_order_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/udplistener_mux_shutdown_order_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/udplistener_shutdown_fixture.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(udplistener_mux_shutdown_order_test MuxClient)
  target_include_directories(udplistener_mux_shutdown_order_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/UdpListener/include
    ${CMAKE_SOURCE_DIR}/ww/managers
  )
  target_link_options(udplistener_mux_shutdown_order_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(udplistener_mux_shutdown_order_test PRIVATE UdpListener ww)
  add_dependencies(waterwall_unit_tests udplistener_mux_shutdown_order_test)
  add_waterwall_unit_test(
    waterwall.udplistener_mux_shutdown_order_unit
    udplistener_mux_shutdown_order_test
    "unit;tunnels;udplistener;mux;shutdown;ordering"
  )
endif()

# Owned-line Finish postcondition. One executable per tunnel, for the same reason
# as every other block here, and one tunnel per ownership shape: an endpoint owner
# that registers its lines in a lookup table, and an internal owner that owns its
# children while borrowing their parent.
if(TARGET UdpStatelessSocket)
  waterwall_add_native_executable(owned_line_finish_udpstatelesssocket_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/udp/owned_line_finish_udpstatelesssocket_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(owned_line_finish_udpstatelesssocket_test UdpStatelessSocket)
  target_link_options(owned_line_finish_udpstatelesssocket_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  if(LINUX)
    target_link_options(owned_line_finish_udpstatelesssocket_test PRIVATE "-Wl,--wrap=udpSendBuffer")
  endif()
  target_link_libraries(owned_line_finish_udpstatelesssocket_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests owned_line_finish_udpstatelesssocket_test)

  add_waterwall_unit_test(
    waterwall.owned_line_finish_udpstatelesssocket_unit
    owned_line_finish_udpstatelesssocket_test
    "unit;tunnels;udpstatelesssocket;line;ownership;lifetime"
  )
endif()

if(TARGET MuxServer)
  waterwall_add_native_executable(owned_line_finish_muxserver_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/owned_line_finish_muxserver_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/src/mux_wire.c)
  waterwall_line_failure_test_use_tunnel(owned_line_finish_muxserver_test MuxServer)
  target_link_options(owned_line_finish_muxserver_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(owned_line_finish_muxserver_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests owned_line_finish_muxserver_test)

  add_waterwall_unit_test(
    waterwall.owned_line_finish_muxserver_unit
    owned_line_finish_muxserver_test
    "unit;tunnels;mux;line;ownership;lifetime"
  )
endif()

# StreamToPackets active-source ownership and per-flow return-line selection.
# Built like the line-failure tests so the buffer ledger and the worker
# environment see the tunnel's own (never-IPO) translation units.
if(TARGET StreamToPackets)
  waterwall_add_native_executable(streamtopackets_ownership_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/streamtopackets_ownership_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(streamtopackets_ownership_test StreamToPackets)
  # Eviction has to keep its "every old-source line is closed" promise even when a
  # worker message cannot be posted, which only an injected rejection can reach.
  target_link_options(streamtopackets_ownership_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
  )
  target_link_libraries(streamtopackets_ownership_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests streamtopackets_ownership_test)

  add_waterwall_unit_test(
    waterwall.streamtopackets_ownership_unit
    streamtopackets_ownership_test
    "unit;tunnels;streamtopackets;ownership;affinity;lifetime"
  )
endif()

# Cross-worker inner-flow affinity restoration in both stream/packet bridge
# decoders. One executable per tunnel: several tunnels ship a structure.h and one
# translation unit must only ever see the tunnel it is testing.
if(TARGET PacketsToStream)
  waterwall_add_native_executable(packetstostream_bridge_affinity_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/packet_bridges/packetstostream_bridge_affinity_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(packetstostream_bridge_affinity_test PacketsToStream)
  target_link_options(packetstostream_bridge_affinity_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(packetstostream_bridge_affinity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests packetstostream_bridge_affinity_test)

  add_waterwall_unit_test(
    waterwall.packetstostream_bridge_affinity_unit
    packetstostream_bridge_affinity_test
    "unit;tunnels;packetstostream;affinity"
  )
endif()

# Exercise the real SocketManager constructor/destructor on Linux as well as in
# portable native builds. The production source is compiled directly so the
# synchronization and staged-constructor seams cover the actual singleton.
