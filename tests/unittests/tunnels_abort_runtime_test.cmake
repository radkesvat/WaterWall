# Reusable registration for the tunnel hard-abort runtime cases.
#
# The tests/ subtree is only added for native Linux builds, so this file is
# included from tests/unittests/CMakeLists.txt there and directly from the
# top-level CMakeLists.txt on Windows and macOS. Every path below is absolute
# and no directory-scoped setting is assumed, so both inclusion points produce
# the same target and the same registered test.
#
# Guarded only by the targets the test really uses; Router is unrelated and must
# never gate this coverage. Each tunnel is optional or platform dependent, so
# every case is collected independently and a missing target removes its own
# case and nothing else.

include_guard(GLOBAL)

set(WATERWALL_ABORT_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}")

if(TARGET ww)
  set(tunnels_abort_runtime_sources "${WATERWALL_ABORT_RUNTIME_DIR}/tunnels_abort_runtime_test.c")
  set(tunnels_abort_runtime_libraries "")
  set(tunnels_abort_runtime_includes "")
  set(tunnels_abort_runtime_definitions "")
  set(tunnels_abort_runtime_cases
    adapter_chain_head_finish
    adapter_chain_head_payload
    adapter_chain_end_finish
    adapter_chain_end_payload
  )

  if(TARGET AuthenticationClient)
    list(APPEND tunnels_abort_runtime_libraries AuthenticationClient)
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_AUTHENTICATIONCLIENT=1)
    list(APPEND tunnels_abort_runtime_cases authenticationclient_disabled_downstream_init)
  endif()

  if(TARGET PingClient)
    list(APPEND tunnels_abort_runtime_libraries PingClient)
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_PINGCLIENT=1)
    list(APPEND tunnels_abort_runtime_cases pingclient_impossible_packet_upstream_init)
  endif()

  if(TARGET RawSocket)
    list(APPEND tunnels_abort_runtime_libraries RawSocket)
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_RAWSOCKET=1)
    list(APPEND tunnels_abort_runtime_cases rawsocket_worker_packet_line_upstream_finish)
  endif()

  if(TARGET TesterClient)
    list(APPEND tunnels_abort_runtime_libraries TesterClient)
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_TESTERCLIENT=1)
    list(APPEND tunnels_abort_runtime_cases testerclient_disabled_upstream_finish)
  endif()

  if(TARGET ReverseClient)
    list(APPEND tunnels_abort_runtime_sources
      "${WATERWALL_ABORT_RUNTIME_DIR}/tunnels_abort_reverseclient_case.c"
    )
    list(APPEND tunnels_abort_runtime_libraries ReverseClient)
    list(APPEND tunnels_abort_runtime_includes ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include)
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_REVERSECLIENT=1)
    list(APPEND tunnels_abort_runtime_cases reverseclient_live_idle_handle_linestate_destroy)
  endif()

  if(TARGET UdpStatelessSocket)
    list(APPEND tunnels_abort_runtime_sources
      "${WATERWALL_ABORT_RUNTIME_DIR}/tunnels_abort_udpstatelesssocket_case.c"
    )
    list(APPEND tunnels_abort_runtime_libraries UdpStatelessSocket)
    list(APPEND tunnels_abort_runtime_includes ${CMAKE_SOURCE_DIR}/tunnels/UdpStatelessSocket/include)
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_UDPSTATELESSSOCKET=1)
    list(APPEND tunnels_abort_runtime_cases udpstatelesssocket_active_worker_idle_table_destroy)
  endif()

  if(TARGET TcpOverUdpClient)
    list(APPEND tunnels_abort_runtime_sources
      "${WATERWALL_ABORT_RUNTIME_DIR}/tunnels_abort_tcpoverudpclient_case.c"
    )
    list(APPEND tunnels_abort_runtime_libraries TcpOverUdpClient)
    # ikcp.h and ww_fec.h are private to the tunnel target but reachable from its structure.h. Both TcpOverUdp
    # tunnels share the FEC sources and carry byte-identical copies of ikcp.h, so one pair of directories serves
    # both fixtures.
    list(APPEND tunnels_abort_runtime_includes
      ${CMAKE_SOURCE_DIR}/tunnels/TcpOverUdpClient/kcp
      ${CMAKE_SOURCE_DIR}/tunnels/TcpOverUdpClient/fec
    )
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_TCPOVERUDPCLIENT=1)
    list(APPEND tunnels_abort_runtime_cases tcpoverudpclient_impossible_kcp_mtu_rejection)
  endif()

  if(TARGET TcpOverUdpServer)
    list(APPEND tunnels_abort_runtime_sources
      "${WATERWALL_ABORT_RUNTIME_DIR}/tunnels_abort_tcpoverudpserver_case.c"
    )
    list(APPEND tunnels_abort_runtime_libraries TcpOverUdpServer)
    list(APPEND tunnels_abort_runtime_includes
      ${CMAKE_SOURCE_DIR}/tunnels/TcpOverUdpClient/kcp
      ${CMAKE_SOURCE_DIR}/tunnels/TcpOverUdpClient/fec
    )
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_TCPOVERUDPSERVER=1)
    list(APPEND tunnels_abort_runtime_cases tcpoverudpserver_impossible_kcp_mtu_rejection)
  endif()

  if(TARGET Router)
    list(APPEND tunnels_abort_runtime_sources
      "${WATERWALL_ABORT_RUNTIME_DIR}/tunnels_abort_router_case.c"
    )
    list(APPEND tunnels_abort_runtime_libraries Router)
    # tunnels/Router itself resolves the "common/..." includes Router's public headers reach for. Its inner
    # include/Router directory is deliberately left out so no bare structure.h joins the search path next to the
    # other tunnels' fixtures.
    list(APPEND tunnels_abort_runtime_includes
      ${CMAKE_SOURCE_DIR}/tunnels/Router/include
      ${CMAKE_SOURCE_DIR}/tunnels/Router
    )
    list(APPEND tunnels_abort_runtime_cases router_geoip_rule_without_open_database)
    list(APPEND tunnels_abort_runtime_definitions WATERWALL_ABORT_TEST_HAS_ROUTER=1)
  endif()
endif()

if(TARGET ww AND tunnels_abort_runtime_cases)
  add_executable(tunnels_abort_runtime_test EXCLUDE_FROM_ALL ${tunnels_abort_runtime_sources})

  # Each fixture includes a different tunnel's structure.h, whose file-local
  # naming conventions intentionally overlap. Keep the fixtures in separate
  # translation units even when the selected preset enables Unity builds.
  # State the non-IPO policy here as well so the non-Linux inclusion point gets
  # the same test build as the Linux one.
  set_target_properties(tunnels_abort_runtime_test PROPERTIES
    UNITY_BUILD OFF
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )

  target_include_directories(tunnels_abort_runtime_test PRIVATE
    "${WATERWALL_ABORT_RUNTIME_DIR}"
    ${tunnels_abort_runtime_includes}
  )
  target_compile_definitions(tunnels_abort_runtime_test PRIVATE ${tunnels_abort_runtime_definitions})
  target_link_libraries(tunnels_abort_runtime_test PRIVATE ${tunnels_abort_runtime_libraries} ww)

  # Only the Linux tests/ subtree defines the aggregate build target.
  if(TARGET waterwall_unit_tests)
    add_dependencies(waterwall_unit_tests tunnels_abort_runtime_test)
  endif()

  # The runner executes the built binary, so it is only registered where that
  # binary runs on the host. When cross-compiling, the target remains available
  # for an explicit compile check without attempting to execute the target
  # binary.
  if(NOT CMAKE_CROSSCOMPILING)
    # Pipe-separated so the case list survives add_test() argument splitting.
    string(REPLACE ";" "|" tunnels_abort_runtime_case_arg "${tunnels_abort_runtime_cases}")

    add_test(
      NAME waterwall.tunnels_abort_runtime_unit
      COMMAND
        "${CMAKE_COMMAND}"
        "-DABORT_TEST_TARGET=tunnels_abort_runtime_test"
        "-DABORT_TEST_CONFIG=$<CONFIG>"
        "-DABORT_TEST_EXECUTABLE=$<TARGET_FILE:tunnels_abort_runtime_test>"
        "-DABORT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
        "-DABORT_TEST_CASES=${tunnels_abort_runtime_case_arg}"
        -P "${WATERWALL_ABORT_RUNTIME_DIR}/run_tunnels_abort_runtime_test.cmake"
    )

    set_tests_properties(
      waterwall.tunnels_abort_runtime_unit
      PROPERTIES
        TIMEOUT 120
        LABELS "unit;tunnels;abort;runtime"
        RESOURCE_LOCK waterwall_unit_test_build
    )
  endif()
endif()

unset(tunnels_abort_runtime_sources)
unset(tunnels_abort_runtime_libraries)
unset(tunnels_abort_runtime_includes)
unset(tunnels_abort_runtime_definitions)
unset(tunnels_abort_runtime_cases)
