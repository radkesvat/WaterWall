# Explicit runtime/native target groups; included inside the ww target condition.
  waterwall_add_native_executable(system_load_semantics_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/system_load_semantics_test.c)
  target_link_libraries(system_load_semantics_test PRIVATE ww_test_support)
  target_link_libraries(system_load_semantics_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests system_load_semantics_test)

  add_waterwall_unit_test(
    waterwall.system_load_semantics_unit
    system_load_semantics_test
    "unit;system-load;failure-semantics"
  )

  waterwall_add_native_executable(aes256gcm_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/aes256gcm_test.c)
  target_link_libraries(aes256gcm_test PRIVATE ww_test_support)
  target_link_libraries(aes256gcm_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests aes256gcm_test)

  add_waterwall_unit_test(waterwall.aes256gcm_unit aes256gcm_test "unit;crypto;aes256gcm")

  waterwall_add_native_executable(crypto_primitives_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/crypto_primitives_test.c)
  target_link_libraries(crypto_primitives_test PRIVATE ww_test_support)
  target_link_libraries(crypto_primitives_test PRIVATE ww)
  target_include_directories(crypto_primitives_test PRIVATE ${CMAKE_BINARY_DIR}/ww/generated)
  add_dependencies(waterwall_unit_tests crypto_primitives_test)

  add_waterwall_unit_test(waterwall.crypto_primitives_unit crypto_primitives_test "unit;crypto")

  waterwall_add_native_executable(wlibc_memcopy_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wlibc_memcopy_test.c)
  target_link_libraries(wlibc_memcopy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wlibc_memcopy_test)

  add_waterwall_unit_test(waterwall.wlibc_memcopy_unit wlibc_memcopy_test "unit;libc;memory")

  waterwall_add_native_executable(lwip_pbuf_copy_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_pbuf_copy_test.c)
  target_link_libraries(lwip_pbuf_copy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests lwip_pbuf_copy_test)
  add_waterwall_unit_test(waterwall.lwip_pbuf_copy_unit lwip_pbuf_copy_test "unit;net;lwip;buffers")

  waterwall_add_native_executable(wendian_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wendian_test.c)
  target_link_libraries(wendian_test PRIVATE ww_test_support)
  target_link_libraries(wendian_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wendian_test)

  add_waterwall_unit_test(waterwall.wendian_unit wendian_test "unit;libc;endian")

  waterwall_add_native_executable(wtime_epoch_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wtime_epoch_test.c)
  target_link_libraries(wtime_epoch_test PRIVATE ww_test_support)
  target_link_libraries(wtime_epoch_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wtime_epoch_test)

  add_waterwall_unit_test(waterwall.wtime_epoch_unit wtime_epoch_test "unit;libc;time;epoch;overflow")

  waterwall_add_native_executable(wsocket_validation_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/wsocket_validation_test.c)
  target_link_libraries(wsocket_validation_test PRIVATE ww_test_support)
  target_link_libraries(wsocket_validation_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wsocket_validation_test)

  add_waterwall_unit_test(waterwall.wsocket_validation_unit wsocket_validation_test "unit;net;socket;validation")

  waterwall_add_native_executable(wsocket_windows_interface_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/wsocket_windows_interface_test.c)
  target_link_libraries(wsocket_windows_interface_test PRIVATE ww_test_support)
  target_link_libraries(wsocket_windows_interface_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wsocket_windows_interface_test)

  add_waterwall_unit_test(
    waterwall.wsocket_windows_interface_unit
    wsocket_windows_interface_test
    "unit;net;socket;windows;interface"
  )

  waterwall_add_native_executable(socket_narrowing_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/socket_narrowing_test.c)
  target_link_libraries(socket_narrowing_test PRIVATE ww_test_support)
  target_link_libraries(socket_narrowing_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socket_narrowing_test)

  add_waterwall_unit_test(
    waterwall.socket_narrowing_unit
    socket_narrowing_test
    "unit;net;socket;narrowing;bounds"
  )

  waterwall_add_native_executable(json_helpers_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/json_helpers_test.c)
  target_link_libraries(json_helpers_test PRIVATE ww_test_support)
  target_link_libraries(json_helpers_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests json_helpers_test)

  add_waterwall_unit_test(waterwall.json_helpers_unit json_helpers_test "unit;utils;json")

  waterwall_add_native_executable(wlibc_helpers_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wlibc_helpers_test.c)
  target_link_libraries(wlibc_helpers_test PRIVATE ww_test_support)
  target_link_libraries(wlibc_helpers_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wlibc_helpers_test)
  add_waterwall_unit_test(waterwall.wlibc_helpers_unit wlibc_helpers_test "unit;libc;helpers")

  waterwall_add_native_executable(base64_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/base64_test.c)
  target_link_libraries(base64_test PRIVATE ww ww_test_support)
  add_dependencies(waterwall_unit_tests base64_test)
  add_waterwall_unit_test(waterwall.base64_unit base64_test "unit;utils;base64")

  if(TARGET HttpServer)
    waterwall_add_native_executable(httpserver_base64_compat_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpserver_base64_compat_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/HttpServer/common/http_base64.c)
    target_include_directories(httpserver_base64_compat_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/HttpServer/include
      ${CMAKE_SOURCE_DIR}/tunnels/HttpServer/include/HttpServer
    )
    target_link_libraries(httpserver_base64_compat_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests httpserver_base64_compat_test)
    add_waterwall_unit_test(
      waterwall.httpserver_base64_compat_unit
      httpserver_base64_compat_test
      "unit;tunnels;httpserver;base64;compatibility"
    )

    waterwall_add_native_executable(httpserver_authority_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/httpserver_authority_test.c)
    target_link_libraries(httpserver_authority_test PRIVATE HttpServer ww)
    add_dependencies(waterwall_unit_tests httpserver_authority_test)
    add_waterwall_unit_test(
      waterwall.httpserver_authority_unit
      httpserver_authority_test
      "unit;tunnels;httpserver;authority;ipv6"
    )
  endif()

  if(TARGET MuxCommon)
    waterwall_add_native_executable(muxcommon_wire_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxcommon_wire_test.c)
    target_link_libraries(muxcommon_wire_test PRIVATE MuxCommon ww)
    add_dependencies(waterwall_unit_tests muxcommon_wire_test)
    add_waterwall_unit_test(waterwall.muxcommon_wire_unit muxcommon_wire_test "unit;mux;wire")
  endif()

  if(TARGET PingCommon)
    waterwall_add_native_executable(ping_wire_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ping/ping_wire_test.c)
    target_link_libraries(ping_wire_test PRIVATE PingCommon ww)
    add_dependencies(waterwall_unit_tests ping_wire_test)
    add_waterwall_unit_test(waterwall.ping_wire_unit ping_wire_test "unit;ping;wire")

    waterwall_add_native_executable(ping_tracker_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ping/ping_tracker_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/Internals/PingCommon/src/ping_wire.c)
    target_compile_definitions(ping_tracker_test PRIVATE WW_SYNC_INIT_TEST_SEAM=1)
    target_include_directories(
      ping_tracker_test
      PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/Internals/PingCommon/include
    )
    target_link_libraries(ping_tracker_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests ping_tracker_test)
    add_waterwall_unit_test(
      waterwall.ping_tracker_unit
      ping_tracker_test
      "unit;ping;tracker;synchronization;failure;tsan"
    )

    if(TARGET PingClient AND TARGET PingServer)
      waterwall_add_native_executable(ping_flow_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ping/ping_flow_test.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_budget.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_queue.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_stream.c)
      target_link_options(
        ping_flow_test
        PRIVATE
          "-Wl,--wrap=abortProgramNow"
          "-Wl,--wrap=requestProgramShutdown"
          "-Wl,--wrap=bufferpoolGetLargeBuffer"
          "-Wl,--wrap=bufferpoolTryGetBestFit"
          "-Wl,--wrap=bufferpoolGetBestFit"
          "-Wl,--wrap=bufferpoolGetSpliceBuffer"
          "-Wl,--wrap=bufferpoolGetMediumBuffer"
          "-Wl,--wrap=bufferpoolGetSmallBuffer"
          "-Wl,--wrap=bufferpoolReuseBuffer"
          "-Wl,--wrap=sbufDestroy"
      )
      target_link_libraries(ping_flow_test PRIVATE PingClient PingServer PingCommon ww)
      add_dependencies(waterwall_unit_tests ping_flow_test)
      add_waterwall_unit_test(
        waterwall.ping_flow_unit
        ping_flow_test
        "unit;ping;flow;packet;direction;affinity;lifetime"
      )
    endif()
  endif()

  waterwall_add_native_executable(wfrand_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wfrand_test.c)
  target_link_libraries(wfrand_test PRIVATE ww_test_support)
  target_link_libraries(wfrand_test PRIVATE ww)
  if(LINUX)
    target_link_options(wfrand_test PRIVATE "-Wl,--wrap=open")
  endif()
  add_dependencies(waterwall_unit_tests wfrand_test)

  add_waterwall_unit_test(waterwall.wfrand_unit wfrand_test "unit;libc;random")

  waterwall_add_native_executable(wpercentgate_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wpercentgate_test.c)
  target_link_libraries(wpercentgate_test PRIVATE ww_test_support)
  target_link_libraries(wpercentgate_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wpercentgate_test)

  add_waterwall_unit_test(
    waterwall.percent_gate_unit
    wpercentgate_test
    "unit;libc;percentage-gate;noncrypto"
  )

  waterwall_add_native_executable(line_user_identifier_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/line_user_identifier_test.c)
  target_link_libraries(line_user_identifier_test PRIVATE ww_test_support)
  target_link_libraries(line_user_identifier_test PRIVATE ww)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(line_user_identifier_test PRIVATE WW_LINE_IDENTITY_FAILURE_TEST=1)
    target_link_options(line_user_identifier_test PRIVATE "-Wl,--wrap=stringDuplicate")
  endif()
  add_dependencies(waterwall_unit_tests line_user_identifier_test)

  add_waterwall_unit_test(waterwall.line_user_identifier_unit line_user_identifier_test "unit;net;line")

  waterwall_add_native_executable(line_state_index_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/line_state_index_test.c)
  target_link_libraries(line_state_index_test PRIVATE ww_test_support)
  target_link_libraries(line_state_index_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests line_state_index_test)

  add_waterwall_unit_test(waterwall.line_state_index_unit line_state_index_test "unit;net;line;chain")

  waterwall_add_native_executable(chain_node_limit_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/chain_node_limit_test.c)
  target_link_libraries(chain_node_limit_test PRIVATE ww_test_support)
  target_link_libraries(chain_node_limit_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests chain_node_limit_test)
  add_waterwall_unit_test(waterwall.chain_node_limit_unit chain_node_limit_test "unit;net;chain;configuration")

  waterwall_add_native_executable(chain_mux_presence_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/chain_mux_presence_test.c)
  target_link_libraries(chain_mux_presence_test PRIVATE ww_test_support)
  target_link_libraries(chain_mux_presence_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests chain_mux_presence_test)
  add_waterwall_unit_test(waterwall.chain_mux_presence_unit chain_mux_presence_test "unit;net;chain;mux")

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET TcpListener)
    waterwall_add_native_executable(tcplistener_mux_buffers_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tcp/tcplistener_mux_buffers_test.c)
    target_link_libraries(tcplistener_mux_buffers_test PRIVATE TcpListener ww)
    target_link_options(tcplistener_mux_buffers_test PRIVATE "-Wl,--wrap=socketacceptorUpdateBufferOptions")
    add_dependencies(waterwall_unit_tests tcplistener_mux_buffers_test)
    add_waterwall_unit_test(waterwall.tcplistener_mux_buffers_unit tcplistener_mux_buffers_test "unit;net;tcp;mux")
  endif()

  if(TARGET TcpConnector)
    waterwall_add_native_executable(tcpconnector_mux_buffers_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tcp/tcpconnector_mux_buffers_test.c)
    target_link_libraries(tcpconnector_mux_buffers_test PRIVATE TcpConnector ww)
    add_dependencies(waterwall_unit_tests tcpconnector_mux_buffers_test)
    add_waterwall_unit_test(waterwall.tcpconnector_mux_buffers_unit tcpconnector_mux_buffers_test "unit;net;tcp;mux")
  endif()

  if(TARGET DomainResolver)
    waterwall_add_native_executable(domainresolver_line_layout_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/domainresolver/domainresolver_line_layout_test.c)
    target_link_libraries(domainresolver_line_layout_test PRIVATE DomainResolver ww)
    add_dependencies(waterwall_unit_tests domainresolver_line_layout_test)
    add_waterwall_unit_test(waterwall.domainresolver_line_layout_unit domainresolver_line_layout_test
      "unit;net;line;chain;domainresolver")
  endif()

