if(NOT WW_BUILD_UNIT_TESTS)
  message(FATAL_ERROR "tests/unittests requires WW_BUILD_UNIT_TESTS=ON")
endif()

include_directories(
  ${CMAKE_SOURCE_DIR}/ww
  ${CMAKE_SOURCE_DIR}/ww/base
  ${CMAKE_SOURCE_DIR}/ww/base/internal_types
  ${CMAKE_SOURCE_DIR}/ww/node_builder
  ${CMAKE_SOURCE_DIR}/ww/bufio
  ${CMAKE_SOURCE_DIR}/ww/event
  ${CMAKE_SOURCE_DIR}/ww/net
  ${CMAKE_SOURCE_DIR}/ww/instance
  ${CMAKE_SOURCE_DIR}/ww/libc
  ${CMAKE_SOURCE_DIR}/ww/crypto
  ${CMAKE_SOURCE_DIR}/ww/lwip
  ${CMAKE_SOURCE_DIR}/ww/lwip/contrib/ports/unix/port/include
  ${CMAKE_SOURCE_DIR}/ww/vendor/asmlib
  ${CMAKE_SOURCE_DIR}/ww/vendor/cjson
  ${CMAKE_BINARY_DIR}/ww
  ${CMAKE_BINARY_DIR}/ww/generated
  ${CMAKE_BINARY_DIR}/patched-deps/lwip/src/include
  ${CMAKE_BINARY_DIR}/patched-deps/lwip/contrib
  ${CMAKE_BINARY_DIR}/_deps/cares-build
  ${cares_SOURCE_DIR}
  ${cares_SOURCE_DIR}/include
  ${komihash_SOURCE_DIR}
  ${stc_SOURCE_DIR}/include
)

if(NOT APPLE)
  add_compile_definitions(LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS=1)
endif()

add_custom_target(waterwall_unit_tests)

set(WATERWALL_UNIT_TEST_RUNNER "${CMAKE_CURRENT_SOURCE_DIR}/run_unit_test.cmake")

function(add_waterwall_unit_test test_name target_name labels)
  add_test(
    NAME ${test_name}
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=${target_name}"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:${target_name}>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${WATERWALL_UNIT_TEST_RUNNER}"
  )

  set_tests_properties(
    ${test_name}
    PROPERTIES
      TIMEOUT 120
      LABELS "${labels}"
      RESOURCE_LOCK waterwall_unit_test_build
  )
endfunction()

if(TARGET ww)
  add_executable(capture_windows_lifetime_test capture_windows_lifetime_test.c)
  target_include_directories(capture_windows_lifetime_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/capture)
  add_dependencies(waterwall_unit_tests capture_windows_lifetime_test)

  add_waterwall_unit_test(
    waterwall.capture_windows_lifetime_unit
    capture_windows_lifetime_test
    "unit;net;capture;windows;lifetime"
  )

  add_executable(capture_lifecycle_test capture_lifecycle_test.c)
  target_include_directories(capture_lifecycle_test PRIVATE ${CMAKE_SOURCE_DIR}/ww)
  target_link_libraries(capture_lifecycle_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests capture_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.capture_lifecycle_unit
    capture_lifecycle_test
    "unit;net;capture;lifecycle"
  )

  add_executable(tun_windows_lifetime_test tun_windows_lifetime_test.c)
  target_include_directories(tun_windows_lifetime_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/tun)
  target_link_libraries(tun_windows_lifetime_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tun_windows_lifetime_test)

  add_waterwall_unit_test(
    waterwall.tun_windows_lifetime_unit
    tun_windows_lifetime_test
    "unit;net;tun;windows;lifetime"
  )

  add_executable(tun_lifecycle_test tun_lifecycle_test.c)
  target_include_directories(tun_lifecycle_test PRIVATE ${CMAKE_SOURCE_DIR}/ww)
  target_link_libraries(tun_lifecycle_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tun_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.tun_lifecycle_unit
    tun_lifecycle_test
    "unit;net;tun;lifecycle"
  )

  add_executable(quiescence_gate_test quiescence_gate_test.c)
  target_include_directories(quiescence_gate_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/base ${CMAKE_SOURCE_DIR}/ww/devices)
  target_compile_definitions(quiescence_gate_test PRIVATE QUIESCENCE_GATE_TEST_HOOKS=1)
  target_link_libraries(quiescence_gate_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests quiescence_gate_test)

  add_waterwall_unit_test(
    waterwall.quiescence_gate_unit
    quiescence_gate_test
    "unit;base;quiescence;gate;lifetime"
  )

  add_executable(device_flow_affinity_test device_flow_affinity_test.c)
  target_link_libraries(device_flow_affinity_test PRIVATE ww)
  if(LINUX)
    target_compile_definitions(device_flow_affinity_test PRIVATE DEVICE_FLOW_AFFINITY_TEST_TRACKING=1)
    target_link_options(device_flow_affinity_test PRIVATE
      "-Wl,--wrap=bufferpoolReuseBuffer"
      "-Wl,--wrap=deviceFragAffinitySettlePublication"
      "-Wl,--wrap=deviceFragAffinityOffer"
    )
  endif()
  if(TARGET WireGuardDevice)
    target_compile_definitions(device_flow_affinity_test PRIVATE DEVICE_FLOW_AFFINITY_TEST_WIREGUARD=1)
    target_include_directories(device_flow_affinity_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice
    )
    target_link_libraries(device_flow_affinity_test PRIVATE WireGuardDevice)
  endif()
  add_dependencies(waterwall_unit_tests device_flow_affinity_test)

  add_waterwall_unit_test(
    waterwall.device_flow_affinity_unit
    device_flow_affinity_test
    "unit;net;device;affinity"
  )

  if(LINUX)
    add_executable(buffer_pool_thread_transfer_test buffer_pool_thread_transfer_test.c)
    target_link_libraries(buffer_pool_thread_transfer_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests buffer_pool_thread_transfer_test)

    add_waterwall_unit_test(
      waterwall.buffer_pool_thread_transfer_unit
      buffer_pool_thread_transfer_test
      "unit;bufio;lifetime;thread"
    )

    add_executable(lwip_shutdown_test lwip_shutdown_test.c)
    target_link_libraries(lwip_shutdown_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests lwip_shutdown_test)

    add_waterwall_unit_test(
      waterwall.lwip_shutdown_unit
      lwip_shutdown_test
      "unit;net;lwip;lifetime;shutdown"
    )

    add_executable(device_reader_session_test
      device_reader_session_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_session.c
    )
    target_link_options(device_reader_session_test PRIVATE
      "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
      "-Wl,--wrap=memoryFree"
      "-Wl,--wrap=masterpoolDestroy"
      "-Wl,--wrap=bufferpoolReuseBuffer"
      "-Wl,--wrap=deviceFragAffinitySettlePublication"
    )
    target_compile_definitions(device_reader_session_test PRIVATE DEVICE_READER_SESSION_TEST_HOOKS=1)
    target_link_libraries(device_reader_session_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests device_reader_session_test)

    add_waterwall_unit_test(
      waterwall.device_reader_session_unit
      device_reader_session_test
      "unit;net;device;lifetime;reader"
    )

    add_executable(device_writer_channel_test
      device_writer_channel_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_writer_channel.c
    )
    target_compile_definitions(device_writer_channel_test PRIVATE DEVICE_WRITER_CHANNEL_TEST_HOOKS=1)
    target_link_libraries(device_writer_channel_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests device_writer_channel_test)

    add_waterwall_unit_test(
      waterwall.device_writer_channel_unit
      device_writer_channel_test
      "unit;net;device;lifetime;writer"
    )
  endif()

  add_executable(wchan_close_semantics_test
    wchan_close_semantics_test.c
    ${CMAKE_SOURCE_DIR}/ww/base/wchan.c
  )
  target_compile_definitions(wchan_close_semantics_test PRIVATE WCHAN_TEST_HOOKS=1)
  target_link_libraries(wchan_close_semantics_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wchan_close_semantics_test)

  add_waterwall_unit_test(
    waterwall.wchan_close_semantics_unit
    wchan_close_semantics_test
    "unit;base;chan;lifetime;close"
  )

  add_executable(tun_windows_receive_policy_test tun_windows_receive_policy_test.c)
  target_include_directories(tun_windows_receive_policy_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/tun)
  target_link_libraries(tun_windows_receive_policy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tun_windows_receive_policy_test)

  add_waterwall_unit_test(
    waterwall.tun_windows_receive_policy_unit
    tun_windows_receive_policy_test
    "unit;net;tun;windows;receive;drop"
  )

  add_executable(log_rate_limiter_test log_rate_limiter_test.c)
  target_link_libraries(log_rate_limiter_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests log_rate_limiter_test)

  add_waterwall_unit_test(
    waterwall.log_rate_limiter_unit
    log_rate_limiter_test
    "unit;logger;rate-limit"
  )

  add_executable(raw_windows_send_policy_test raw_windows_send_policy_test.c)
  target_include_directories(raw_windows_send_policy_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/raw)
  target_link_libraries(raw_windows_send_policy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests raw_windows_send_policy_test)

  add_waterwall_unit_test(
    waterwall.raw_windows_send_policy_unit
    raw_windows_send_policy_test
    "unit;net;raw;windows;send;failure"
  )

  add_executable(sbuf_capacity_test sbuf_capacity_test.c)
  target_link_libraries(sbuf_capacity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests sbuf_capacity_test)

  add_waterwall_unit_test(
    waterwall.sbuf_capacity_unit
    sbuf_capacity_test
    "unit;bufio;sbuf;bufferpool;capacity;overflow"
  )

  add_executable(bufio_contract_test bufio_contract_test.c)
  target_link_libraries(bufio_contract_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests bufio_contract_test)

  add_waterwall_unit_test(
    waterwall.bufio_contract_unit
    bufio_contract_test
    "unit;bufio;sbuf;buffer-stream;invariant"
  )

  add_executable(system_load_semantics_test system_load_semantics_test.c)
  target_link_libraries(system_load_semantics_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests system_load_semantics_test)

  add_waterwall_unit_test(
    waterwall.system_load_semantics_unit
    system_load_semantics_test
    "unit;system-load;failure-semantics"
  )

  add_executable(aes256gcm_test aes256gcm_test.c)
  target_link_libraries(aes256gcm_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests aes256gcm_test)

  add_waterwall_unit_test(waterwall.aes256gcm_unit aes256gcm_test "unit;crypto;aes256gcm")

  add_executable(crypto_primitives_test crypto_primitives_test.c)
  target_link_libraries(crypto_primitives_test PRIVATE ww)
  target_include_directories(crypto_primitives_test PRIVATE ${CMAKE_BINARY_DIR}/ww/generated)
  add_dependencies(waterwall_unit_tests crypto_primitives_test)

  add_waterwall_unit_test(waterwall.crypto_primitives_unit crypto_primitives_test "unit;crypto")

  add_executable(wlibc_memcopy_test wlibc_memcopy_test.c)
  target_link_libraries(wlibc_memcopy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wlibc_memcopy_test)

  add_waterwall_unit_test(waterwall.wlibc_memcopy_unit wlibc_memcopy_test "unit;libc;memory")

  add_executable(wendian_test wendian_test.c)
  target_link_libraries(wendian_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wendian_test)

  add_waterwall_unit_test(waterwall.wendian_unit wendian_test "unit;libc;endian")

  add_executable(wtime_epoch_test wtime_epoch_test.c)
  target_link_libraries(wtime_epoch_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wtime_epoch_test)

  add_waterwall_unit_test(waterwall.wtime_epoch_unit wtime_epoch_test "unit;libc;time;epoch;overflow")

  add_executable(wsocket_validation_test wsocket_validation_test.c)
  target_link_libraries(wsocket_validation_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wsocket_validation_test)

  add_waterwall_unit_test(waterwall.wsocket_validation_unit wsocket_validation_test "unit;net;socket;validation")

  add_executable(wsocket_windows_interface_test wsocket_windows_interface_test.c)
  target_link_libraries(wsocket_windows_interface_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wsocket_windows_interface_test)

  add_waterwall_unit_test(
    waterwall.wsocket_windows_interface_unit
    wsocket_windows_interface_test
    "unit;net;socket;windows;interface"
  )

  add_executable(socket_narrowing_test socket_narrowing_test.c)
  target_link_libraries(socket_narrowing_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socket_narrowing_test)

  add_waterwall_unit_test(
    waterwall.socket_narrowing_unit
    socket_narrowing_test
    "unit;net;socket;narrowing;bounds"
  )

  add_executable(json_helpers_test json_helpers_test.c)
  target_link_libraries(json_helpers_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests json_helpers_test)

  add_waterwall_unit_test(waterwall.json_helpers_unit json_helpers_test "unit;utils;json")

  add_executable(wlibc_helpers_test wlibc_helpers_test.c)
  target_link_libraries(wlibc_helpers_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wlibc_helpers_test)
  add_waterwall_unit_test(waterwall.wlibc_helpers_unit wlibc_helpers_test "unit;libc;helpers")

  add_executable(base64_test base64_test.c)
  target_link_libraries(base64_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests base64_test)
  add_waterwall_unit_test(waterwall.base64_unit base64_test "unit;utils;base64")

  if(TARGET HttpServer)
    add_executable(httpserver_base64_compat_test
      httpserver_base64_compat_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/HttpServer/common/http_base64.c
    )
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

    add_executable(httpserver_authority_test httpserver_authority_test.c)
    target_link_libraries(httpserver_authority_test PRIVATE HttpServer ww)
    add_dependencies(waterwall_unit_tests httpserver_authority_test)
    add_waterwall_unit_test(
      waterwall.httpserver_authority_unit
      httpserver_authority_test
      "unit;tunnels;httpserver;authority;ipv6"
    )
  endif()

  if(TARGET MuxCommon)
    add_executable(muxcommon_wire_test muxcommon_wire_test.c)
    target_link_libraries(muxcommon_wire_test PRIVATE MuxCommon ww)
    add_dependencies(waterwall_unit_tests muxcommon_wire_test)
    add_waterwall_unit_test(waterwall.muxcommon_wire_unit muxcommon_wire_test "unit;mux;wire")
  endif()

  if(TARGET PingCommon)
    add_executable(ping_wire_test ping_wire_test.c)
    target_link_libraries(ping_wire_test PRIVATE PingCommon ww)
    add_dependencies(waterwall_unit_tests ping_wire_test)
    add_waterwall_unit_test(waterwall.ping_wire_unit ping_wire_test "unit;ping;wire")

    add_executable(
      ping_tracker_test
      ping_tracker_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/Internals/PingCommon/src/ping_wire.c
    )
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
      add_executable(
        ping_flow_test
        ping_flow_test.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_queue.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_stream.c
      )
      target_link_options(
        ping_flow_test
        PRIVATE
          "-Wl,--wrap=abortProgramNow"
          "-Wl,--wrap=requestProgramShutdown"
          "-Wl,--wrap=bufferpoolGetLargeBuffer"
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

  add_executable(wfrand_test wfrand_test.c)
  target_link_libraries(wfrand_test PRIVATE ww)
  if(LINUX)
    target_link_options(wfrand_test PRIVATE "-Wl,--wrap=open")
  endif()
  add_dependencies(waterwall_unit_tests wfrand_test)

  add_waterwall_unit_test(waterwall.wfrand_unit wfrand_test "unit;libc;random")

  add_executable(line_user_identifier_test line_user_identifier_test.c)
  target_link_libraries(line_user_identifier_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests line_user_identifier_test)

  add_waterwall_unit_test(waterwall.line_user_identifier_unit line_user_identifier_test "unit;net;line")

  add_executable(line_state_index_test line_state_index_test.c)
  target_link_libraries(line_state_index_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests line_state_index_test)

  add_waterwall_unit_test(waterwall.line_state_index_unit line_state_index_test "unit;net;line;chain")

  add_executable(address_context_test address_context_test.c)
  target_link_libraries(address_context_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests address_context_test)

  add_waterwall_unit_test(waterwall.address_context_unit address_context_test "unit;net;address-context")

  add_executable(wchecksum_test wchecksum_test.c)
  # ww_lwip calls the platform assert hook defined by ww. Repeat ww after the
  # lwIP archive so a one-pass static linker can resolve that reverse edge.
  target_link_libraries(wchecksum_test PRIVATE ww ww_lwip ww)
  add_dependencies(waterwall_unit_tests wchecksum_test)

  add_waterwall_unit_test(waterwall.wchecksum_unit wchecksum_test "unit;net;checksum")

  add_executable(ipv4_packet_view_test ipv4_packet_view_test.c)
  target_link_libraries(ipv4_packet_view_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipv4_packet_view_test)

  add_waterwall_unit_test(waterwall.ipv4_packet_view_unit ipv4_packet_view_test "unit;net;packet-view")

  add_executable(tls_client_hello_test tls_client_hello_test.c)
  target_link_libraries(tls_client_hello_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tls_client_hello_test)

  add_waterwall_unit_test(waterwall.tls_client_hello_unit tls_client_hello_test "unit;net;tls")

  add_executable(buffer_pool_best_fit_test buffer_pool_best_fit_test.c)
  target_link_libraries(buffer_pool_best_fit_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests buffer_pool_best_fit_test)

  add_waterwall_unit_test(waterwall.buffer_pool_best_fit_unit buffer_pool_best_fit_test "unit;bufio;buffer-pool")

  add_executable(packet_tunnel_test packet_tunnel_test.c)
  target_link_libraries(packet_tunnel_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests packet_tunnel_test)

  add_waterwall_unit_test(waterwall.packet_tunnel_unit packet_tunnel_test "unit;net;packet-tunnel")
  add_library(missing_abi_node_library SHARED legacy_node_library.c)
  target_compile_definitions(missing_abi_node_library PRIVATE FIXTURE_NODE_TYPE="MissingAbiFixture")
  set_target_properties(missing_abi_node_library PROPERTIES PREFIX "")
  add_library(mismatched_abi_node_library SHARED legacy_node_library.c)
  target_compile_definitions(
    mismatched_abi_node_library
    PRIVATE FIXTURE_NODE_TYPE="MismatchedAbiFixture" FIXTURE_ABI_VERSION=1
  )
  set_target_properties(mismatched_abi_node_library PROPERTIES PREFIX "")
  add_library(lifecycle_v2_node_library SHARED lifecycle_v2_node_library.c)
  set_target_properties(lifecycle_v2_node_library PROPERTIES PREFIX "")
  add_executable(legacy_node_compatibility_test legacy_node_compatibility_test.c)
  target_compile_definitions(
    legacy_node_compatibility_test
    PRIVATE
      MISSING_NODE_LIBRARY_PATH="$<TARGET_FILE:missing_abi_node_library>"
      MISMATCHED_NODE_LIBRARY_PATH="$<TARGET_FILE:mismatched_abi_node_library>"
      LIFECYCLE_V2_NODE_LIBRARY_PATH="$<TARGET_FILE:lifecycle_v2_node_library>"
  )
  target_link_libraries(legacy_node_compatibility_test PRIVATE ww)
  add_dependencies(
    legacy_node_compatibility_test
    missing_abi_node_library
    mismatched_abi_node_library
    lifecycle_v2_node_library
  )
  add_dependencies(waterwall_unit_tests legacy_node_compatibility_test)
  add_waterwall_unit_test(
    waterwall.lifecycle_node_abi_v2_unit
    legacy_node_compatibility_test
    "unit;net;tunnels;node-manager;abi;lifecycle-v2;portable"
  )

  add_executable(users_runtime_migration_test
    users_runtime_migration_test.c
    ${CMAKE_SOURCE_DIR}/ww/objects/user.c
  )
  target_link_libraries(users_runtime_migration_test PRIVATE ww)
  if(LINUX)
    target_compile_definitions(users_runtime_migration_test PRIVATE WCRYPTO_TEST_LINKER_WRAP=1)
    target_link_options(users_runtime_migration_test PRIVATE
      "-Wl,-u,wCryptoSHA224"
      "-Wl,-u,wCryptoSHA256"
      "-Wl,-u,wCryptoX25519"
      "-Wl,--wrap=wCryptoSHA224"
      "-Wl,--wrap=wCryptoSHA256"
      "-Wl,--wrap=wCryptoX25519"
    )
  endif()
  add_dependencies(waterwall_unit_tests users_runtime_migration_test)

  add_waterwall_unit_test(waterwall.users_runtime_migration_unit users_runtime_migration_test "unit;objects;users")

  # Focused lookup-index correctness/instrumentation test. user.c and users.c are
  # compiled directly into the executable so the test-only password-lookup visit
  # counter (proving the fallback scan is gone) is available; the archive copies
  # in libww are left untouched by this compile definition.
  add_executable(users_index_test
    users_index_test.c
    ${CMAKE_SOURCE_DIR}/ww/objects/user.c
    ${CMAKE_SOURCE_DIR}/ww/objects/users.c
  )
  target_link_libraries(users_index_test PRIVATE ww)
  target_compile_definitions(users_index_test PRIVATE USERS_TEST_PASSWORD_LOOKUP_VISIT_COUNTER=1)
  # Test-only counter proving every post-snapshot exit of the password change
  # wipes the old credential snapshot; the counter is compiled into the directly
  # built users.c copy and left out of the libww archive copies.
  target_compile_definitions(users_index_test PRIVATE USERS_TEST_CREDENTIAL_SNAPSHOT_WIPE_COUNTER=1)
  if(LINUX)
    target_compile_definitions(users_index_test PRIVATE WCRYPTO_TEST_LINKER_WRAP=1)
    # Deterministic allocation-fault injection so the transactional password-change,
    # removal, add, and Allowed-IP-update paths can be swept for failure atomicity.
    target_compile_definitions(users_index_test PRIVATE USERS_TEST_ALLOC_INJECTION=1)
    target_link_options(users_index_test PRIVATE
      "-Wl,-u,wCryptoSHA224"
      "-Wl,-u,wCryptoSHA256"
      "-Wl,-u,wCryptoX25519"
      "-Wl,-u,stringDuplicate"
      "-Wl,--wrap=wCryptoSHA224"
      "-Wl,--wrap=wCryptoSHA256"
      "-Wl,--wrap=wCryptoX25519"
      "-Wl,--wrap=stringDuplicate"
      "-Wl,--wrap=memoryAllocate"
      "-Wl,--wrap=memoryReAllocate"
      "-Wl,--wrap=memoryCalloc"
    )
  endif()
  add_dependencies(waterwall_unit_tests users_index_test)

  add_waterwall_unit_test(waterwall.users_index_unit users_index_test "unit;objects;users")

  add_executable(socket_manager_rules_test socket_manager_rules_test.c)
  target_link_libraries(socket_manager_rules_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socket_manager_rules_test)

  add_waterwall_unit_test(waterwall.socket_manager_rules_unit socket_manager_rules_test "unit;net;socket-manager")

  add_executable(socket_manager_iptables_recovery_test socket_manager_iptables_recovery_test.c)
  target_link_libraries(socket_manager_iptables_recovery_test PRIVATE ww)
  if(LINUX)
    target_sources(socket_manager_iptables_recovery_test PRIVATE
      ${CMAKE_SOURCE_DIR}/ww/managers/socket_manager_iptables_recovery.c
    )
    target_compile_definitions(socket_manager_iptables_recovery_test PRIVATE
      SOCKET_MANAGER_IPTABLES_ALLOC_FAILURE_TEST=1
    )
    # Only the planner's reallocation and the lease cleanup close() are injected
    # here. The command supervisor's own allocation failure moved to
    # wproc_deadline_test.c along with the supervisor itself.
    target_link_options(socket_manager_iptables_recovery_test PRIVATE
      "-Wl,--wrap=memoryReAllocate"
      "-Wl,--wrap=close"
    )
  endif()
  add_dependencies(waterwall_unit_tests socket_manager_iptables_recovery_test)

  add_waterwall_unit_test(
    waterwall.socket_manager_iptables_recovery_unit
    socket_manager_iptables_recovery_test
    "unit;net;socket-manager;iptables"
  )

  add_executable(udp_zero_length_test udp_zero_length_test.c)
  target_link_libraries(udp_zero_length_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests udp_zero_length_test)

  add_waterwall_unit_test(waterwall.udp_zero_length_unit udp_zero_length_test "unit;event;udp")

  if(LINUX)
    add_executable(wlibc_write_file_test wlibc_write_file_test.c)
    target_link_libraries(wlibc_write_file_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests wlibc_write_file_test)

    add_waterwall_unit_test(waterwall.wlibc_write_file_unit wlibc_write_file_test "unit;libc;file")

    add_executable(capture_linux_nfqueue_test capture_linux_nfqueue_test.c)
    target_link_libraries(capture_linux_nfqueue_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests capture_linux_nfqueue_test)

    add_waterwall_unit_test(
      waterwall.capture_linux_nfqueue_unit
      capture_linux_nfqueue_test
      "unit;net;capture;nfqueue"
    )

    # Generic deadline-aware command supervisor. wproc.c is compiled directly so
    # the linker wrap still intercepts the capture-buffer allocation it performs.
    add_executable(wproc_deadline_test
      wproc_deadline_test.c
      ${CMAKE_SOURCE_DIR}/ww/base/wproc.c
    )
    target_link_options(wproc_deadline_test PRIVATE "-Wl,--wrap=memoryAllocate")
    target_link_libraries(wproc_deadline_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests wproc_deadline_test)

    add_waterwall_unit_test(
      waterwall.wproc_deadline_unit
      wproc_deadline_test
      "unit;base;process;deadline"
    )

    # Capture command wiring. capture_linux.c is compiled directly so the wrap of
    # the generic runner intercepts Capture's own calls without opening a real
    # NFQUEUE socket or requiring root.
    add_executable(capture_linux_command_test
      capture_linux_command_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux.c
    )
    target_link_options(capture_linux_command_test PRIVATE
      "-Wl,--wrap=procRunArgvWithDeadline"
      "-Wl,--wrap=procCommandResultDrop"
    )
    target_link_libraries(capture_linux_command_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests capture_linux_command_test)

    add_waterwall_unit_test(
      waterwall.capture_linux_command_unit
      capture_linux_command_test
      "unit;net;capture;process;deadline"
    )

    # Capture stop-pipe lifecycle. capture_linux.c is compiled directly and the
    # generic runner is wrapped, so BringUp/BringDown run for real while no
    # iptables rule, sysctl, NFQUEUE socket or root privilege is involved.
    add_executable(capture_linux_pipe_test
      capture_linux_pipe_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux.c
    )
    target_link_options(capture_linux_pipe_test PRIVATE
      "-Wl,--wrap=procRunArgvWithDeadline"
      "-Wl,--wrap=procCommandResultDrop"
      "-Wl,--wrap=pthread_create"
      "-Wl,--wrap=pthread_join"
      "-Wl,--wrap=recvmsg"
      "-Wl,--wrap=sendto"
      "-Wl,--wrap=requestProgramShutdown"
      "-Wl,--wrap=abortProgramNow"
    )
    target_link_libraries(capture_linux_pipe_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests capture_linux_pipe_test)

    add_waterwall_unit_test(
      waterwall.capture_linux_pipe_unit
      capture_linux_pipe_test
      "unit;net;capture;lifecycle;pipe"
    )

    # Linux TUN queued-message lifetime. tun_linux.c is compiled directly and
    # privileged syscalls/thread creation are wrapped so the real device
    # lifecycle and message paths run without root or /dev/net/tun.
    add_executable(tun_linux_message_lifetime_test
      tun_linux_message_lifetime_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_session.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_writer_channel.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux.c
    )
    target_compile_definitions(tun_linux_message_lifetime_test PRIVATE DEVICE_WRITER_CHANNEL_TEST_HOOKS=1)
    target_link_options(tun_linux_message_lifetime_test PRIVATE
      "-Wl,--wrap=open"
      "-Wl,--wrap=ioctl"
      "-Wl,--wrap=socket"
      "-Wl,--wrap=read"
      "-Wl,--wrap=write"
      "-Wl,--wrap=poll"
      "-Wl,--wrap=pthread_create"
      "-Wl,--wrap=pthread_join"
      "-Wl,--wrap=fork"
      "-Wl,--wrap=execvp"
      "-Wl,--wrap=waitpid"
      "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
      "-Wl,--wrap=memoryFree"
      "-Wl,--wrap=masterpoolDestroy"
      "-Wl,--wrap=bufferpoolReuseBuffer"
      # tun_linux.c is compiled into this test, so its process-shutdown request
      # is intercepted instead of tearing the test process down.
      "-Wl,--wrap=requestProgramShutdown"
      "-Wl,--wrap=abortProgramNow"
    )
    target_link_libraries(tun_linux_message_lifetime_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests tun_linux_message_lifetime_test)

    add_waterwall_unit_test(
      waterwall.tun_linux_message_lifetime_unit
      tun_linux_message_lifetime_test
      "unit;net;tun;linux;lifetime"
    )

    if(TARGET TunDevice)
      # Compile the small tunnel wrapper directly so the test can inject one
      # lower-layer refusal and verify it does not add a duplicate diagnostic.
      add_executable(tundevice_writer_refusal_log_test
        tundevice_writer_refusal_log_test.c
        ${CMAKE_SOURCE_DIR}/tunnels/TunDevice/common/helpers.c
      )
      target_include_directories(tundevice_writer_refusal_log_test PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/TunDevice/include
        ${CMAKE_SOURCE_DIR}/tunnels/TunDevice/include/TunDevice
      )
      target_link_options(tundevice_writer_refusal_log_test PRIVATE "-Wl,--wrap=bufferpoolReuseBuffer")
      target_link_libraries(tundevice_writer_refusal_log_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests tundevice_writer_refusal_log_test)
      add_waterwall_unit_test(
        waterwall.tundevice_writer_refusal_log_unit
        tundevice_writer_refusal_log_test
        "unit;net;tun;linux;writer;logger"
      )
    endif()

    add_executable(capture_linux_message_lifetime_test
      capture_linux_message_lifetime_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_session.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux.c
    )
    target_link_options(capture_linux_message_lifetime_test PRIVATE
      "-Wl,--wrap=procRunArgvWithDeadline"
      "-Wl,--wrap=procCommandResultDrop"
      "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
      "-Wl,--wrap=memoryFree"
      "-Wl,--wrap=masterpoolDestroy"
    )
    target_link_libraries(capture_linux_message_lifetime_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests capture_linux_message_lifetime_test)

    add_waterwall_unit_test(
      waterwall.capture_linux_message_lifetime_unit
      capture_linux_message_lifetime_test
      "unit;net;capture;linux;lifetime"
    )

    add_executable(raw_linux_writer_test
      raw_linux_writer_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_writer_channel.c
      ${CMAKE_SOURCE_DIR}/ww/devices/raw/raw_linux.c
    )
    target_compile_definitions(raw_linux_writer_test PRIVATE DEVICE_WRITER_CHANNEL_TEST_HOOKS=1)
    target_link_options(raw_linux_writer_test PRIVATE
      "-Wl,--wrap=pthread_join"
      "-Wl,--wrap=sendmmsg"
      "-Wl,--wrap=poll"
      "-Wl,--wrap=requestProgramShutdown"
      "-Wl,--wrap=abortProgramNow"
    )
    target_link_libraries(raw_linux_writer_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests raw_linux_writer_test)

    add_waterwall_unit_test(
      waterwall.raw_linux_writer_unit
      raw_linux_writer_test
      "unit;net;raw;linux;lifetime;writer"
    )

    # Wraps send/sendto for a deterministic EAGAIN/EINTR/ENOBUFS seam.
    add_executable(udp_datagram_write_test udp_datagram_write_test.c)
    target_link_libraries(udp_datagram_write_test PRIVATE ww)
    target_link_options(udp_datagram_write_test PRIVATE
      "-Wl,--wrap=sendto"
      "-Wl,--wrap=send"
    )
    add_dependencies(waterwall_unit_tests udp_datagram_write_test)

    add_waterwall_unit_test(
      waterwall.udp_datagram_write_unit
      udp_datagram_write_test
      "unit;event;udp;datagram"
    )

    add_executable(select_fd_range_test
      select_fd_range_test.c
      ${CMAKE_SOURCE_DIR}/ww/event/select.c
    )
    target_compile_definitions(select_fd_range_test PRIVATE
      EVENT_SELECT=1
      iowatcherInit=selectTestIowatcherInit
      iowatcherCleanUp=selectTestIowatcherCleanUp
      iowatcherAddEvent=selectTestIowatcherAddEvent
      iowatcherDelEvent=selectTestIowatcherDelEvent
      iowatcherPollEvents=selectTestIowatcherPollEvents
    )
    target_link_libraries(select_fd_range_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests select_fd_range_test)

    add_waterwall_unit_test(
      waterwall.select_fd_range_unit
      select_fd_range_test
      "unit;event;select;bounds"
    )

    add_executable(select_registration_failure_test
      select_registration_failure_test.c
      ${CMAKE_SOURCE_DIR}/ww/event/wloop.c
      ${CMAKE_SOURCE_DIR}/ww/event/nio.c
      ${CMAKE_SOURCE_DIR}/ww/event/select.c
    )
    target_compile_definitions(select_registration_failure_test PRIVATE EVENT_SELECT=1)
    target_link_options(select_registration_failure_test PRIVATE "-Wl,--wrap=connect" "-Wl,--wrap=eventfd")
    target_link_libraries(select_registration_failure_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests select_registration_failure_test)

    add_waterwall_unit_test(
      waterwall.select_registration_failure_unit
      select_registration_failure_test
      "unit;event;select;registration;lifetime"
    )

    add_executable(signal_manager_registration_failure_test
      signal_manager_registration_failure_test.c
      ${CMAKE_SOURCE_DIR}/ww/managers/signal_manager.c
    )
    target_link_options(signal_manager_registration_failure_test PRIVATE "-Wl,--wrap=wRead")
    target_link_libraries(signal_manager_registration_failure_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests signal_manager_registration_failure_test)

    add_waterwall_unit_test(
      waterwall.signal_manager_registration_failure_unit
      signal_manager_registration_failure_test
      "unit;signal-manager;startup;failure"
    )

    add_executable(wloop_stop_request_test wloop_stop_request_test.c)
    target_link_options(wloop_stop_request_test PRIVATE "-Wl,--wrap=send")
    target_link_libraries(wloop_stop_request_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests wloop_stop_request_test)

    add_waterwall_unit_test(
      waterwall.wloop_stop_request_unit
      wloop_stop_request_test
      "unit;event;shutdown;worker;lifetime"
    )

    foreach(wloop_wakeup_backend IN ITEMS pipe socketpair)
      set(wloop_wakeup_target "wloop_wakeup_${wloop_wakeup_backend}_test")
      add_executable(${wloop_wakeup_target}
        wloop_wakeup_coalescing_test.c
        ${CMAKE_SOURCE_DIR}/ww/event/wloop.c
        ${CMAKE_SOURCE_DIR}/ww/event/nio.c
        ${CMAKE_SOURCE_DIR}/ww/event/select.c
      )
      target_compile_definitions(${wloop_wakeup_target} PRIVATE
        EVENT_SELECT=1
        HAVE_EVENTFD=0
        WATERWALL_WLOOP_TEST_HOOKS=1
      )
      if(wloop_wakeup_backend STREQUAL "pipe")
        target_compile_definitions(${wloop_wakeup_target} PRIVATE
          HAVE_PIPE=1
          WLOOP_TEST_PIPE_BACKEND=1
        )
      else()
        target_compile_definitions(${wloop_wakeup_target} PRIVATE HAVE_PIPE=0)
      endif()
      target_link_libraries(${wloop_wakeup_target} PRIVATE ww)
      add_dependencies(waterwall_unit_tests ${wloop_wakeup_target})

      add_waterwall_unit_test(
        waterwall.wloop_wakeup_${wloop_wakeup_backend}
        ${wloop_wakeup_target}
        "unit;event;wakeup;coalescing;${wloop_wakeup_backend}"
      )
    endforeach()

    if(UNIX)
      add_executable(shutdown_manager_test shutdown_manager_test.c)
      target_compile_definitions(ww PUBLIC APPLICATION_SHUTDOWN_TEST_HOOKS=1)
      target_compile_definitions(shutdown_manager_test PRIVATE APPLICATION_SHUTDOWN_TEST_HOOKS=1)
      target_link_libraries(shutdown_manager_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests shutdown_manager_test)

      add_waterwall_unit_test(
        waterwall.shutdown_manager_unit
        shutdown_manager_test
        "unit;signal-manager;shutdown;worker;lifetime"
      )

      add_executable(shutdown_signal_test shutdown_signal_test.c)
      target_compile_definitions(ww PUBLIC SIGNAL_MANAGER_TEST_HOOKS=1)
      target_compile_definitions(shutdown_signal_test PRIVATE SIGNAL_MANAGER_TEST_HOOKS=1)
      target_link_libraries(shutdown_signal_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests shutdown_signal_test)

      add_waterwall_unit_test(
        waterwall.shutdown_signal_unit
        shutdown_signal_test
        "unit;signal-manager;shutdown;signals"
      )

      add_executable(node_manager_stop_once_test
        node_manager_stop_once_test.c
      )
      target_link_libraries(node_manager_stop_once_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests node_manager_stop_once_test)

      add_waterwall_unit_test(
        waterwall.node_manager_stop_once_unit
        node_manager_stop_once_test
        "unit;node-manager;shutdown;lifetime"
      )

      add_executable(node_manager_map_invariant_test
        node_manager_map_invariant_test.c
      )
      target_link_libraries(node_manager_map_invariant_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests node_manager_map_invariant_test)

      add_waterwall_unit_test(
        waterwall.node_manager_map_invariant_unit
        node_manager_map_invariant_test
        "unit;node-manager;configuration;capacity;lifetime"
      )

      add_executable(node_layer_validation_test
        node_layer_validation_test.c
      )
      target_link_libraries(node_layer_validation_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests node_layer_validation_test)

      add_waterwall_unit_test(
        waterwall.node_layer_validation_unit
        node_layer_validation_test
        "unit;node-manager;validation;layer;capabilities"
      )
    endif()

    add_executable(thread_creation_failure_test thread_creation_failure_test.c)
    target_link_options(thread_creation_failure_test PRIVATE "-Wl,--wrap=pthread_create")
    target_link_libraries(thread_creation_failure_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests thread_creation_failure_test)

    add_waterwall_unit_test(
      waterwall.thread_creation_failure_unit
      thread_creation_failure_test
      "unit;thread;startup;failure"
    )

    add_executable(worker_identity_test worker_identity_test.c)
    target_link_libraries(worker_identity_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests worker_identity_test)

    add_waterwall_unit_test(
      waterwall.worker_identity_unit
      worker_identity_test
      "unit;worker;identity;threads"
    )

    add_executable(worker_context_helpers_test
      worker_context_helpers_test.c
      ${CMAKE_SOURCE_DIR}/ww/instance/worker_messages.c
      ${CMAKE_SOURCE_DIR}/ww/net/pipe_tunnel.c
    )
    target_compile_definitions(worker_context_helpers_test PRIVATE
      WW_WORKER_MESSAGE_TEST_SEAM=1
      WW_PIPE_TUNNEL_TEST_SEAM=1
    )
    if(NOT MSVC)
      target_compile_definitions(worker_context_helpers_test PRIVATE WW_WORKER_MESSAGE_LINK_WRAP=1)
      target_link_options(worker_context_helpers_test PRIVATE
        "-Wl,--wrap=wloopPostEvent"
        "-Wl,--wrap=wtimerAdd"
        "-Wl,--wrap=signalmanagerRequestShutdownPreservingAcceptedStatus"
      )
    endif()
    target_link_libraries(worker_context_helpers_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests worker_context_helpers_test)

    add_waterwall_unit_test(
      waterwall.worker_context_helpers_unit
      worker_context_helpers_test
      "unit;worker;identity;messages;buffers"
    )

    if(TARGET RawSocket)
      add_executable(rawsocket_startup_failure_test
        rawsocket_startup_failure_test.c
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/instance/start.c
      )
      target_include_directories(rawsocket_startup_failure_test PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/include
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/include/RawSocket
      )
      target_link_options(rawsocket_startup_failure_test PRIVATE
        "-Wl,--wrap=caputredeviceCreate"
        "-Wl,--wrap=caputredeviceBringUp"
        "-Wl,--wrap=caputredeviceBringDown"
        "-Wl,--wrap=capturedeviceDestroy"
        "-Wl,--wrap=rawdeviceCreate"
        "-Wl,--wrap=rawdeviceBringUp"
        "-Wl,--wrap=rawdeviceBringDown"
        "-Wl,--wrap=rawdeviceDestroy"
      )
      target_link_libraries(rawsocket_startup_failure_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests rawsocket_startup_failure_test)

      add_waterwall_unit_test(
        waterwall.rawsocket_startup_failure_unit
        rawsocket_startup_failure_test
        "unit;net;rawsocket;startup;failure"
      )
    endif()

    add_executable(os_helpers_bbr_test
      os_helpers_bbr_test.c
      ${CMAKE_SOURCE_DIR}/core/os_helpers.c
    )
    target_include_directories(os_helpers_bbr_test PRIVATE ${CMAKE_SOURCE_DIR}/core)
    target_link_libraries(os_helpers_bbr_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests os_helpers_bbr_test)

    add_waterwall_unit_test(
      waterwall.os_helpers_bbr_unit
      os_helpers_bbr_test
      "unit;core;linux;bbr"
    )

    add_executable(global_crypto_startup_failure_test
      global_crypto_startup_failure_test.c
      ${CMAKE_SOURCE_DIR}/ww/instance/global_state.c
    )
    target_include_directories(global_crypto_startup_failure_test PRIVATE ${CMAKE_BINARY_DIR}/ww/generated)
    target_link_libraries(global_crypto_startup_failure_test PRIVATE ww)
    if(PROJECT_REQUIRES_OPENSSL AND WCRYPTO_BACKEND_SODIUM)
      target_sources(global_crypto_startup_failure_test PRIVATE
        ${CMAKE_SOURCE_DIR}/ww/crypto/global.c
      )
    else()
      target_link_options(global_crypto_startup_failure_test PRIVATE
        "-Wl,-u,wCryptoGlobalInit"
        "-Wl,--wrap=wCryptoGlobalInit"
      )
    endif()
    add_dependencies(waterwall_unit_tests global_crypto_startup_failure_test)

    add_waterwall_unit_test(
      waterwall.global_crypto_startup_failure_unit
      global_crypto_startup_failure_test
      "unit;core;crypto;startup;failure"
    )

    if(PROJECT_REQUIRES_OPENSSL)
      add_executable(openssl_partial_init_failure_test
        openssl_partial_init_failure_test.c
      )
      target_link_libraries(openssl_partial_init_failure_test PRIVATE ww)
      target_link_options(openssl_partial_init_failure_test PRIVATE
        "-Wl,--wrap=OPENSSL_init_ssl"
        "-Wl,--wrap=OPENSSL_cleanup"
      )
      add_dependencies(waterwall_unit_tests openssl_partial_init_failure_test)

      add_waterwall_unit_test(
        waterwall.openssl_partial_init_failure_unit
        openssl_partial_init_failure_test
        "unit;core;crypto;openssl;startup;failure"
      )
    endif()
  endif()
endif()

if(TARGET tcp_over_udp_fec)
  add_executable(tcp_over_udp_fec_test tcp_over_udp_fec_test.cc)
  target_compile_features(tcp_over_udp_fec_test PRIVATE cxx_std_17)
  target_link_libraries(tcp_over_udp_fec_test PRIVATE tcp_over_udp_fec)
  add_dependencies(waterwall_unit_tests tcp_over_udp_fec_test)

  add_waterwall_unit_test(waterwall.tcp_over_udp_fec_unit tcp_over_udp_fec_test "unit;tunnels;fec")
endif()

if(TARGET nghttp2_static)
  add_executable(nghttp2_large_recv_test nghttp2_large_recv_test.c)
  target_link_libraries(nghttp2_large_recv_test PRIVATE nghttp2_static ww)
  add_dependencies(waterwall_unit_tests nghttp2_large_recv_test)

  add_waterwall_unit_test(waterwall.nghttp2_large_recv_unit nghttp2_large_recv_test "unit;tunnels;http;nghttp2")
endif()

if(TARGET TlsServer)
  add_executable(tlsserver_alpn_test tlsserver_alpn_test.c)
  target_link_libraries(tlsserver_alpn_test PRIVATE TlsServer ww)
  add_dependencies(waterwall_unit_tests tlsserver_alpn_test)

  add_waterwall_unit_test(waterwall.tlsserver_alpn_unit tlsserver_alpn_test "unit;tunnels;tlsserver")

  add_executable(tlsserver_record_padding_test tlsserver_record_padding_test.c)
  target_compile_definitions(tlsserver_record_padding_test PRIVATE
    TLSSERVER_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSSERVER_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsserver_record_padding_test PRIVATE TlsServer TlsRecordShapingCommon ww)
  add_dependencies(waterwall_unit_tests tlsserver_record_padding_test)

  add_waterwall_unit_test(
    waterwall.tlsserver_record_padding_unit
    tlsserver_record_padding_test
    "unit;tunnels;tlsserver;tls13_record;padding;openssl"
  )

  add_executable(tlsserver_record_delay_lifecycle_test tlsserver_record_delay_lifecycle_test.c)
  target_compile_definitions(tlsserver_record_delay_lifecycle_test PRIVATE
    TLSSERVER_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSSERVER_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsserver_record_delay_lifecycle_test PRIVATE TlsServer TlsRecordShapingCommon ww)
  add_dependencies(waterwall_unit_tests tlsserver_record_delay_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.tlsserver_record_delay_lifecycle_unit
    tlsserver_record_delay_lifecycle_test
    "unit;tunnels;tlsserver;tls13_record;delay;lifecycle;reentry"
  )
endif()

if(TARGET TlsRecordShapingCommon)
  add_executable(tls13_record_shaping_test tls13_record_shaping_test.c)
  target_link_libraries(tls13_record_shaping_test PRIVATE TlsRecordShapingCommon ww)
  add_dependencies(waterwall_unit_tests tls13_record_shaping_test)

  add_waterwall_unit_test(
    waterwall.tls13_record_shaping_unit
    tls13_record_shaping_test
    "unit;tunnels;tls13_record;configuration;sampler"
  )
endif()

if(TARGET TlsClient)
  add_executable(tlsclient_record_padding_test tlsclient_record_padding_test.c)
  target_include_directories(tlsclient_record_padding_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_record_padding_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    TLSCLIENT_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSCLIENT_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_record_padding_test PRIVATE ssl crypto ww)
  add_dependencies(waterwall_unit_tests tlsclient_record_padding_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_record_padding_unit
    tlsclient_record_padding_test
    "unit;tunnels;tlsclient;tls13_record;padding;boringssl"
  )

  add_executable(tlsclient_alpn_test tlsclient_alpn_test.c)
  target_include_directories(tlsclient_alpn_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(tlsclient_alpn_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_alpn_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_alpn_test PRIVATE TlsClient ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_alpn_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_alpn_unit
    tlsclient_alpn_test
    "unit;tunnels;tlsclient;configuration;alpn"
  )

  add_executable(tlsclient_hostname_verification_test tlsclient_hostname_verification_test.c)
  target_include_directories(tlsclient_hostname_verification_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(tlsclient_hostname_verification_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_hostname_verification_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    TLSCLIENT_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    TLSCLIENT_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_hostname_verification_test PRIVATE TlsClient ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_hostname_verification_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_hostname_verification_unit
    tlsclient_hostname_verification_test
    "unit;tunnels;tlsclient;certificate;hostname"
  )

  add_executable(tlsclient_close_lifecycle_test tlsclient_close_lifecycle_test.c)
  target_include_directories(tlsclient_close_lifecycle_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(tlsclient_close_lifecycle_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_close_lifecycle_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(tlsclient_close_lifecycle_test PRIVATE TlsClient ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_close_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_close_lifecycle_unit
    tlsclient_close_lifecycle_test
    "unit;tunnels;tlsclient;lifecycle;reentry"
  )

  if(LINUX)
    add_executable(tls13_record_delay_lifecycle_test tls13_record_delay_lifecycle_test.c)
    target_include_directories(tls13_record_delay_lifecycle_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
    )
    target_include_directories(tls13_record_delay_lifecycle_test BEFORE PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
      ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
    )
    target_compile_definitions(tls13_record_delay_lifecycle_test PRIVATE BORINGSSL_PREFIX=WW_BSSL)
    target_link_options(tls13_record_delay_lifecycle_test PRIVATE "-Wl,--wrap=WW_BSSL_SSL_version")
    target_link_libraries(tls13_record_delay_lifecycle_test PRIVATE TlsClient TlsRecordShapingCommon ww ssl crypto)
    add_dependencies(waterwall_unit_tests tls13_record_delay_lifecycle_test)

    add_waterwall_unit_test(
      waterwall.tls13_record_delay_lifecycle_unit
      tls13_record_delay_lifecycle_test
      "unit;tunnels;tlsclient;tls13_record;delay;lifecycle;reentry"
    )
  endif()
endif()

if(TARGET RealityCommon)
  add_executable(reality_config_test reality_config_test.c)
  target_link_libraries(reality_config_test PRIVATE RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_config_test)

  add_waterwall_unit_test(
    waterwall.reality_config_unit
    reality_config_test
    "unit;tunnels;reality;v2;crypto;configuration"
  )

  add_executable(reality_v2_test reality_v2_test.c)
  target_compile_definitions(reality_v2_test PRIVATE
    REALITY_TLS_CLIENT_HANDSHAKE_SOURCE="${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/ssl/handshake_client.cc"
  )
  target_link_libraries(reality_v2_test PRIVATE RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_v2_test)

  add_waterwall_unit_test(waterwall.reality_v2_unit reality_v2_test "unit;tunnels;reality;v2;crypto;replay;direction")
endif()

if(TARGET WireGuardDevice)
  add_executable(wireguarddevice_layer_resolution_test
    wireguarddevice_layer_resolution_test.c
  )
  target_include_directories(wireguarddevice_layer_resolution_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice
  )
  target_link_libraries(wireguarddevice_layer_resolution_test PRIVATE WireGuardDevice ww)
  add_dependencies(waterwall_unit_tests wireguarddevice_layer_resolution_test)

  add_waterwall_unit_test(
    waterwall.wireguarddevice_layer_resolution_unit
    wireguarddevice_layer_resolution_test
    "unit;tunnels;wireguard;layer;topology"
  )
endif()

if(LINUX AND TARGET WireGuardDevice)
  add_executable(wireguard_crypto_failure_test
    wireguard_crypto_failure_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice/common/wireguard.c
  )
  target_include_directories(wireguard_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice/include/WireGuardDevice
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice
  )
  target_link_libraries(wireguard_crypto_failure_test PRIVATE ww)
  target_link_options(wireguard_crypto_failure_test PRIVATE
    "-Wl,-u,wCryptoBlake2sInit"
    "-Wl,-u,wCryptoBlake2s"
    "-Wl,-u,wCryptoX25519"
    "-Wl,-u,wCryptoChaCha20Poly1305Encrypt"
    "-Wl,--wrap=wCryptoBlake2sInit"
    "-Wl,--wrap=wCryptoBlake2s"
    "-Wl,--wrap=wCryptoX25519"
    "-Wl,--wrap=wCryptoChaCha20Poly1305Encrypt"
  )
  add_dependencies(waterwall_unit_tests wireguard_crypto_failure_test)

  add_waterwall_unit_test(
    waterwall.wireguard_crypto_failure_unit
    wireguard_crypto_failure_test
    "unit;tunnels;wireguard;crypto;failure"
  )
endif()

if(LINUX AND TARGET EncryptionClient)
  add_executable(encryptionclient_crypto_failure_test
    encryption_crypto_failure_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/common/line_state.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/downstream/payload.c
  )
  target_compile_definitions(encryptionclient_crypto_failure_test PRIVATE TEST_ENCRYPTION_CLIENT=1)
  target_include_directories(encryptionclient_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/include
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/include/EncryptionClient
  )
  target_link_libraries(encryptionclient_crypto_failure_test PRIVATE ww)
  target_link_options(encryptionclient_crypto_failure_test PRIVATE
    "-Wl,--wrap=wCryptoChaCha20Poly1305Decrypt"
  )
  add_dependencies(waterwall_unit_tests encryptionclient_crypto_failure_test)

  add_waterwall_unit_test(
    waterwall.encryptionclient_crypto_failure_unit
    encryptionclient_crypto_failure_test
    "unit;tunnels;encryptionclient;crypto;failure"
  )
endif()

if(LINUX AND TARGET EncryptionServer)
  add_executable(encryptionserver_crypto_failure_test
    encryption_crypto_failure_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/common/line_state.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/upstream/payload.c
  )
  target_compile_definitions(encryptionserver_crypto_failure_test PRIVATE TEST_ENCRYPTION_SERVER=1)
  target_include_directories(encryptionserver_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/include/EncryptionServer
  )
  target_link_libraries(encryptionserver_crypto_failure_test PRIVATE ww)
  target_link_options(encryptionserver_crypto_failure_test PRIVATE
    "-Wl,--wrap=wCryptoChaCha20Poly1305Decrypt"
  )
  add_dependencies(waterwall_unit_tests encryptionserver_crypto_failure_test)

  add_waterwall_unit_test(
    waterwall.encryptionserver_crypto_failure_unit
    encryptionserver_crypto_failure_test
    "unit;tunnels;encryptionserver;crypto;failure"
  )
endif()

if(TARGET RealityServer)
  add_executable(reality_tls_binding_test reality_tls_binding_test.c)
  target_include_directories(reality_tls_binding_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include/RealityServer
  )
  target_link_libraries(reality_tls_binding_test PRIVATE RealityServer RealityCommon ww)
  add_dependencies(waterwall_unit_tests reality_tls_binding_test)

  add_waterwall_unit_test(waterwall.reality_tls_binding_unit reality_tls_binding_test "unit;tunnels;reality;v2;tls-parser")
endif()

if(TARGET RealityServer AND TARGET TlsClient)
  add_executable(reality_tls_binding_interop_test
    reality_tls_binding_interop_test.c
    reality_tls_binding_fixture.c
  )
  target_include_directories(reality_tls_binding_interop_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include/RealityServer
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(reality_tls_binding_interop_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(reality_tls_binding_interop_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(reality_tls_binding_interop_test PRIVATE
    RealityServer RealityCommon TlsClient ww ssl crypto
  )
  add_dependencies(waterwall_unit_tests reality_tls_binding_interop_test)

  add_waterwall_unit_test(
    waterwall.reality_tls_binding_interop_unit
    reality_tls_binding_interop_test
    "unit;tunnels;reality;v2;tls-parser;tls-accessor"
  )
endif()

if(TARGET RealityClient AND TARGET RealityServer AND TARGET TlsClient)
  add_executable(reality_close_lifecycle_test
    reality_close_lifecycle_test.c
    reality_close_lifecycle_client.c
    reality_close_lifecycle_server.c
    reality_tls_binding_fixture.c
  )
  target_include_directories(reality_close_lifecycle_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/RealityClient/include
    ${CMAKE_SOURCE_DIR}/tunnels/RealityServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_include_directories(reality_close_lifecycle_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(reality_close_lifecycle_test PRIVATE
    BORINGSSL_PREFIX=WW_BSSL
    REALITY_TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.crt"
    REALITY_TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/cases/tls_roundtrip/server.key"
  )
  target_link_libraries(reality_close_lifecycle_test PRIVATE
    RealityClient RealityServer RealityCommon TlsClient TlsRecordShapingCommon ww ssl crypto
  )
  add_dependencies(waterwall_unit_tests reality_close_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.reality_close_lifecycle_unit
    reality_close_lifecycle_test
    "unit;tunnels;reality;v2;lifecycle;reentry"
  )
endif()

if(TARGET SniffRouter)
  add_executable(sniffrouter_classifier_test sniffrouter_classifier_test.c)
  target_include_directories(sniffrouter_classifier_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SniffRouter/include
    ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include
  )
  target_link_libraries(sniffrouter_classifier_test PRIVATE SniffRouter ReverseClient ww)
  add_dependencies(waterwall_unit_tests sniffrouter_classifier_test)

  add_waterwall_unit_test(waterwall.sniffrouter_classifier_unit sniffrouter_classifier_test "unit;tunnels;sniffrouter")
endif()

if(TARGET SniffRouter AND TARGET Router)
  add_executable(router_chain_ownership_test router_chain_ownership_test.c)
  target_include_directories(router_chain_ownership_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SniffRouter/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
  )
  target_link_libraries(router_chain_ownership_test PRIVATE SniffRouter Router ReverseClient ww)
  add_dependencies(waterwall_unit_tests router_chain_ownership_test)

  add_waterwall_unit_test(
    waterwall.router_chain_ownership_unit
    router_chain_ownership_test
    "unit;tunnels;router;sniffrouter;chain;ownership"
  )
endif()

if(TARGET PacketsToStream)
  add_executable(packetstostream_parser_test packetstostream_parser_test.c)
  target_include_directories(packetstostream_parser_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToStream/include
  )
  target_link_libraries(packetstostream_parser_test PRIVATE PacketsToStream ww)
  add_dependencies(waterwall_unit_tests packetstostream_parser_test)

  add_waterwall_unit_test(waterwall.packetstostream_parser_unit packetstostream_parser_test "unit;tunnels;packetstostream")
endif()

if(TARGET ReverseClient AND UNIX)
  add_executable(reverseclient_owner_drain_test reverseclient_owner_drain_test.c)
  target_compile_definitions(reverseclient_owner_drain_test PRIVATE WW_IDLE_TABLE_TEST_SEAM=1)
  target_include_directories(reverseclient_owner_drain_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/ReverseClient/include
  )
  target_link_libraries(reverseclient_owner_drain_test PRIVATE ReverseClient ww)
  add_dependencies(waterwall_unit_tests reverseclient_owner_drain_test)
  add_waterwall_unit_test(
    waterwall.reverseclient_owner_drain_unit
    reverseclient_owner_drain_test
    "unit;tunnels;reverseclient;ownership;shutdown"
  )
endif()

if(UNIX)
  # ww's PCH is reused by tunnel targets, so every consumer in this unit-only
  # tree must see the same test-hook macro set.
  target_compile_definitions(ww PUBLIC WW_IDLE_TABLE_TEST_SEAM=1)

  add_executable(widle_table_cancellation_test widle_table_cancellation_test.c)
  target_link_options(widle_table_cancellation_test PRIVATE
    "-Wl,--wrap=abortProgramNow"
    "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer"
    "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer"
    "-Wl,--wrap=sbufDestroy"
  )
  target_link_libraries(widle_table_cancellation_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests widle_table_cancellation_test)
  add_waterwall_unit_test(
    waterwall.widle_table_cancellation_unit
    widle_table_cancellation_test
    "unit;idle-table;worker-message;ownership;shutdown;tsan"
  )
endif()

if(TARGET IpManipulator)
  add_executable(ipmanipulator_tcpbit_test ipmanipulator_tcpbit_test.c)
  target_include_directories(ipmanipulator_tcpbit_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_tcpbit_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_tcpbit_test)

  add_waterwall_unit_test(waterwall.ipmanipulator_tcpbit_unit ipmanipulator_tcpbit_test "unit;tunnels;ipmanipulator")

  add_executable(ipmanipulator_syn_predicate_test ipmanipulator_syn_predicate_test.c)
  target_include_directories(ipmanipulator_syn_predicate_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_syn_predicate_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_syn_predicate_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_syn_predicate_unit
    ipmanipulator_syn_predicate_test
    "unit;tunnels;ipmanipulator;tcp;configuration"
  )

  add_executable(ipmanipulator_flow_table_test
    ipmanipulator_flow_table_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
  )
  target_include_directories(ipmanipulator_flow_table_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_flow_table_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_flow_table_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_flow_table_unit
    ipmanipulator_flow_table_test
    "unit;tunnels;ipmanipulator;flowtable;bounded;hashing"
  )

  add_executable(ipmanipulator_delay_barrier_test
    ipmanipulator_delay_barrier_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c
  )
  target_include_directories(ipmanipulator_delay_barrier_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_compile_definitions(ipmanipulator_delay_barrier_test PRIVATE IPMANIPULATOR_DELAY_BARRIER_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_delay_barrier_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_delay_barrier_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_delay_barrier_unit
    ipmanipulator_delay_barrier_test
    "unit;tunnels;ipmanipulator;firstsni;smugglesni;overlapsni;delay;fifo;lifecycle;worker;ownership"
  )

  add_executable(ipmanipulator_config_validation_test ipmanipulator_config_validation_test.c)
  target_include_directories(ipmanipulator_config_validation_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_config_validation_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_config_validation_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_config_validation_unit
    ipmanipulator_config_validation_test
    "unit;tunnels;ipmanipulator;configuration;tcpbit;sni"
  )

  add_executable(ipmanipulator_protoswap_test ipmanipulator_protoswap_test.c)
  target_include_directories(ipmanipulator_protoswap_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_protoswap_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_protoswap_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_protoswap_unit
    ipmanipulator_protoswap_test
    "unit;tunnels;ipmanipulator;protoswap;checksum"
  )

  add_executable(ipmanipulator_egress_test ipmanipulator_egress_test.c)
  target_include_directories(ipmanipulator_egress_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_egress_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_egress_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_egress_unit
    ipmanipulator_egress_test
    "unit;tunnels;ipmanipulator;protoswap;portghost;sniblender;checksum;lifecycle"
  )

  add_executable(ipmanipulator_worker_mismatch_log_test ipmanipulator_worker_mismatch_log_test.c)
  target_include_directories(ipmanipulator_worker_mismatch_log_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_worker_mismatch_log_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_worker_mismatch_log_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_worker_mismatch_log_unit
    ipmanipulator_worker_mismatch_log_test
    "unit;tunnels;ipmanipulator;logging;workers"
  )

  add_executable(ipmanipulator_firstsni_offsets_test ipmanipulator_firstsni_offsets_test.c)
  target_include_directories(ipmanipulator_firstsni_offsets_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_firstsni_offsets_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_firstsni_offsets_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_firstsni_offsets_unit
    ipmanipulator_firstsni_offsets_test
    "unit;tunnels;ipmanipulator;firstsni;tls"
  )

  add_executable(ipmanipulator_echsni_delay_test
    ipmanipulator_echsni_delay_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/echsnitrick/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c
  )
  target_include_directories(ipmanipulator_echsni_delay_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_compile_definitions(ipmanipulator_echsni_delay_test PRIVATE IPMANIPULATOR_ECHSNI_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_echsni_delay_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_echsni_delay_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_echsni_delay_unit
    ipmanipulator_echsni_delay_test
    "unit;tunnels;ipmanipulator;echsni;delay;lifecycle;worker;ownership"
  )

  add_executable(ipmanipulator_smugglesni_capture_test ipmanipulator_smugglesni_capture_test.c)
  target_include_directories(ipmanipulator_smugglesni_capture_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_link_libraries(ipmanipulator_smugglesni_capture_test PRIVATE IpManipulator ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_smugglesni_capture_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_smugglesni_capture_unit
    ipmanipulator_smugglesni_capture_test
    "unit;tunnels;ipmanipulator;smugglesni;tls;worker;ownership"
  )

  add_executable(ipmanipulator_smugglefin_pause_test
    ipmanipulator_smugglefin_pause_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/smugglefin/trick.c
  )
  target_include_directories(ipmanipulator_smugglefin_pause_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
  )
  target_compile_definitions(ipmanipulator_smugglefin_pause_test PRIVATE IPMANIPULATOR_SMUGGLEFIN_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_smugglefin_pause_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_smugglefin_pause_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_smugglefin_pause_unit
    ipmanipulator_smugglefin_pause_test
    "unit;tunnels;ipmanipulator;smugglefin;timeout;affinity"
  )

  add_executable(ipmanipulator_overlap_hold_test
    ipmanipulator_overlap_hold_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/overlapsni/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c
  )
  target_include_directories(ipmanipulator_overlap_hold_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_compile_definitions(ipmanipulator_overlap_hold_test PRIVATE IPMANIPULATOR_OVERLAP_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_overlap_hold_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_overlap_hold_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_overlap_hold_unit
    ipmanipulator_overlap_hold_test
    "unit;tunnels;ipmanipulator;overlapsni;timeout;lifecycle;worker;ownership"
  )

  add_executable(ipmanipulator_synfin_hold_test
    ipmanipulator_synfin_hold_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/synfinsni/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/portghost/trick.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/protoswap/trick.c
  )
  target_include_directories(ipmanipulator_synfin_hold_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_compile_definitions(ipmanipulator_synfin_hold_test PRIVATE IPMANIPULATOR_SYNFIN_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_synfin_hold_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_synfin_hold_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_synfin_hold_unit
    ipmanipulator_synfin_hold_test
    "unit;tunnels;ipmanipulator;synfinsni;timeout;lifecycle;worker;ownership"
  )

  add_executable(ipmanipulator_synfin_output_test
    ipmanipulator_synfin_output_test.c
    ipmanipulator_synfin_output_link_stubs.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/flow_table.c
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common/tricks/synfinsni/trick.c
  )
  target_include_directories(ipmanipulator_synfin_output_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
    ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/include
  )
  target_compile_definitions(ipmanipulator_synfin_output_test PRIVATE IPMANIPULATOR_SYNFIN_TEST_HOOKS=1)
  target_link_libraries(ipmanipulator_synfin_output_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipmanipulator_synfin_output_test)

  add_waterwall_unit_test(
    waterwall.ipmanipulator_synfin_output_unit
    ipmanipulator_synfin_output_test
    "unit;tunnels;ipmanipulator;synfinsni;ordering;lifecycle"
  )

  if(TARGET TlsClient)
    add_executable(ipmanipulator_internal_tls_child_test
      ipmanipulator_internal_tls_child_test.c
    )
    target_include_directories(ipmanipulator_internal_tls_child_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include
      ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/include/IpManipulator
      ${CMAKE_SOURCE_DIR}/tunnels/IpManipulator/common
    )
    target_link_libraries(ipmanipulator_internal_tls_child_test PRIVATE
      IpManipulator TlsClient ww ssl crypto
    )
    add_dependencies(waterwall_unit_tests ipmanipulator_internal_tls_child_test)

    add_waterwall_unit_test(
      waterwall.ipmanipulator_internal_tls_child_unit
      ipmanipulator_internal_tls_child_test
      "unit;tunnels;ipmanipulator;tlsclient;configuration;ownership"
    )
  endif()
endif()

if(TARGET IpOverrider)
  add_executable(ipoverrider_node_gate_test ipoverrider_node_gate_test.c)
  target_include_directories(ipoverrider_node_gate_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/IpOverrider/include
    ${CMAKE_SOURCE_DIR}/tunnels/IpOverrider/include/IpOverrider
  )
  target_link_libraries(ipoverrider_node_gate_test PRIVATE IpOverrider ww)
  add_dependencies(waterwall_unit_tests ipoverrider_node_gate_test)

  add_waterwall_unit_test(
    waterwall.ipoverrider_node_gate_unit
    ipoverrider_node_gate_test
    "unit;tunnels;ipoverrider;chance;only120"
  )
endif()

if(TARGET SoftIpLimiter)
  add_executable(softiplimiter_test softiplimiter_test.c)
  target_include_directories(softiplimiter_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/SoftIpLimiter/include
  )
  target_link_libraries(softiplimiter_test PRIVATE SoftIpLimiter ww)
  add_dependencies(waterwall_unit_tests softiplimiter_test)

  add_waterwall_unit_test(waterwall.softiplimiter_unit softiplimiter_test "unit;tunnels;softiplimiter")
endif()

set(ROUTER_GEOIP_TEST_DB "")
if(DEFINED maxminddb_SOURCE_DIR)
  set(ROUTER_GEOIP_TEST_DB "${maxminddb_SOURCE_DIR}/t/maxmind-db/test-data/GeoLite2-Country-Test.mmdb")
elseif(DEFINED CPM_PACKAGE_maxminddb_SOURCE_DIR)
  set(ROUTER_GEOIP_TEST_DB "${CPM_PACKAGE_maxminddb_SOURCE_DIR}/t/maxmind-db/test-data/GeoLite2-Country-Test.mmdb")
endif()

if(TARGET Router AND EXISTS "${ROUTER_GEOIP_TEST_DB}")
  add_executable(router_geoip_test router_geoip_test.c)
  target_include_directories(router_geoip_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_compile_definitions(router_geoip_test PRIVATE
    ROUTER_GEOIP_TEST_DB="${ROUTER_GEOIP_TEST_DB}"
  )
  target_link_libraries(router_geoip_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_geoip_test)

  add_waterwall_unit_test(waterwall.router_geoip_unit router_geoip_test "unit;tunnels;router;geoip")
endif()

if(TARGET Router)
  add_executable(router_geosite_test router_geosite_test.c)
  target_include_directories(router_geosite_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_link_libraries(router_geosite_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_geosite_test)

  add_waterwall_unit_test(waterwall.router_geosite_unit router_geosite_test "unit;tunnels;router;geosite")

  add_executable(router_sniffing_test router_sniffing_test.c)
  target_include_directories(router_sniffing_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_compile_definitions(router_sniffing_test PRIVATE
    ROUTER_QUIC_SNI_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/router_quic_sni/vectors"
  )
  target_link_libraries(router_sniffing_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_sniffing_test)

  add_waterwall_unit_test(waterwall.router_sniffing_unit router_sniffing_test "unit;tunnels;router;sniffing")
endif()

# ---------------------------------------------------------------------------
# Category-C per-line failure injection.
#
# Each tunnel gets its own executable on purpose: several tunnels ship a header
# named structure.h, so one translation unit must only ever see the include tree
# of the tunnel it is testing.
#
# Every one of these links against tunnel_line_failure_harness.h, which wraps the
# three process APIs (so a line-local failure that terminates the process fails
# the test immediately) and the buffer pool (so a leaked or twice-recycled buffer
# is a hard error).
# ---------------------------------------------------------------------------
# ww is an IPO library in Release, and a wrapped symbol whose caller is inside that same LTO unit is resolved by
# the plugin before --wrap is applied. The two bufio translation units that recycle buffers on the tunnels' behalf
# are therefore compiled into the test as well; the linker satisfies them from these objects and never pulls the
# library members, so the buffer ledger sees every acquire and every recycle in every configuration.
set(WATERWALL_LINE_FAILURE_WW_SOURCES
  ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_queue.c
  ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_stream.c
)

set(WATERWALL_LINE_FAILURE_WRAPS
  "-Wl,--wrap=abortProgramNow"
  "-Wl,--wrap=requestProgramShutdown"
  "-Wl,--wrap=bufferpoolGetLargeBuffer"
  "-Wl,--wrap=bufferpoolGetSmallBuffer"
  "-Wl,--wrap=bufferpoolReuseBuffer"
  "-Wl,--wrap=sbufDestroy"
)


# Linker --wrap only intercepts references that survive as real relocations. The production tunnel libraries are
# built with IPO in Release, where the compiler may inline a wrapped call before the linker ever sees it, so the
# tunnel under test is compiled straight into the (never-IPO) test executable instead of being linked as a
# library. This mirrors what the capture and device tests already do for the ww sources they inject faults into.
function(waterwall_line_failure_test_use_tunnel test_target tunnel_target)
  get_target_property(tunnel_dir "${tunnel_target}" SOURCE_DIR)
  get_target_property(tunnel_srcs "${tunnel_target}" SOURCES)
  get_target_property(tunnel_incs "${tunnel_target}" INCLUDE_DIRECTORIES)
  get_target_property(tunnel_interface_incs "${tunnel_target}" INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(tunnel_defs "${tunnel_target}" COMPILE_DEFINITIONS)
  get_target_property(tunnel_interface_defs "${tunnel_target}" INTERFACE_COMPILE_DEFINITIONS)
  get_target_property(tunnel_links "${tunnel_target}" LINK_LIBRARIES)
  get_target_property(tunnel_interface_links "${tunnel_target}" INTERFACE_LINK_LIBRARIES)

  set(resolved_sources "")
  foreach(source IN LISTS tunnel_srcs)
    if(IS_ABSOLUTE "${source}" OR source MATCHES "^\\$<")
      list(APPEND resolved_sources "${source}")
    else()
      list(APPEND resolved_sources "${tunnel_dir}/${source}")
    endif()
  endforeach()

  target_sources("${test_target}" PRIVATE ${resolved_sources})

  foreach(entry IN ITEMS tunnel_incs tunnel_interface_incs)
    if(${entry})
      target_include_directories("${test_target}" PRIVATE ${${entry}})
    endif()
  endforeach()

  foreach(entry IN ITEMS tunnel_defs tunnel_interface_defs)
    if(${entry})
      target_compile_definitions("${test_target}" PRIVATE ${${entry}})
    endif()
  endforeach()

  foreach(entry IN ITEMS tunnel_links tunnel_interface_links)
    if(${entry})
      target_link_libraries("${test_target}" PRIVATE ${${entry}})
    endif()
  endforeach()
endfunction()

# Focused packet-bridge coverage for user-visible classification, checksum,
# lifetime, and adapter-boundary contracts.
if(TARGET ww)
  add_executable(capture_windows_checksum_test capture_windows_checksum_test.c)
  target_link_libraries(capture_windows_checksum_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests capture_windows_checksum_test)
  add_waterwall_unit_test(
    waterwall.capture_windows_checksum_unit
    capture_windows_checksum_test
    "unit;net;capture;checksum"
  )

  add_executable(device_checksum_validity_test device_checksum_validity_test.c)
  target_link_libraries(device_checksum_validity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests device_checksum_validity_test)
  add_waterwall_unit_test(
    waterwall.device_checksum_validity_unit
    device_checksum_validity_test
    "unit;net;devices;checksum"
  )

  add_executable(device_frag_affinity_test device_frag_affinity_test.c)
  target_link_libraries(device_frag_affinity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests device_frag_affinity_test)
  add_waterwall_unit_test(
    waterwall.device_frag_affinity_unit
    device_frag_affinity_test
    "unit;net;devices;fragment;affinity;lifetime"
  )
endif()

if(TARGET ConnectionToPackets AND TARGET TcpUdpConnector)
  add_executable(transport_classifier_matrix_test transport_classifier_matrix_test.c)
  target_link_libraries(transport_classifier_matrix_test PRIVATE ConnectionToPackets TcpUdpConnector ww)
  add_dependencies(waterwall_unit_tests transport_classifier_matrix_test)
  add_waterwall_unit_test(
    waterwall.transport_classifier_matrix_unit
    transport_classifier_matrix_test
    "unit;tunnels;connectiontopackets;tcpudpconnector;classifier"
  )
endif()

if(TARGET ConnectionToPackets)
  add_executable(connectiontopackets_netif_contract_test connectiontopackets_netif_contract_test.c)
  target_link_libraries(connectiontopackets_netif_contract_test PRIVATE ConnectionToPackets ww)
  add_dependencies(waterwall_unit_tests connectiontopackets_netif_contract_test)
  add_waterwall_unit_test(
    waterwall.connectiontopackets_netif_contract_unit
    connectiontopackets_netif_contract_test
    "unit;tunnels;connectiontopackets;netif;fragment"
  )
endif()

if(TARGET PacketsToConnection)
  add_executable(packetstoconnection_fake_dns_fragment_test packetstoconnection_fake_dns_fragment_test.c)
  target_include_directories(packetstoconnection_fake_dns_fragment_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include
    ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include/PacketsToConnection
  )
  target_link_libraries(packetstoconnection_fake_dns_fragment_test PRIVATE PacketsToConnection ww)
  add_dependencies(waterwall_unit_tests packetstoconnection_fake_dns_fragment_test)
  add_waterwall_unit_test(
    waterwall.packetstoconnection_fake_dns_fragment_unit
    packetstoconnection_fake_dns_fragment_test
    "unit;tunnels;packetstoconnection;packet;fragment;dns"
  )

  if(LINUX)
    # The payload source is compiled once more with its unit-only final-admission
    # seam.  The archive's ordinary payload object is not extracted, so normal
    # PacketsToConnection code and layout stay production-identical.
    add_executable(packetstoconnection_fragment_admission_test
      packetstoconnection_fragment_admission_test.c
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/upstream/payload.c
    )
    target_compile_definitions(packetstoconnection_fragment_admission_test PRIVATE
      PTC_FRAGMENT_ADMISSION_TEST_HOOKS=1
    )
    target_include_directories(packetstoconnection_fragment_admission_test PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection/include/PacketsToConnection
      ${CMAKE_SOURCE_DIR}/tunnels/PacketsToConnection
      ${CMAKE_SOURCE_DIR}/ww/base
    )
    target_link_options(packetstoconnection_fragment_admission_test PRIVATE
      "-Wl,--wrap=bufferpoolReuseBuffer"
      "-Wl,--wrap=deviceFragAffinitySettlePublication"
    )
    target_link_libraries(packetstoconnection_fragment_admission_test PRIVATE PacketsToConnection ww)
    add_dependencies(waterwall_unit_tests packetstoconnection_fragment_admission_test)
    add_waterwall_unit_test(
      waterwall.packetstoconnection_fragment_admission_unit
      packetstoconnection_fragment_admission_test
      "unit;tunnels;packetstoconnection;packet;fragment;admission;lifetime"
    )
  endif()
endif()

if(LINUX AND TARGET RawSocket)
  add_executable(rawsocket_ipv4_boundary_test
    rawsocket_ipv4_boundary_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(rawsocket_ipv4_boundary_test RawSocket)
  target_link_options(rawsocket_ipv4_boundary_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=rawdeviceWrite"
  )
  target_link_libraries(rawsocket_ipv4_boundary_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests rawsocket_ipv4_boundary_test)
  add_waterwall_unit_test(
    waterwall.rawsocket_ipv4_boundary_unit
    rawsocket_ipv4_boundary_test
    "unit;net;packet;rawsocket;boundary"
  )
endif()

if(TARGET HttpClient)
  add_executable(httpclient_chunked_terminator_test
    httpclient_chunked_terminator_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(httpclient_chunked_terminator_test HttpClient)
  target_link_options(httpclient_chunked_terminator_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(httpclient_chunked_terminator_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpclient_chunked_terminator_test)

  add_waterwall_unit_test(
    waterwall.httpclient_chunked_terminator_unit
    httpclient_chunked_terminator_test
    "unit;tunnels;httpclient;chunked;framing"
  )
  set_tests_properties(waterwall.httpclient_chunked_terminator_unit PROPERTIES TIMEOUT 30)

  add_executable(httpclient_reentrant_finish_test
    httpclient_reentrant_finish_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(httpclient_reentrant_finish_test HttpClient)
  target_link_options(httpclient_reentrant_finish_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=bufferpoolGetLargeBufferSize"
  )
  target_link_libraries(httpclient_reentrant_finish_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpclient_reentrant_finish_test)

  add_waterwall_unit_test(
    waterwall.httpclient_reentrant_finish_unit
    httpclient_reentrant_finish_test
    "unit;tunnels;httpclient;reentrant;finish;line"
  )
endif()

if(TARGET HttpServer)
  add_executable(httpserver_chunked_terminator_test
    httpserver_chunked_terminator_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(httpserver_chunked_terminator_test HttpServer)
  target_link_options(httpserver_chunked_terminator_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(httpserver_chunked_terminator_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpserver_chunked_terminator_test)

  add_waterwall_unit_test(
    waterwall.httpserver_chunked_terminator_unit
    httpserver_chunked_terminator_test
    "unit;tunnels;httpserver;chunked;framing"
  )
  set_tests_properties(waterwall.httpserver_chunked_terminator_unit PROPERTIES TIMEOUT 30)

  add_executable(httpserver_reentrant_finish_test
    httpserver_reentrant_finish_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(httpserver_reentrant_finish_test HttpServer)
  target_link_options(httpserver_reentrant_finish_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=bufferpoolGetLargeBufferSize"
  )
  target_link_libraries(httpserver_reentrant_finish_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests httpserver_reentrant_finish_test)

  add_waterwall_unit_test(
    waterwall.httpserver_reentrant_finish_unit
    httpserver_reentrant_finish_test
    "unit;tunnels;httpserver;reentrant;finish;line"
  )
endif()

if(TARGET HalfDuplexServer)
  add_executable(halfduplexserver_reentrant_init_test
    halfduplexserver_reentrant_init_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(halfduplexserver_reentrant_init_test HalfDuplexServer)
  target_link_options(halfduplexserver_reentrant_init_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleTask"
  )
  target_link_libraries(halfduplexserver_reentrant_init_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests halfduplexserver_reentrant_init_test)

  add_waterwall_unit_test(
    waterwall.halfduplexserver_reentrant_init_unit
    halfduplexserver_reentrant_init_test
    "unit;tunnels;halfduplexserver;reentrant;init;line"
  )
endif()

if(TARGET SpeedLimit)
  add_executable(speedlimit_line_failure_test
    speedlimit_line_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(speedlimit_line_failure_test SpeedLimit)
  target_link_options(speedlimit_line_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=wtimerAdd"
  )
  target_link_libraries(speedlimit_line_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests speedlimit_line_failure_test)

  add_waterwall_unit_test(
    waterwall.speedlimit_line_failure_unit
    speedlimit_line_failure_test
    "unit;tunnels;speedlimit;failure;line"
  )
endif()

if(TARGET TlsServer)
  add_executable(tlsserver_line_failure_test
    tlsserver_line_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(tlsserver_line_failure_test TlsServer)
  target_link_options(tlsserver_line_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=wtimerAdd"
  )
  target_link_libraries(tlsserver_line_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tlsserver_line_failure_test)

  add_waterwall_unit_test(
    waterwall.tlsserver_line_failure_unit
    tlsserver_line_failure_test
    "unit;tunnels;tlsserver;failure;line"
  )
endif()

if(TARGET TlsClient)
  add_executable(tlsclient_line_failure_test
    tlsclient_line_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(tlsclient_line_failure_test TlsClient)
  target_include_directories(tlsclient_line_failure_test BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/TlsClient/boringssl/include
    ${CMAKE_BINARY_DIR}/tunnels/TlsClient/boringssl/symbol_prefix_include
  )
  target_compile_definitions(tlsclient_line_failure_test PRIVATE BORINGSSL_PREFIX=WW_BSSL)
  target_link_options(tlsclient_line_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=WW_BSSL_BIO_new"
    "-Wl,--wrap=WW_BSSL_SSL_new"
    "-Wl,--wrap=WW_BSSL_SSL_add_application_settings"
  )
  target_link_libraries(tlsclient_line_failure_test PRIVATE ww ssl crypto)
  add_dependencies(waterwall_unit_tests tlsclient_line_failure_test)

  add_waterwall_unit_test(
    waterwall.tlsclient_line_failure_unit
    tlsclient_line_failure_test
    "unit;tunnels;tlsclient;failure;line"
  )
endif()

if(TARGET TcpUdpConnector AND TARGET TcpConnector AND TARGET UdpConnector)
  add_executable(tcpudpconnector_selection_failure_test
    tcpudpconnector_selection_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(tcpudpconnector_selection_failure_test TcpUdpConnector)
  target_link_options(tcpudpconnector_selection_failure_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(tcpudpconnector_selection_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tcpudpconnector_selection_failure_test)

  add_waterwall_unit_test(
    waterwall.tcpudpconnector_selection_failure_unit
    tcpudpconnector_selection_failure_test
    "unit;tunnels;tcpudpconnector;failure;line"
  )
endif()

if(TARGET Router)
  add_executable(router_evaluation_failure_test
    router_evaluation_failure_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(router_evaluation_failure_test Router)
  # Per-source properties are directory scoped, so Router's own relaxation for the STC regex implementation unit
  # has to be repeated where the source is compiled.
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set_source_files_properties(${CMAKE_SOURCE_DIR}/tunnels/Router/common/stc_regex.c
      PROPERTIES COMPILE_OPTIONS "-Wno-nested-externs")
  endif()
  target_link_options(router_evaluation_failure_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=MMDB_lookup_sockaddr"
    "-Wl,--wrap=MMDB_get_value"
    # cregex_match_sv() is a macro; cregex_match_opt() is the symbol it actually links against.
    "-Wl,--wrap=cregex_match_opt"
  )
  target_link_libraries(router_evaluation_failure_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests router_evaluation_failure_test)

  add_waterwall_unit_test(
    waterwall.router_evaluation_failure_unit
    router_evaluation_failure_test
    "unit;tunnels;router;failure;line"
  )
endif()

foreach(tcpoverudp_side Client Server)
  string(TOLOWER "${tcpoverudp_side}" tcpoverudp_side_lower)
  set(tcpoverudp_target "TcpOverUdp${tcpoverudp_side}")
  set(tcpoverudp_test "tcpoverudp${tcpoverudp_side_lower}_line_failure_test")

  if(TARGET ${tcpoverudp_target})
    add_executable(${tcpoverudp_test}
      ${tcpoverudp_test}.c
      ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    )
    waterwall_line_failure_test_use_tunnel(${tcpoverudp_test} ${tcpoverudp_target})
    # ikcp.h and ww_fec.h are private to the tunnel target but reachable from its public structure.h.
    target_include_directories(${tcpoverudp_test} PRIVATE
      ${CMAKE_SOURCE_DIR}/tunnels/${tcpoverudp_target}/kcp
      ${CMAKE_SOURCE_DIR}/tunnels/TcpOverUdpClient/fec
    )
    target_link_options(${tcpoverudp_test} PRIVATE
      ${WATERWALL_LINE_FAILURE_WRAPS}
      "-Wl,--wrap=wtimerAdd"
      "-Wl,--wrap=wtimerDelete"
      "-Wl,--wrap=ikcp_create"
      "-Wl,--wrap=ikcp_release"
      "-Wl,--wrap=ikcp_setmtu"
      "-Wl,--wrap=tcpoverudpFecEncoderCreate"
      "-Wl,--wrap=tcpoverudpFecDecoderCreate"
      "-Wl,--wrap=tcpoverudpFecEncoderDestroy"
      "-Wl,--wrap=tcpoverudpFecDecoderDestroy"
    )
    target_link_libraries(${tcpoverudp_test} PRIVATE ww)
    add_dependencies(waterwall_unit_tests ${tcpoverudp_test})

    add_waterwall_unit_test(
      waterwall.${tcpoverudp_test}_unit
      ${tcpoverudp_test}
      "unit;tunnels;tcpoverudp;failure;line"
    )
  endif()
endforeach()

foreach(mux_side Client Server)
  string(TOLOWER "${mux_side}" mux_side_lower)
  set(mux_target "Mux${mux_side}")
  set(mux_test "mux${mux_side_lower}_frame_encoding_test")

  if(TARGET ${mux_target})
    add_executable(${mux_test}
      ${mux_test}.c
      ${WATERWALL_LINE_FAILURE_WW_SOURCES}
      ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/src/mux_wire.c
    )
    waterwall_line_failure_test_use_tunnel(${mux_test} ${mux_target})
    target_link_options(${mux_test} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    target_link_libraries(${mux_test} PRIVATE ww)
    add_dependencies(waterwall_unit_tests ${mux_test})

    add_waterwall_unit_test(
      waterwall.${mux_test}_unit
      ${mux_test}
      "unit;tunnels;mux;framing"
    )
  endif()
endforeach()

if(LINUX AND TARGET MuxClient AND TARGET TlsServer AND TARGET TlsRecordShapingCommon)
  add_executable(muxclient_tlsserver_close_backpressure_test
    muxclient_tlsserver_close_backpressure_test.c
    mux_tls_close_backpressure_fixture.c
    muxclient_backpressure_fixture.c
    tlsserver_backpressure_fixture.c
  )
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
  add_executable(muxserver_tlsclient_close_backpressure_test
    muxserver_tlsclient_close_backpressure_test.c
    mux_tls_close_backpressure_fixture.c
    muxserver_backpressure_fixture.c
    tlsclient_backpressure_fixture.c
  )
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
  add_executable(udplistener_mux_shutdown_order_test
    udplistener_mux_shutdown_order_test.c
    udplistener_shutdown_fixture.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
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
  add_executable(owned_line_finish_udpstatelesssocket_test
    owned_line_finish_udpstatelesssocket_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
  waterwall_line_failure_test_use_tunnel(owned_line_finish_udpstatelesssocket_test UdpStatelessSocket)
  target_link_options(owned_line_finish_udpstatelesssocket_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
  target_link_libraries(owned_line_finish_udpstatelesssocket_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests owned_line_finish_udpstatelesssocket_test)

  add_waterwall_unit_test(
    waterwall.owned_line_finish_udpstatelesssocket_unit
    owned_line_finish_udpstatelesssocket_test
    "unit;tunnels;udpstatelesssocket;line;ownership;lifetime"
  )
endif()

if(TARGET MuxServer)
  add_executable(owned_line_finish_muxserver_test
    owned_line_finish_muxserver_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/src/mux_wire.c
  )
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
  add_executable(streamtopackets_ownership_test
    streamtopackets_ownership_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
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
  add_executable(packetstostream_bridge_affinity_test
    packetstostream_bridge_affinity_test.c
    ${WATERWALL_LINE_FAILURE_WW_SOURCES}
  )
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
add_executable(socket_manager_lifetime_test
  socket_manager_lifetime_test.c
  ${CMAKE_SOURCE_DIR}/ww/managers/socket_manager.c
)
set_target_properties(socket_manager_lifetime_test PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
target_compile_definitions(socket_manager_lifetime_test PRIVATE
  WW_SYNC_INIT_TEST_SEAM=1
  WW_SOCKET_MANAGER_CONSTRUCTOR_TEST_SEAM=1
)
target_include_directories(socket_manager_lifetime_test PRIVATE
  ${CMAKE_SOURCE_DIR}/ww/managers
)
target_link_libraries(socket_manager_lifetime_test PRIVATE ww)
add_dependencies(waterwall_unit_tests socket_manager_lifetime_test)
add_waterwall_unit_test(
  waterwall.socket_manager_lifetime_unit
  socket_manager_lifetime_test
  "unit;socket-manager;synchronization;lifecycle;failure;linux"
)

# Category-B orderly-shutdown failure injection. One executable per tunnel so
# that only one tunnel's structure.h is ever visible in a translation unit.
# wtimerAdd is wrapped alongside the process APIs wherever the injected failure
# is a timer that cannot be created.
foreach(orderly_case IN ITEMS
  "TesterClient|testerclient_orderly_shutdown_test|testerclient|ON"
  "SpeedTestClient|speedtestclient_orderly_shutdown_test|speedtestclient|ON"
  "TesterServer|testerserver_orderly_shutdown_test|testerserver|OFF"
  "PacketsToStream|packetstostream_orderly_shutdown_test|packetstostream|ON"
  "PacketSender|packetsender_orderly_shutdown_test|packetsender|ON"
  "AuthenticationClient|authenticationclient_orderly_shutdown_test|authenticationclient|ON"
  "KeepAliveClient|keepaliveclient_orderly_shutdown_test|keepaliveclient|ON"
  "UserController|usercontroller_orderly_shutdown_test|usercontroller|ON"
  "WireGuardDevice|wireguarddevice_orderly_shutdown_test|wireguarddevice|OFF"
)
  string(REPLACE "|" ";" orderly_fields "${orderly_case}")
  list(GET orderly_fields 0 orderly_tunnel)
  list(GET orderly_fields 1 orderly_test)
  list(GET orderly_fields 2 orderly_label)
  list(GET orderly_fields 3 orderly_wraps_timer)

  if(TARGET ${orderly_tunnel})
    add_executable(${orderly_test}
      ${orderly_test}.c
      ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    )
    waterwall_line_failure_test_use_tunnel(${orderly_test} ${orderly_tunnel})
    target_link_options(${orderly_test} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    if(orderly_wraps_timer)
      target_link_options(${orderly_test} PRIVATE "-Wl,--wrap=wtimerAdd")
    endif()
    if(orderly_tunnel STREQUAL "PacketsToStream" OR orderly_tunnel STREQUAL "PacketSender")
      target_link_options(${orderly_test} PRIVATE "-Wl,--wrap=wtimerReset")
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
      target_compile_definitions(${orderly_test} PRIVATE WW_SPEEDTESTCLIENT_SHUTDOWN_TEST_SEAM=1)
      target_sources(${orderly_test} PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/SpeedTestClient/instance/start.c
      )
      target_link_options(${orderly_test} PRIVATE
        "-Wl,--wrap=memoryAllocate"
        "-Wl,--wrap=memoryFree"
      )
    endif()
    if(orderly_tunnel STREQUAL "TesterClient")
      target_sources(${orderly_test} PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/TesterClient/instance/start.c
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

# Tunnel hard-abort runtime cases. The registration is shared with the native
# Windows/macOS test configurations, which do not add the tests/ subtree.
include("${CMAKE_CURRENT_SOURCE_DIR}/tunnels_abort_runtime_test.cmake")

add_custom_target(check_waterwall_unit_tests
  COMMAND
    "${CMAKE_CTEST_COMMAND}"
    --test-dir "${CMAKE_BINARY_DIR}"
    -C "$<CONFIG>"
    --output-on-failure
    -L unit
  DEPENDS waterwall_unit_tests
  USES_TERMINAL
)
