# Explicit runtime/native target groups; included inside the ww target condition.
  waterwall_add_native_executable(address_context_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/address_context_test.c)
  target_link_libraries(address_context_test PRIVATE ww_test_support)
  target_link_libraries(address_context_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests address_context_test)

  add_waterwall_unit_test(waterwall.address_context_unit address_context_test "unit;net;address-context")

  waterwall_add_native_executable(wchecksum_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/wchecksum_test.c)
  target_link_libraries(wchecksum_test PRIVATE ww_test_support)
  target_link_libraries(wchecksum_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wchecksum_test)

  add_waterwall_unit_test(waterwall.wchecksum_unit wchecksum_test "unit;net;checksum")

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
    foreach(variant IN ITEMS backend variants)
      set(checksum_test lwip_checksum_${variant}_test)
      waterwall_add_native_executable(${checksum_test} SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_checksum_backend_test.c)
  target_link_libraries(${checksum_test} PRIVATE ww_test_support)
      target_link_libraries(${checksum_test} PRIVATE ww)
      target_link_options(${checksum_test} PRIVATE "-Wl,--wrap=wwLwipChecksum")
      if(variant STREQUAL "variants")
        target_compile_definitions(${checksum_test} PRIVATE WW_CHECKSUM_TEST_VARIANT=1)
      endif()
      add_dependencies(waterwall_unit_tests ${checksum_test})
      add_waterwall_unit_test(waterwall.lwip_checksum_${variant}_unit ${checksum_test} "unit;net;lwip;checksum")
    endforeach()
  endif()

  waterwall_add_native_executable(ipv4_packet_view_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/ipv4_packet_view_test.c)
  target_link_libraries(ipv4_packet_view_test PRIVATE ww_test_support)
  target_link_libraries(ipv4_packet_view_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests ipv4_packet_view_test)

  add_waterwall_unit_test(waterwall.ipv4_packet_view_unit ipv4_packet_view_test "unit;net;packet-view")

  waterwall_add_native_executable(tls_client_hello_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tls/tls_client_hello_test.c)
  target_link_libraries(tls_client_hello_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tls_client_hello_test)

  add_waterwall_unit_test(waterwall.tls_client_hello_unit tls_client_hello_test "unit;net;tls")

  waterwall_add_native_executable(buffer_pool_best_fit_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/buffer_pool_best_fit_test.c)
  target_link_libraries(buffer_pool_best_fit_test PRIVATE ww_test_support)
  target_link_libraries(buffer_pool_best_fit_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests buffer_pool_best_fit_test)

  add_waterwall_unit_test(waterwall.buffer_pool_best_fit_unit buffer_pool_best_fit_test "unit;bufio;buffer-pool")

  waterwall_add_native_executable(buffer_pool_splice_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/buffer_pool_splice_test.c)
  target_link_libraries(buffer_pool_splice_test PRIVATE ww_test_support)
  target_link_libraries(buffer_pool_splice_test PRIVATE ww)
  if(LINUX)
    waterwall_add_native_executable(buffer_pool_splice_bypass_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/buffer_pool_splice_test.c)
  target_link_libraries(buffer_pool_splice_bypass_test PRIVATE ww_test_support)
    target_compile_definitions(buffer_pool_splice_bypass_test PRIVATE WW_SPLICE_POOL_BYPASS_TEST=1)
    target_link_libraries(buffer_pool_splice_bypass_test PRIVATE ww)
    target_link_options(buffer_pool_splice_bypass_test PRIVATE "-Wl,--wrap=pipe2")
    add_dependencies(waterwall_unit_tests buffer_pool_splice_bypass_test)
    add_waterwall_unit_test(waterwall.buffer_pool_splice_bypass_unit buffer_pool_splice_bypass_test "unit;bufio;buffer-pool;splice")
    target_compile_definitions(buffer_pool_splice_test PRIVATE WW_SPLICE_POOL_FAILURE_TEST=1)
    target_link_options(buffer_pool_splice_test PRIVATE "-Wl,--wrap=memoryAllocate" "-Wl,--wrap=pipe2")
  endif()
  add_dependencies(waterwall_unit_tests buffer_pool_splice_test)
  add_waterwall_unit_test(waterwall.buffer_pool_splice_unit buffer_pool_splice_test "unit;bufio;buffer-pool;splice")

  waterwall_add_native_executable(packet_tunnel_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/packet_tunnel_test.c)
  target_link_libraries(packet_tunnel_test PRIVATE ww_test_support)
  target_link_libraries(packet_tunnel_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests packet_tunnel_test)

  add_waterwall_unit_test(waterwall.packet_tunnel_unit packet_tunnel_test "unit;net;packet-tunnel")
  add_library(missing_abi_node_library SHARED ${WATERWALL_UNIT_SOURCE_ROOT}/core/legacy_node_library.c)
  target_compile_definitions(missing_abi_node_library PRIVATE FIXTURE_NODE_TYPE="MissingAbiFixture")
  set_target_properties(missing_abi_node_library PROPERTIES PREFIX "")
  add_library(mismatched_abi_node_library SHARED ${WATERWALL_UNIT_SOURCE_ROOT}/core/legacy_node_library.c)
  target_compile_definitions(
    mismatched_abi_node_library
    PRIVATE FIXTURE_NODE_TYPE="MismatchedAbiFixture" FIXTURE_ABI_VERSION=4
  )
  set_target_properties(mismatched_abi_node_library PROPERTIES PREFIX "")
  add_library(external_node_abi_v3_library SHARED ${WATERWALL_UNIT_SOURCE_ROOT}/core/lifecycle_v2_node_library.c)
  set_target_properties(external_node_abi_v3_library PROPERTIES PREFIX "")
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    foreach(node_fixture_target IN ITEMS
        missing_abi_node_library
        mismatched_abi_node_library
        external_node_abi_v3_library)
      # At -O0 the public headers emit otherwise-unused static helpers whose
      # application-owned symbols cannot resolve inside a standalone fixture.
      # Give the linker one section per helper so it can retain only the ABI
      # surface these external-node fixtures actually export.
      target_compile_options(${node_fixture_target} PRIVATE -ffunction-sections -fdata-sections)
      target_link_options(${node_fixture_target} PRIVATE "LINKER:--gc-sections")
    endforeach()
  endif()
  waterwall_add_native_executable(legacy_node_compatibility_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/legacy_node_compatibility_test.c)
  target_link_libraries(legacy_node_compatibility_test PRIVATE ww_test_support)
  target_compile_definitions(
    legacy_node_compatibility_test
    PRIVATE
      MISSING_NODE_LIBRARY_PATH="$<TARGET_FILE:missing_abi_node_library>"
      MISMATCHED_NODE_LIBRARY_PATH="$<TARGET_FILE:mismatched_abi_node_library>"
      EXTERNAL_NODE_ABI_V3_LIBRARY_PATH="$<TARGET_FILE:external_node_abi_v3_library>"
  )
  target_link_libraries(legacy_node_compatibility_test PRIVATE ww)
  add_dependencies(
    legacy_node_compatibility_test
    missing_abi_node_library
    mismatched_abi_node_library
    external_node_abi_v3_library
  )
  add_dependencies(waterwall_unit_tests legacy_node_compatibility_test)
  add_waterwall_unit_test(
    waterwall.external_node_abi_v3_unit
    legacy_node_compatibility_test
    "unit;net;tunnels;node-manager;abi;external-node-v3;portable"
  )

  waterwall_add_native_executable(users_runtime_migration_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/users_runtime_migration_test.c
    ${CMAKE_SOURCE_DIR}/ww/objects/user.c)
  target_link_libraries(users_runtime_migration_test PRIVATE ww_test_support)
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
  # compiled directly so linker wrappers and the retained credential-snapshot
  # wipe counter observe this executable's lookup and update paths.
  waterwall_add_native_executable(users_index_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/users_index_test.c
    ${CMAKE_SOURCE_DIR}/ww/objects/user.c
    ${CMAKE_SOURCE_DIR}/ww/objects/users.c)
  target_link_libraries(users_index_test PRIVATE ww_test_support)
  target_link_libraries(users_index_test PRIVATE ww)
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

  waterwall_add_native_executable(socket_manager_rules_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/socket_manager/socket_manager_rules_test.c)
  target_link_libraries(socket_manager_rules_test PRIVATE ww_test_support)
  target_link_libraries(socket_manager_rules_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests socket_manager_rules_test)

  add_waterwall_unit_test(waterwall.socket_manager_rules_unit socket_manager_rules_test "unit;net;socket-manager")

  waterwall_add_native_executable(socket_manager_selection_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/devices/socket_manager/socket_manager_selection_test.c)
  target_include_directories(socket_manager_selection_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/managers)
  target_link_libraries(socket_manager_selection_test PRIVATE ww_test_support ww)
  add_dependencies(waterwall_unit_tests socket_manager_selection_test)
  add_waterwall_unit_test(waterwall.socket_manager_selection_unit socket_manager_selection_test
    "unit;net;socket-manager;selection")

  waterwall_add_native_executable(socket_manager_iptables_recovery_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/socket_manager/socket_manager_iptables_recovery_test.c)
  target_link_libraries(socket_manager_iptables_recovery_test PRIVATE ww_test_support)
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
    # ${WATERWALL_UNIT_SOURCE_ROOT}/base/wproc_deadline_test.c along with the supervisor itself.
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

  waterwall_add_native_executable(udp_zero_length_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/udp_zero_length_test.c)
  target_link_libraries(udp_zero_length_test PRIVATE ww_test_support)
  target_link_libraries(udp_zero_length_test PRIVATE ww)
  if(LINUX)
    target_compile_definitions(udp_zero_length_test PRIVATE WW_UDP_READ_IOCTL_TEST=1)
    target_link_options(udp_zero_length_test PRIVATE "-Wl,--wrap=ioctl")
  endif()
  add_dependencies(waterwall_unit_tests udp_zero_length_test)

  add_waterwall_unit_test(waterwall.udp_zero_length_unit udp_zero_length_test "unit;event;udp")

  if(LINUX)
    waterwall_add_native_executable(wlibc_write_file_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wlibc_write_file_test.c)
    target_link_libraries(wlibc_write_file_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests wlibc_write_file_test)

    add_waterwall_unit_test(waterwall.wlibc_write_file_unit wlibc_write_file_test "unit;libc;file")

    waterwall_add_native_executable(capture_linux_nfqueue_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_linux_nfqueue_test.c)
  target_link_libraries(capture_linux_nfqueue_test PRIVATE ww_test_support)
    target_link_libraries(capture_linux_nfqueue_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests capture_linux_nfqueue_test)

    add_waterwall_unit_test(
      waterwall.capture_linux_nfqueue_unit
      capture_linux_nfqueue_test
      "unit;net;capture;nfqueue"
    )

    # Generic deadline-aware command supervisor. wproc.c is compiled directly so
    # the linker wrap still intercepts the capture-buffer allocation it performs.
    waterwall_add_native_executable(wproc_deadline_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wproc_deadline_test.c
      ${CMAKE_SOURCE_DIR}/ww/base/wproc.c)
  target_link_libraries(wproc_deadline_test PRIVATE ww_test_support)
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
    waterwall_add_native_executable(capture_linux_command_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_linux_command_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_io.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_nfqueue.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_rules.c)
  target_link_libraries(capture_linux_command_test PRIVATE ww_test_support)
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

    waterwall_add_native_executable(tun_linux_command_test SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_linux_command_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux_config.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux_io.c)
    target_link_options(tun_linux_command_test PRIVATE
      "-Wl,--wrap=procRunArgvWithDeadline"
      "-Wl,--wrap=procCommandResultDrop"
    )
    target_link_libraries(tun_linux_command_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests tun_linux_command_test)
    add_waterwall_unit_test(waterwall.tun_linux_command_unit tun_linux_command_test
      "unit;net;tun;process;deadline")

    waterwall_add_native_executable(tun_linux_dns_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_linux_dns_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux_config.c)
  target_link_libraries(tun_linux_dns_test PRIVATE ww_test_support)
    target_link_options(tun_linux_dns_test PRIVATE
      "-Wl,--wrap=procRunArgvWithDeadline"
      "-Wl,--wrap=procCommandResultDrop"
      "-Wl,--wrap=ioctl")
    target_link_libraries(tun_linux_dns_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests tun_linux_dns_test)
    add_waterwall_unit_test(waterwall.tun_linux_dns_unit tun_linux_dns_test
      "unit;net;tun;dns;shutdown")

    if(PYTHON3_EXECUTABLE)
      add_test(NAME waterwall.tun_linux_dns_bus_unit
        COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tun_linux_dns_bus_test.py"
          --build-dir "${CMAKE_BINARY_DIR}" --config "$<CONFIG>"
          --cmake "${CMAKE_COMMAND}" --source-dir "${CMAKE_SOURCE_DIR}"
          --fixture-dir "${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
          --test-name waterwall.tun_linux_dns_bus_unit "$<TARGET_FILE:tun_linux_dns_test>")
      set_tests_properties(waterwall.tun_linux_dns_bus_unit PROPERTIES
        TIMEOUT 215 SKIP_RETURN_CODE 77 LABELS "unit;net;tun;dns;process"
        RESOURCE_LOCK waterwall_unit_test_build)
    endif()

    waterwall_add_native_executable(tundevice_policy_cleanup_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tundevice_policy_cleanup_test.c)
  target_link_libraries(tundevice_policy_cleanup_test PRIVATE ww_test_support)
    target_include_directories(tundevice_policy_cleanup_test PRIVATE
      "${PROJECT_SOURCE_DIR}/tunnels/TunDevice/include/TunDevice")
    target_link_libraries(tundevice_policy_cleanup_test PRIVATE ww)
    set_target_properties(tundevice_policy_cleanup_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
    add_dependencies(waterwall_unit_tests tundevice_policy_cleanup_test)
    add_waterwall_unit_test(waterwall.tundevice_policy_cleanup_unit tundevice_policy_cleanup_test
      "unit;tunnels;tun;shutdown")

    # Capture stop-pipe lifecycle. capture_linux.c is compiled directly and the
    # generic runner is wrapped, so BringUp/BringDown run for real while no
    # iptables rule, sysctl, NFQUEUE socket or root privilege is involved.
    waterwall_add_native_executable(capture_linux_pipe_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_linux_pipe_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_io.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_nfqueue.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_rules.c)
  target_link_libraries(capture_linux_pipe_test PRIVATE ww_test_support)
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
    waterwall_add_native_executable(tun_linux_message_lifetime_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_linux_message_lifetime_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_session.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_budget.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_dispatch.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_writer_channel.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux_config.c
      ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux_io.c)
  target_link_libraries(tun_linux_message_lifetime_test PRIVATE ww_test_support)
    target_compile_definitions(tun_linux_message_lifetime_test PRIVATE DEVICE_WRITER_CHANNEL_TEST_HOOKS=1)
    target_link_options(tun_linux_message_lifetime_test PRIVATE
      "-Wl,--wrap=chanTryRecv"
      "-Wl,--wrap=procRunArgvWithDeadline"
      "-Wl,--wrap=open"
      "-Wl,--wrap=ioctl"
      "-Wl,--wrap=socket"
      "-Wl,--wrap=read"
      "-Wl,--wrap=write"
      "-Wl,--wrap=writev"
      "-Wl,--wrap=poll"
      "-Wl,--wrap=tunLinuxGsoMaxSegmentsConfigure"
      "-Wl,--wrap=tunLinuxOffloadPrepareSegment"
      "-Wl,--wrap=tunLinuxOffloadCompleteChecksum"
      "-Wl,--wrap=deviceReaderSessionEnableWorkerQueue"
      "-Wl,--wrap=deviceReaderSessionConfigureOutputBudget"
      "-Wl,--wrap=tunConfigureWorkerGso"
      "-Wl,--wrap=fcntl"
      "-Wl,--wrap=sbufTryCreateWithPadding"
      "-Wl,--wrap=sbufDestroy"
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

    waterwall_add_native_executable(tun_linux_offload_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_linux_offload_test.c)
  target_link_libraries(tun_linux_offload_test PRIVATE ww_test_support)
    target_link_libraries(tun_linux_offload_test PRIVATE ww)
    target_link_options(tun_linux_offload_test PRIVATE "-Wl,--wrap=calcGenericChecksum")
    add_dependencies(waterwall_unit_tests tun_linux_offload_test)
    add_waterwall_unit_test(
      waterwall.tun_linux_offload_unit
      tun_linux_offload_test
      "unit;net;tun;linux;offload"
    )

    if(TARGET TunDevice)
      waterwall_add_native_executable(tundevice_gso_configuration_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tundevice_gso_configuration_test.c)
  target_link_libraries(tundevice_gso_configuration_test PRIVATE ww_test_support)
      target_link_libraries(tundevice_gso_configuration_test PRIVATE TunDevice)
      add_dependencies(waterwall_unit_tests tundevice_gso_configuration_test)
      add_waterwall_unit_test(
        waterwall.tundevice_gso_configuration_unit
        tundevice_gso_configuration_test
        "unit;net;tun;linux;configuration"
      )

      # Compile the small tunnel wrapper directly so the test can inject one
      # lower-layer refusal and verify it does not add a duplicate diagnostic.
      waterwall_add_native_executable(tundevice_writer_refusal_log_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tundevice_writer_refusal_log_test.c
        ${CMAKE_SOURCE_DIR}/tunnels/TunDevice/common/helpers.c)
  target_link_libraries(tundevice_writer_refusal_log_test PRIVATE ww_test_support)
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

    waterwall_add_native_executable(capture_linux_message_lifetime_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_linux_message_lifetime_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_session.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_budget.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_dispatch.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_io.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_nfqueue.c
      ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_rules.c)
  target_link_libraries(capture_linux_message_lifetime_test PRIVATE ww_test_support)
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

    waterwall_add_native_executable(raw_linux_writer_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/raw_linux_writer_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_writer_channel.c
      ${CMAKE_SOURCE_DIR}/ww/devices/raw/raw_linux.c)
  target_link_libraries(raw_linux_writer_test PRIVATE ww_test_support)
    target_compile_definitions(raw_linux_writer_test PRIVATE DEVICE_WRITER_CHANNEL_TEST_HOOKS=1)
    target_link_options(raw_linux_writer_test PRIVATE
      "-Wl,--wrap=rawLinuxNotrackInstall"
      "-Wl,--wrap=rawLinuxNotrackRemove"
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

    waterwall_add_native_executable(raw_linux_notrack_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/raw_linux_notrack_test.c)
  target_link_libraries(raw_linux_notrack_test PRIVATE ww_test_support)
    target_link_libraries(raw_linux_notrack_test PRIVATE ww)
    target_link_options(raw_linux_notrack_test PRIVATE
      "-Wl,--wrap=procRunArgvWithDeadline"
      "-Wl,--wrap=setsockopt"
      "-Wl,--wrap=fastRand32"
      "-Wl,--wrap=fastRand64"
    )
    add_dependencies(waterwall_unit_tests raw_linux_notrack_test)
    add_waterwall_unit_test(
      waterwall.raw_linux_notrack_unit
      raw_linux_notrack_test
      "unit;net;raw;linux;conntrack"
    )

    # Wraps send/sendto for a deterministic EAGAIN/EINTR/ENOBUFS seam.
    waterwall_add_native_executable(udp_datagram_write_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/udp_datagram_write_test.c)
  target_link_libraries(udp_datagram_write_test PRIVATE ww_test_support)
    target_link_libraries(udp_datagram_write_test PRIVATE ww)
    target_link_options(udp_datagram_write_test PRIVATE
      "-Wl,--wrap=splice" "-Wl,--wrap=read"
      "-Wl,--wrap=sendto"
      "-Wl,--wrap=send"
    )
    add_dependencies(waterwall_unit_tests udp_datagram_write_test)

    add_waterwall_unit_test(
      waterwall.udp_datagram_write_unit
      udp_datagram_write_test
      "unit;event;udp;datagram"
    )

    waterwall_add_native_executable(udp_datagram_write_no_splice_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/udp_datagram_write_test.c
      ${CMAKE_SOURCE_DIR}/ww/event/udp_send.c)
  target_link_libraries(udp_datagram_write_no_splice_test PRIVATE ww_test_support)
    target_compile_definitions(udp_datagram_write_no_splice_test PRIVATE WW_HAVE_SPLICE=0)
    target_link_libraries(udp_datagram_write_no_splice_test PRIVATE ww)
    target_link_options(udp_datagram_write_no_splice_test PRIVATE "-Wl,--wrap=sendto" "-Wl,--wrap=send")
    add_dependencies(waterwall_unit_tests udp_datagram_write_no_splice_test)
    add_waterwall_unit_test(waterwall.udp_datagram_write_no_splice_unit udp_datagram_write_no_splice_test
      "unit;event;udp;datagram;no-splice")

    waterwall_add_native_executable(select_fd_range_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/event/select_fd_range_test.c
      ${CMAKE_SOURCE_DIR}/ww/event/select.c)
  target_link_libraries(select_fd_range_test PRIVATE ww_test_support)
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

    waterwall_add_native_executable(select_registration_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/event/select_registration_failure_test.c
      ${CMAKE_SOURCE_DIR}/ww/event/wloop.c
      ${CMAKE_SOURCE_DIR}/ww/event/nio.c
      ${CMAKE_SOURCE_DIR}/ww/event/select.c)
  target_link_libraries(select_registration_failure_test PRIVATE ww_test_support)
    target_compile_definitions(select_registration_failure_test PRIVATE EVENT_SELECT=1)
    target_link_options(select_registration_failure_test PRIVATE "-Wl,--wrap=connect" "-Wl,--wrap=eventfd")
    target_link_libraries(select_registration_failure_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests select_registration_failure_test)

    add_waterwall_unit_test(
      waterwall.select_registration_failure_unit
      select_registration_failure_test
      "unit;event;select;registration;lifetime"
    )

    waterwall_add_native_executable(signal_manager_registration_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/signal_manager_registration_failure_test.c
      ${CMAKE_SOURCE_DIR}/ww/managers/signal_manager.c)
  target_link_libraries(signal_manager_registration_failure_test PRIVATE ww_test_support)
    target_link_options(signal_manager_registration_failure_test PRIVATE "-Wl,--wrap=wRead")
    target_link_libraries(signal_manager_registration_failure_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests signal_manager_registration_failure_test)

    add_waterwall_unit_test(
      waterwall.signal_manager_registration_failure_unit
      signal_manager_registration_failure_test
      "unit;signal-manager;startup;failure"
    )

    waterwall_add_native_executable(wloop_stop_request_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/event/wloop_stop_request_test.c)
  target_link_libraries(wloop_stop_request_test PRIVATE ww_test_support)
    target_link_options(wloop_stop_request_test PRIVATE "-Wl,--wrap=send" "-Wl,--wrap=wloopInvokeWriteCallback")
    target_link_libraries(wloop_stop_request_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests wloop_stop_request_test)

    add_waterwall_unit_test(
      waterwall.wloop_stop_request_unit
      wloop_stop_request_test
      "unit;event;shutdown;worker;lifetime"
    )

    foreach(wloop_wakeup_backend IN ITEMS pipe socketpair)
      set(wloop_wakeup_target "wloop_wakeup_${wloop_wakeup_backend}_test")
      waterwall_add_native_executable(${wloop_wakeup_target} SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/event/wloop_wakeup_coalescing_test.c
        ${CMAKE_SOURCE_DIR}/ww/event/wloop.c
        ${CMAKE_SOURCE_DIR}/ww/event/nio.c
        ${CMAKE_SOURCE_DIR}/ww/event/select.c)
  target_link_libraries(${wloop_wakeup_target} PRIVATE ww_test_support)
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
      waterwall_add_native_executable(shutdown_manager_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/shutdown_manager_test.c)
  target_link_libraries(shutdown_manager_test PRIVATE ww_test_support)
      target_compile_definitions(ww PUBLIC APPLICATION_SHUTDOWN_TEST_HOOKS=1)
      target_compile_definitions(shutdown_manager_test PRIVATE APPLICATION_SHUTDOWN_TEST_HOOKS=1)
      target_link_libraries(shutdown_manager_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests shutdown_manager_test)

      add_waterwall_unit_test(
        waterwall.shutdown_manager_unit
        shutdown_manager_test
        "unit;signal-manager;shutdown;worker;lifetime"
      )

      waterwall_add_native_executable(shutdown_signal_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/shutdown_signal_test.c)
  target_link_libraries(shutdown_signal_test PRIVATE ww_test_support)
      target_compile_definitions(ww PUBLIC SIGNAL_MANAGER_TEST_HOOKS=1)
      target_compile_definitions(shutdown_signal_test PRIVATE SIGNAL_MANAGER_TEST_HOOKS=1)
      target_link_libraries(shutdown_signal_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests shutdown_signal_test)

      add_waterwall_unit_test(
        waterwall.shutdown_signal_unit
        shutdown_signal_test
        "unit;signal-manager;shutdown;signals"
      )

      waterwall_add_native_executable(node_manager_stop_once_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/node_manager_stop_once_test.c)
  target_link_libraries(node_manager_stop_once_test PRIVATE ww_test_support)
      target_link_libraries(node_manager_stop_once_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests node_manager_stop_once_test)

      add_waterwall_unit_test(
        waterwall.node_manager_stop_once_unit
        node_manager_stop_once_test
        "unit;node-manager;shutdown;lifetime"
      )

      waterwall_add_native_executable(node_manager_map_invariant_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/node_manager_map_invariant_test.c)
  target_link_libraries(node_manager_map_invariant_test PRIVATE ww_test_support)
      target_link_libraries(node_manager_map_invariant_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests node_manager_map_invariant_test)

      add_waterwall_unit_test(
        waterwall.node_manager_map_invariant_unit
        node_manager_map_invariant_test
        "unit;node-manager;configuration;capacity;lifetime"
      )

      waterwall_add_native_executable(node_layer_validation_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/node_layer_validation_test.c)
  target_link_libraries(node_layer_validation_test PRIVATE ww_test_support)
      target_link_libraries(node_layer_validation_test PRIVATE ww)
      if(TARGET MuxClient AND TARGET MuxServer AND TARGET TcpListener AND TARGET TcpConnector)
        target_link_libraries(node_layer_validation_test PRIVATE MuxClient MuxServer TcpListener TcpConnector)
        target_compile_definitions(node_layer_validation_test PRIVATE WW_TEST_REAL_TCP_MUX_NODES=1)
      endif()
      if(TARGET HeaderClient AND TARGET Bridge AND TARGET UserController AND TARGET BlackHole
         AND TARGET ReverseClient AND TARGET JunkDatagramSender)
        target_link_libraries(node_layer_validation_test PRIVATE HeaderClient Bridge UserController BlackHole ReverseClient JunkDatagramSender)
        target_compile_definitions(node_layer_validation_test PRIVATE WW_TEST_EASY_SPLICE_NODES=1)
      endif()
      if(TARGET UdpListener AND TARGET UdpConnector AND TARGET UdpStatelessSocket
         AND TARGET TcpUdpListener AND TARGET TcpUdpConnector)
        target_link_libraries(node_layer_validation_test PRIVATE UdpListener UdpConnector UdpStatelessSocket
          TcpUdpListener TcpUdpConnector TcpListener TcpConnector)
        target_compile_definitions(node_layer_validation_test PRIVATE WW_TEST_UDP_SPLICE_NODES=1)
      endif()
      add_dependencies(waterwall_unit_tests node_layer_validation_test)

      add_waterwall_unit_test(
        waterwall.node_layer_validation_unit
        node_layer_validation_test
        "unit;node-manager;validation;layer;capabilities"
      )

      # Exercise unsupported-platform eligibility using the same production chain implementation.
      waterwall_add_native_executable(node_layer_validation_no_splice_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/node_layer_validation_test.c
        ${CMAKE_SOURCE_DIR}/ww/net/chain.c)
  target_link_libraries(node_layer_validation_no_splice_test PRIVATE ww_test_support)
      target_compile_definitions(node_layer_validation_no_splice_test PRIVATE WW_HAVE_SPLICE=0)
      target_link_libraries(node_layer_validation_no_splice_test PRIVATE ww)
      if(TARGET MuxClient AND TARGET MuxServer AND TARGET TcpListener AND TARGET TcpConnector)
        target_link_libraries(node_layer_validation_no_splice_test PRIVATE MuxClient MuxServer TcpListener TcpConnector)
        target_compile_definitions(node_layer_validation_no_splice_test PRIVATE WW_TEST_REAL_TCP_MUX_NODES=1)
      endif()
      if(TARGET HeaderClient AND TARGET Bridge AND TARGET UserController AND TARGET BlackHole
         AND TARGET ReverseClient AND TARGET JunkDatagramSender)
        target_link_libraries(node_layer_validation_no_splice_test PRIVATE HeaderClient Bridge UserController BlackHole ReverseClient JunkDatagramSender)
        target_compile_definitions(node_layer_validation_no_splice_test PRIVATE WW_TEST_EASY_SPLICE_NODES=1)
      endif()
      if(TARGET UdpListener AND TARGET UdpConnector AND TARGET UdpStatelessSocket
         AND TARGET TcpUdpListener AND TARGET TcpUdpConnector)
        target_link_libraries(node_layer_validation_no_splice_test PRIVATE UdpListener UdpConnector UdpStatelessSocket
          TcpUdpListener TcpUdpConnector TcpListener TcpConnector)
        target_compile_definitions(node_layer_validation_no_splice_test PRIVATE WW_TEST_UDP_SPLICE_NODES=1)
      endif()
      if(TARGET HalfDuplexClient AND TARGET HalfDuplexServer)
        foreach(target IN ITEMS node_layer_validation_test node_layer_validation_no_splice_test)
          target_link_libraries(${target} PRIVATE HalfDuplexClient HalfDuplexServer)
          target_compile_definitions(${target} PRIVATE WW_TEST_HALFDUPLEX_SPLICE_NODES=1)
        endforeach()
      endif()
      if(TARGET Router AND TARGET SniffRouter)
        foreach(target IN ITEMS node_layer_validation_test node_layer_validation_no_splice_test)
          target_link_libraries(${target} PRIVATE Router SniffRouter)
          target_compile_definitions(${target} PRIVATE WW_TEST_ROUTER_SPLICE_NODES=1)
        endforeach()
      endif()
      if(TARGET ReverseServer AND TARGET Bridge)
        foreach(target IN ITEMS node_layer_validation_test node_layer_validation_no_splice_test)
          target_link_libraries(${target} PRIVATE ReverseServer Bridge)
          target_compile_definitions(${target} PRIVATE WW_TEST_REVERSE_SERVER_SPLICE=1)
        endforeach()
      endif()
      if(TARGET Socks5Client AND TARGET Socks5Server AND TARGET DomainResolver)
        foreach(target IN ITEMS node_layer_validation_test node_layer_validation_no_splice_test)
          target_link_libraries(${target} PRIVATE Socks5Client Socks5Server DomainResolver)
          target_compile_definitions(${target} PRIVATE WW_TEST_SOCKS_SPLICE_NODES=1)
        endforeach()
      endif()
      if(TARGET HeaderServer AND TARGET KeepAliveClient AND TARGET KeepAliveServer)
        foreach(target IN ITEMS node_layer_validation_test node_layer_validation_no_splice_test)
          target_link_libraries(${target} PRIVATE HeaderServer KeepAliveClient KeepAliveServer)
          target_compile_definitions(${target} PRIVATE WW_TEST_FRAMED_SPLICE_NODES=1)
        endforeach()
      endif()
      add_dependencies(waterwall_unit_tests node_layer_validation_no_splice_test)

      add_waterwall_unit_test(
        waterwall.node_layer_validation_no_splice_unit
        node_layer_validation_no_splice_test
        "unit;node-manager;validation;layer;capabilities"
      )
    endif()

    waterwall_add_native_executable(thread_creation_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/thread_creation_failure_test.c)
  target_link_libraries(thread_creation_failure_test PRIVATE ww_test_support)
    target_link_options(thread_creation_failure_test PRIVATE "-Wl,--wrap=pthread_create")
    target_link_libraries(thread_creation_failure_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests thread_creation_failure_test)

    add_waterwall_unit_test(
      waterwall.thread_creation_failure_unit
      thread_creation_failure_test
      "unit;thread;startup;failure"
    )

    waterwall_add_native_executable(worker_identity_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/worker_identity_test.c)
  target_link_libraries(worker_identity_test PRIVATE ww_test_support)
    target_link_libraries(worker_identity_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests worker_identity_test)

    add_waterwall_unit_test(
      waterwall.worker_identity_unit
      worker_identity_test
      "unit;worker;identity;threads"
    )

    waterwall_add_native_executable(worker_context_helpers_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/worker_context_helpers_test.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/worker_fixture.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/worker_accessors_cases.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/worker_messages_cases.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/worker_teardown_cases.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/pipe_tunnel_cases.c
    ${WATERWALL_UNIT_SOURCE_ROOT}/net/worker/halfduplex_workers_cases.c
      ${CMAKE_SOURCE_DIR}/ww/instance/worker_messages.c
      ${CMAKE_SOURCE_DIR}/ww/net/pipe_tunnel.c)
  set_target_properties(worker_context_helpers_test PROPERTIES UNITY_BUILD OFF)
    target_link_libraries(worker_context_helpers_test PRIVATE ww_test_support)
    target_compile_definitions(worker_context_helpers_test PRIVATE
      WW_WORKER_MESSAGE_TEST_SEAM=1
      WW_PIPE_TUNNEL_TEST_SEAM=1
      WW_EVENT_MEMORY_TEST_SEAM=1
    )
    if(NOT MSVC)
      target_compile_definitions(worker_context_helpers_test PRIVATE WW_WORKER_MESSAGE_LINK_WRAP=1)
      target_link_options(worker_context_helpers_test PRIVATE
        "-Wl,--wrap=wloopPostEvent"
        "-Wl,--wrap=signalmanagerRequestShutdownPreservingAcceptedStatus"
      )
    endif()
    target_link_libraries(worker_context_helpers_test PRIVATE ww)
    if(TARGET HalfDuplexServer)
      target_link_libraries(worker_context_helpers_test PRIVATE HalfDuplexServer)
      target_compile_definitions(worker_context_helpers_test PRIVATE WW_TEST_HALFDUPLEX_WORKERS=1)
    endif()
    target_link_options(worker_context_helpers_test PRIVATE "-Wl,--wrap=sbufDestroy" "-Wl,--wrap=bufferpoolReuseBuffer")
  add_dependencies(waterwall_unit_tests worker_context_helpers_test)

    add_waterwall_unit_test(
      waterwall.worker_context_helpers_unit
      worker_context_helpers_test
      "unit;worker;identity;messages;buffers"
    )

    waterwall_add_native_executable(line_task_scheduling_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/line_task_scheduling_test.c
      ${CMAKE_SOURCE_DIR}/ww/instance/worker_messages.c)
  target_link_libraries(line_task_scheduling_test PRIVATE ww_test_support)
    target_compile_definitions(line_task_scheduling_test PRIVATE
      WW_WORKER_MESSAGE_TEST_SEAM=1
      WW_EVENT_MEMORY_TEST_SEAM=1
    )
    target_link_libraries(line_task_scheduling_test PRIVATE ww)
    target_link_options(line_task_scheduling_test PRIVATE "-Wl,--wrap=sbufDestroy" "-Wl,--wrap=bufferpoolReuseBuffer")
  add_dependencies(waterwall_unit_tests line_task_scheduling_test)

    add_waterwall_unit_test(
      waterwall.line_task_scheduling_unit
      line_task_scheduling_test
      "unit;net;line;worker;messages;buffers;cancellation;concurrency"
    )

    if(TARGET RawSocket)
      waterwall_add_native_executable(rawsocket_config_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rawsocket/rawsocket_config_test.c)
      target_link_libraries(rawsocket_config_test PRIVATE RawSocket ww)
      add_dependencies(waterwall_unit_tests rawsocket_config_test)

      add_waterwall_unit_test(
        waterwall.rawsocket_config_unit
        rawsocket_config_test
        "unit;net;rawsocket;config"
      )

      waterwall_add_native_executable(rawsocket_startup_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rawsocket/rawsocket_startup_failure_test.c
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/instance/start.c)
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

      waterwall_add_native_executable(rawsocket_write_only_startup_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/rawsocket/rawsocket_write_only_startup_test.c
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/instance/start.c
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/instance/stop.c
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/instance/destroy.c)
      target_include_directories(rawsocket_write_only_startup_test PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/include
        ${CMAKE_SOURCE_DIR}/tunnels/RawSocket/include/RawSocket
      )
      target_link_options(rawsocket_write_only_startup_test PRIVATE
        "-Wl,--wrap=caputredeviceCreate"
        "-Wl,--wrap=caputredeviceBringUp"
        "-Wl,--wrap=capturedeviceRequestStop"
        "-Wl,--wrap=caputredeviceBringDown"
        "-Wl,--wrap=capturedeviceDestroy"
        "-Wl,--wrap=rawdeviceCreate"
        "-Wl,--wrap=rawdeviceBringUp"
        "-Wl,--wrap=rawdeviceRequestStop"
        "-Wl,--wrap=rawdeviceBringDown"
        "-Wl,--wrap=rawdeviceDestroy"
      )
      target_link_libraries(rawsocket_write_only_startup_test PRIVATE ww)
      add_dependencies(waterwall_unit_tests rawsocket_write_only_startup_test)

      add_waterwall_unit_test(
        waterwall.rawsocket_write_only_startup_unit
        rawsocket_write_only_startup_test
        "unit;net;rawsocket;startup;write-only"
      )
    endif()

    waterwall_add_native_executable(os_helpers_bbr_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/os_helpers_bbr_test.c
      ${CMAKE_SOURCE_DIR}/core/os_helpers.c)
  target_link_libraries(os_helpers_bbr_test PRIVATE ww_test_support)
    target_include_directories(os_helpers_bbr_test PRIVATE ${CMAKE_SOURCE_DIR}/core)
    target_link_libraries(os_helpers_bbr_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests os_helpers_bbr_test)

    add_waterwall_unit_test(
      waterwall.os_helpers_bbr_unit
      os_helpers_bbr_test
      "unit;core;linux;bbr"
    )

    waterwall_add_native_executable(os_helpers_tcp_tune_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/os_helpers_tcp_tune_test.c
      ${CMAKE_SOURCE_DIR}/core/os_helpers.c)
  target_link_libraries(os_helpers_tcp_tune_test PRIVATE ww_test_support)
    target_include_directories(os_helpers_tcp_tune_test PRIVATE ${CMAKE_SOURCE_DIR}/core)
    target_link_libraries(os_helpers_tcp_tune_test PRIVATE ww)
    target_link_options(os_helpers_tcp_tune_test PRIVATE "-Wl,--wrap=sysinfo" "-Wl,--wrap=sysconf")
    add_dependencies(waterwall_unit_tests os_helpers_tcp_tune_test)
    add_waterwall_unit_test(
      waterwall.os_helpers_tcp_tune_unit
      os_helpers_tcp_tune_test
      "unit;core;linux;tcp;startup"
    )

    waterwall_add_native_executable(os_helpers_pipe_limit_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/os_helpers_pipe_limit_test.c
      ${CMAKE_SOURCE_DIR}/core/os_helpers.c)
  target_link_libraries(os_helpers_pipe_limit_test PRIVATE ww_test_support)
    target_include_directories(os_helpers_pipe_limit_test PRIVATE ${CMAKE_SOURCE_DIR}/core)
    target_link_libraries(os_helpers_pipe_limit_test PRIVATE ww)
    target_link_options(os_helpers_pipe_limit_test PRIVATE "-Wl,--wrap=sysconf")
    add_dependencies(waterwall_unit_tests os_helpers_pipe_limit_test)
    add_waterwall_unit_test(
      waterwall.os_helpers_pipe_limit_unit
      os_helpers_pipe_limit_test
      "unit;core;linux;pipe;startup"
    )

    waterwall_add_native_executable(global_crypto_startup_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/global_crypto_startup_failure_test.c
      ${CMAKE_SOURCE_DIR}/ww/instance/global_state.c)
  target_link_libraries(global_crypto_startup_failure_test PRIVATE ww_test_support)
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
      waterwall_add_native_executable(openssl_partial_init_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/openssl_partial_init_failure_test.c)
  target_link_libraries(openssl_partial_init_failure_test PRIVATE ww_test_support)
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
