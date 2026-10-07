# Explicit runtime/native target groups; included inside the ww target condition.
  waterwall_add_native_executable(restricted_config_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/core/restricted_config_test.c)
  target_link_libraries(restricted_config_test PRIVATE ww_test_support)
  target_link_libraries(restricted_config_test PRIVATE ww)
  if(LINUX)
    target_compile_definitions(restricted_config_test PRIVATE WW_TEST_WRAP_DLOPEN=1)
    target_link_options(restricted_config_test PRIVATE "-Wl,--wrap=dlopen")
  endif()
  add_dependencies(waterwall_unit_tests restricted_config_test)
  add_waterwall_unit_test(waterwall.restricted_config_unit restricted_config_test "unit;configuration;security;portable")

  waterwall_add_native_executable(capture_windows_lifetime_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_windows_lifetime_test.c)
  target_link_libraries(capture_windows_lifetime_test PRIVATE ww_test_support)
  target_include_directories(capture_windows_lifetime_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/capture)
  target_link_libraries(capture_windows_lifetime_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests capture_windows_lifetime_test)

  add_waterwall_unit_test(
    waterwall.capture_windows_lifetime_unit
    capture_windows_lifetime_test
    "unit;net;capture;windows;lifetime"
  )

  waterwall_add_native_executable(capture_lifecycle_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_lifecycle_test.c)
  target_link_libraries(capture_lifecycle_test PRIVATE ww_test_support)
  target_include_directories(capture_lifecycle_test PRIVATE ${CMAKE_SOURCE_DIR}/ww)
  target_link_libraries(capture_lifecycle_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests capture_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.capture_lifecycle_unit
    capture_lifecycle_test
    "unit;net;capture;lifecycle"
  )

  waterwall_add_native_executable(tun_windows_lifetime_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_windows_lifetime_test.c)
  target_link_libraries(tun_windows_lifetime_test PRIVATE ww_test_support)
  target_include_directories(tun_windows_lifetime_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/tun)
  target_link_libraries(tun_windows_lifetime_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tun_windows_lifetime_test)

  add_waterwall_unit_test(
    waterwall.tun_windows_lifetime_unit
    tun_windows_lifetime_test
    "unit;net;tun;windows;lifetime"
  )

  waterwall_add_native_executable(tun_lifecycle_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_lifecycle_test.c)
  target_link_libraries(tun_lifecycle_test PRIVATE ww_test_support)
  target_include_directories(tun_lifecycle_test PRIVATE ${CMAKE_SOURCE_DIR}/ww)
  target_link_libraries(tun_lifecycle_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tun_lifecycle_test)

  add_waterwall_unit_test(
    waterwall.tun_lifecycle_unit
    tun_lifecycle_test
    "unit;net;tun;lifecycle"
  )

  waterwall_add_native_executable(quiescence_gate_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/quiescence_gate_test.c)
  target_link_libraries(quiescence_gate_test PRIVATE ww_test_support)
  target_include_directories(quiescence_gate_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/base ${CMAKE_SOURCE_DIR}/ww/devices)
  target_compile_definitions(quiescence_gate_test PRIVATE QUIESCENCE_GATE_TEST_HOOKS=1)
  target_link_libraries(quiescence_gate_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests quiescence_gate_test)

  add_waterwall_unit_test(
    waterwall.quiescence_gate_unit
    quiescence_gate_test
    "unit;base;quiescence;gate;lifetime"
  )

  waterwall_add_native_executable(device_flow_affinity_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/device_flow_affinity_test.c)
  target_link_libraries(device_flow_affinity_test PRIVATE ww_test_support)
  target_link_libraries(device_flow_affinity_test PRIVATE ww)
  if(LINUX)
    target_compile_definitions(device_flow_affinity_test PRIVATE DEVICE_FLOW_AFFINITY_TEST_TRACKING=1)
    target_link_options(device_flow_affinity_test PRIVATE
      "-Wl,--wrap=bufferpoolReuseBuffer"
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
    waterwall_add_native_executable(buffer_pool_thread_transfer_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/buffer_pool_thread_transfer_test.c)
  target_link_libraries(buffer_pool_thread_transfer_test PRIVATE ww_test_support)
    target_link_libraries(buffer_pool_thread_transfer_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests buffer_pool_thread_transfer_test)

    add_waterwall_unit_test(
      waterwall.buffer_pool_thread_transfer_unit
      buffer_pool_thread_transfer_test
      "unit;bufio;lifetime;thread"
    )

    waterwall_add_native_executable(lwip_shutdown_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_shutdown_test.c)
  target_link_libraries(lwip_shutdown_test PRIVATE ww_test_support)
    target_link_libraries(lwip_shutdown_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests lwip_shutdown_test)

    add_waterwall_unit_test(
      waterwall.lwip_shutdown_unit
      lwip_shutdown_test
      "unit;net;lwip;lifetime;shutdown"
    )

    waterwall_add_native_executable(lwip_random_isn_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_random_isn_test.c)
  target_link_libraries(lwip_random_isn_test PRIVATE ww_test_support)
    target_link_libraries(lwip_random_isn_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests lwip_random_isn_test)

    add_waterwall_unit_test(
      waterwall.lwip_random_isn_unit
      lwip_random_isn_test
      "unit;net;lwip;random;tcp;isn;security"
    )

    waterwall_add_native_executable(device_reader_session_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/device_reader_session_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_session.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_budget.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_reader_dispatch.c)
  target_link_libraries(device_reader_session_test PRIVATE ww_test_support)
    target_link_options(device_reader_session_test PRIVATE
      "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
      "-Wl,--wrap=memoryFree"
      "-Wl,--wrap=masterpoolDestroy"
      "-Wl,--wrap=bufferpoolReuseBuffer"
    )
    target_compile_definitions(device_reader_session_test PRIVATE DEVICE_READER_SESSION_TEST_HOOKS=1)
    target_link_libraries(device_reader_session_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests device_reader_session_test)

    add_waterwall_unit_test(
      waterwall.device_reader_session_unit
      device_reader_session_test
      "unit;net;device;lifetime;reader"
    )

    waterwall_add_native_executable(device_writer_channel_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/device_writer_channel_test.c
      ${CMAKE_SOURCE_DIR}/ww/devices/device_writer_channel.c)
  target_link_libraries(device_writer_channel_test PRIVATE ww_test_support)
    target_compile_definitions(device_writer_channel_test PRIVATE DEVICE_WRITER_CHANNEL_TEST_HOOKS=1)
    target_link_libraries(device_writer_channel_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests device_writer_channel_test)

    add_waterwall_unit_test(
      waterwall.device_writer_channel_unit
      device_writer_channel_test
      "unit;net;device;lifetime;writer"
    )
  endif()

  waterwall_add_native_executable(lwip_pretend_udp_dispatch_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_pretend_udp_dispatch_test.c)
  target_link_libraries(lwip_pretend_udp_dispatch_test PRIVATE ww_test_support)
  target_link_libraries(lwip_pretend_udp_dispatch_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests lwip_pretend_udp_dispatch_test)

  add_waterwall_unit_test(
    waterwall.lwip_pretend_udp_dispatch_unit
    lwip_pretend_udp_dispatch_test
    "unit;net;lwip;udp;pretend;ownership"
  )

  waterwall_add_native_executable(wchan_close_semantics_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/wchan_close_semantics_test.c
    ${CMAKE_SOURCE_DIR}/ww/base/wchan.c)
  target_link_libraries(wchan_close_semantics_test PRIVATE ww_test_support)
  target_compile_definitions(wchan_close_semantics_test PRIVATE WCHAN_TEST_HOOKS=1)
  target_link_libraries(wchan_close_semantics_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wchan_close_semantics_test)

  add_waterwall_unit_test(
    waterwall.wchan_close_semantics_unit
    wchan_close_semantics_test
    "unit;base;chan;lifetime;close"
  )

  waterwall_add_native_executable(tun_windows_receive_policy_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_windows_receive_policy_test.c)
  target_link_libraries(tun_windows_receive_policy_test PRIVATE ww_test_support)
  target_include_directories(tun_windows_receive_policy_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/tun)
  target_link_libraries(tun_windows_receive_policy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests tun_windows_receive_policy_test)

  add_waterwall_unit_test(
    waterwall.tun_windows_receive_policy_unit
    tun_windows_receive_policy_test
    "unit;net;tun;windows;receive;drop"
  )

  waterwall_add_native_executable(log_rate_limiter_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/log_rate_limiter_test.c)
  target_link_libraries(log_rate_limiter_test PRIVATE ww_test_support)
  target_link_libraries(log_rate_limiter_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests log_rate_limiter_test)

  add_waterwall_unit_test(
    waterwall.log_rate_limiter_unit
    log_rate_limiter_test
    "unit;logger;rate-limit"
  )

  waterwall_add_native_executable(raw_windows_send_policy_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/raw_windows_send_policy_test.c)
  target_link_libraries(raw_windows_send_policy_test PRIVATE ww_test_support)
  target_include_directories(raw_windows_send_policy_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/devices/raw)
  target_link_libraries(raw_windows_send_policy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests raw_windows_send_policy_test)

  add_waterwall_unit_test(
    waterwall.raw_windows_send_policy_unit
    raw_windows_send_policy_test
    "unit;net;raw;windows;send;failure"
  )

  waterwall_add_native_executable(sbuf_capacity_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/sbuf_capacity_test.c)
  target_link_libraries(sbuf_capacity_test PRIVATE ww_test_support)
  target_link_options(sbuf_capacity_test PRIVATE "-Wl,--wrap=memoryAllocateAligned")
  target_link_libraries(sbuf_capacity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests sbuf_capacity_test)

  add_waterwall_unit_test(
    waterwall.sbuf_capacity_unit
    sbuf_capacity_test
    "unit;bufio;sbuf;bufferpool;capacity;overflow"
  )

  waterwall_add_native_executable(bufio_contract_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/bufio_contract_test.c)
  target_link_libraries(bufio_contract_test PRIVATE ww_test_support)
  target_link_libraries(bufio_contract_test PRIVATE ww)
  if(LINUX)
    target_link_options(bufio_contract_test PRIVATE "-Wl,--wrap=read" "-Wl,--wrap=splice")
  endif()
  add_dependencies(waterwall_unit_tests bufio_contract_test)

  add_waterwall_unit_test(
    waterwall.bufio_contract_unit
    bufio_contract_test
    "unit;bufio;sbuf;buffer-stream;invariant"
  )

  if(LINUX)
    waterwall_add_native_executable(bufio_queue_failure_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/bufio_queue_failure_test.c)
    target_link_libraries(bufio_queue_failure_test PRIVATE ww)
    target_link_options(bufio_queue_failure_test PRIVATE
      "-Wl,--wrap=memoryReAllocate" "-Wl,--wrap=abortProgramNow")
    add_dependencies(waterwall_unit_tests bufio_queue_failure_test)
    add_waterwall_unit_test(waterwall.bufio_queue_failure_unit bufio_queue_failure_test
      "unit;bufio;buffer-stream;context-queue;failure")

    # Compile the actual stream and splice primitives with splice disabled.
    # Linking only the normal ww objects would not exercise these code paths.
    waterwall_add_native_executable(bufio_contract_no_splice_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/bufio/bufio_contract_test.c
      ${CMAKE_SOURCE_DIR}/ww/bufio/splice_stream.c
      ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_stream.c
      ${CMAKE_SOURCE_DIR}/ww/bufio/splice_buffer.c
      ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_pool.c
      ${CMAKE_SOURCE_DIR}/ww/bufio/shiftbuffer.c)
  target_link_libraries(bufio_contract_no_splice_test PRIVATE ww_test_support)
    target_compile_definitions(bufio_contract_no_splice_test PRIVATE WW_HAVE_SPLICE=0)
    target_link_libraries(bufio_contract_no_splice_test PRIVATE ww)
    add_dependencies(waterwall_unit_tests bufio_contract_no_splice_test)

    add_waterwall_unit_test(
      waterwall.bufio_contract_no_splice_unit
      bufio_contract_no_splice_test
      "unit;bufio;sbuf;buffer-stream;invariant;no-splice"
    )
  endif()

