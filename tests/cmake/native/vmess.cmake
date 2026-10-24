# VMess replay state has no event-loop dependency; concurrent callers exercise
# the same shared admission operation invoked by separate event workers.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET VmessServer)
  waterwall_add_native_executable(vmess_replay_test SUPPORT SOURCES
    "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/vmess/vmess_replay_test.c"
    "${CMAKE_SOURCE_DIR}/tunnels/VmessServer/common/replay.c"
    INCLUDES "${CMAKE_SOURCE_DIR}/tunnels/VmessServer/include"
      "${CMAKE_SOURCE_DIR}/tunnels/VmessServer/include/VmessServer"
    LIBRARIES ww)
  add_dependencies(waterwall_unit_tests vmess_replay_test)
  add_waterwall_unit_test(waterwall.vmess_replay_unit vmess_replay_test
    "unit;tunnels;vmess;authentication;replay;concurrency")

  waterwall_add_native_executable(vmess_crypto_test SUPPORT SOURCES
    "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/vmess/vmess_crypto_test.c"
    "${CMAKE_SOURCE_DIR}/tunnels/VmessServer/common/crypto.c"
    INCLUDES "${CMAKE_SOURCE_DIR}/tunnels/VmessServer/include"
      "${CMAKE_SOURCE_DIR}/tunnels/VmessServer/include/VmessServer"
    LIBRARIES ww OpenSSL::Crypto)
  add_dependencies(waterwall_unit_tests vmess_crypto_test)
  add_waterwall_unit_test(waterwall.vmess_crypto_unit vmess_crypto_test
    "unit;tunnels;vmess;crypto;framing;security")

  waterwall_add_native_executable(vmess_runtime_test SUPPORT SOURCES
    "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/vmess/vmess_runtime_test.c"
    ${WATERWALL_LINE_FAILURE_WW_SOURCES})
  waterwall_line_failure_test_use_tunnel(vmess_runtime_test VmessServer)
  target_link_options(vmess_runtime_test PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS} "-Wl,--wrap=gettimeofday"
    "-Wl,--wrap=vmessAuthIdCheck")
  target_link_libraries(vmess_runtime_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests vmess_runtime_test)
  add_waterwall_unit_test(waterwall.vmess_runtime_unit vmess_runtime_test
    "unit;tunnels;vmess;authentication;framing;lifetime;reentry;ownership")
endif()
