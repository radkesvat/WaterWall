# The shared codec is independently useful to either VMess endpoint.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET VmessCommon)
  waterwall_add_native_executable(vmess_crypto_test SUPPORT SOURCES
    "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/vmess/vmess_crypto_test.c"
    LIBRARIES ww VmessCommon)
  waterwall_add_native_executable(vmess_parser_fuzz_test SUPPORT SOURCES
    "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/vmess/vmess_parser_fuzz_test.c"
    LIBRARIES ww VmessCommon)
  add_dependencies(waterwall_unit_tests vmess_parser_fuzz_test)
  add_waterwall_unit_test(waterwall.vmess_parser_fuzz_unit vmess_parser_fuzz_test
    "unit;tunnels;vmess;parser;fuzz;security")
  add_dependencies(waterwall_unit_tests vmess_crypto_test)
  add_waterwall_unit_test(waterwall.vmess_crypto_unit vmess_crypto_test
    "unit;tunnels;vmess;crypto;framing;security")
endif()

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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET VmessClient)
  foreach(kind IN ITEMS runtime config)
    set(target "vmess_client_${kind}_test")
    waterwall_add_native_executable(${target} SUPPORT SOURCES
      "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/vmess/vmess_client_${kind}_test.c"
      ${WATERWALL_LINE_FAILURE_WW_SOURCES})
    waterwall_line_failure_test_use_tunnel(${target} VmessClient)
    target_link_options(${target} PRIVATE ${WATERWALL_LINE_FAILURE_WRAPS})
    target_link_libraries(${target} PRIVATE ww VmessCommon)
    add_dependencies(waterwall_unit_tests ${target})
    add_waterwall_unit_test(waterwall.vmess_client_${kind}_unit ${target}
      "unit;tunnels;vmess;client;${kind};framing;lifetime;reentry;ownership")
  endforeach()
endif()
