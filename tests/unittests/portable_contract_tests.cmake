include_guard(GLOBAL)

if(NOT WW_BUILD_UNIT_TESTS OR NOT BUILD_TESTING)
  return()
endif()

set(_waterwall_portable_unit_dir "${CMAKE_CURRENT_LIST_DIR}")
set(_waterwall_portable_unit_runner "${CMAKE_CURRENT_LIST_DIR}/run_unit_test.cmake")

# ww's PCH is reused by tunnel targets. Every native-unit consumer must see the
# same unit-only seams before any portable target compiles.
target_compile_definitions(ww PUBLIC WW_IDLE_TABLE_TEST_SEAM=1 WW_SYSINFO_TEST_SEAM=1)

function(_waterwall_register_portable_contract test_name target_name labels)
  add_test(
    NAME ${test_name}
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=${target_name}"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:${target_name}>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${_waterwall_portable_unit_runner}"
  )
  set_tests_properties(${test_name} PROPERTIES
    TIMEOUT 120
    LABELS "${labels}"
    RESOURCE_LOCK waterwall_unit_test_build
  )

  if(TARGET waterwall_unit_tests)
    add_dependencies(waterwall_unit_tests ${target_name})
  else()
    waterwall_register_platform_native_unit(${test_name} ${target_name} "${labels}")
  endif()
endfunction()

add_executable(buffer_budget_test EXCLUDE_FROM_ALL "${_waterwall_portable_unit_dir}/buffer_budget_test.c")
target_link_libraries(buffer_budget_test PRIVATE ww)
set_target_properties(buffer_budget_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.buffer_budget_unit buffer_budget_test "unit;buffer;portable")

add_executable(atomic_u32_test EXCLUDE_FROM_ALL "${_waterwall_portable_unit_dir}/atomic_u32_test.c")
target_link_libraries(atomic_u32_test PRIVATE ww)
set_target_properties(atomic_u32_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.atomic_u32_unit atomic_u32_test "unit;atomic;portable")

add_executable(timer_pool_test EXCLUDE_FROM_ALL "${_waterwall_portable_unit_dir}/timer_pool_test.c")
target_link_libraries(timer_pool_test PRIVATE ww)
set_target_properties(timer_pool_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.timer_pool_unit timer_pool_test "unit;timer;pool;lifetime;portable")

if(WIN32)
  add_executable(atomic_u32_fallback_test EXCLUDE_FROM_ALL "${_waterwall_portable_unit_dir}/atomic_u32_test.c")
  target_compile_definitions(atomic_u32_fallback_test PRIVATE WW_HAVE_C11_ATOMICS=0)
  target_link_libraries(atomic_u32_fallback_test PRIVATE ww)
  set_target_properties(atomic_u32_fallback_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
  _waterwall_register_portable_contract(
    waterwall.atomic_u32_fallback_unit atomic_u32_fallback_test "unit;atomic;windows")
endif()

if(TARGET HttpProxyClient AND NOT TARGET http_proxy_client_lifecycle_test)
  add_executable(http_proxy_client_lifecycle_test EXCLUDE_FROM_ALL
    "${_waterwall_portable_unit_dir}/http_proxy_client_lifecycle_test.c")
  target_link_libraries(http_proxy_client_lifecycle_test PRIVATE HttpProxyClient ww)
  _waterwall_register_portable_contract(
    waterwall.http_proxy_client_lifecycle_unit http_proxy_client_lifecycle_test "unit;http;proxy;portable;lifetime")
endif()

if(TARGET HttpProxyCommon AND NOT TARGET http_proxy_common_parser_test)
  add_executable(http_proxy_common_parser_test EXCLUDE_FROM_ALL
    "${_waterwall_portable_unit_dir}/http_proxy_common_parser_test.c")
  target_link_libraries(http_proxy_common_parser_test PRIVATE HttpProxyCommon ww)
  _waterwall_register_portable_contract(
    waterwall.http_proxy_common_parser_unit http_proxy_common_parser_test "unit;http;proxy;portable")
endif()

if(TARGET HttpProxyServer AND NOT TARGET http_proxy_server_parser_test)
  foreach(kind IN ITEMS parser lifecycle)
    add_executable(http_proxy_server_${kind}_test EXCLUDE_FROM_ALL
      "${_waterwall_portable_unit_dir}/http_proxy_server_${kind}_test.c")
    target_link_libraries(http_proxy_server_${kind}_test PRIVATE HttpProxyServer AuthenticationClient ww)
    _waterwall_register_portable_contract(
      waterwall.http_proxy_server_${kind}_unit http_proxy_server_${kind}_test "unit;http;proxy;portable")
  endforeach()
endif()

add_executable(idle_table_contract_test EXCLUDE_FROM_ALL
  "${_waterwall_portable_unit_dir}/idle_table_contract_test.c")
target_link_libraries(idle_table_contract_test PRIVATE ww)
_waterwall_register_portable_contract(
  waterwall.idle_table_contract_unit
  idle_table_contract_test
  "unit;idle-table;local-idle;contract;lifetime;tsan"
)

add_executable(system_memory_snapshot_test EXCLUDE_FROM_ALL
  "${_waterwall_portable_unit_dir}/system_memory_snapshot_test.c")
target_link_libraries(system_memory_snapshot_test PRIVATE ww)
_waterwall_register_portable_contract(
  waterwall.system_memory_snapshot_unit
  system_memory_snapshot_test
  "unit;base;system-memory;sampler;concurrency;tsan"
)

if(TARGET MuxServer AND TARGET MuxClient)
  add_executable(muxserver_admission_limit_test EXCLUDE_FROM_ALL
    "${_waterwall_portable_unit_dir}/muxserver_admission_limit_test.c")
  target_include_directories(muxserver_admission_limit_test PRIVATE
    "${CMAKE_SOURCE_DIR}/tunnels/MuxServer/include"
    "${CMAKE_SOURCE_DIR}/tunnels/MuxClient/include"
    "${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include"
  )
  target_link_libraries(muxserver_admission_limit_test PRIVATE MuxServer MuxClient ww)
  _waterwall_register_portable_contract(
    waterwall.muxserver_admission_limit_unit
    muxserver_admission_limit_test
    "unit;tunnels;muxserver;muxclient;admission;cid;concurrency;tsan"
  )
endif()

if(TARGET MuxClient)
  add_executable(muxclient_cid_index_test EXCLUDE_FROM_ALL
    "${_waterwall_portable_unit_dir}/muxclient_cid_index_test.c")
  target_include_directories(muxclient_cid_index_test PRIVATE
    "${CMAKE_SOURCE_DIR}/tunnels/MuxClient/include"
    "${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include"
  )
  target_link_libraries(muxclient_cid_index_test PRIVATE MuxClient ww)
  _waterwall_register_portable_contract(
    waterwall.muxclient_cid_index_unit
    muxclient_cid_index_test
    "unit;tunnels;muxclient;cid;scalability"
  )
endif()
