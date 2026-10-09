# Explicit portable native contracts, using the shared registration helpers.
# Standalone archive/header probes retain their link boundaries; runtime fixtures
# opt into private support and join the existing Linux or platform aggregate.
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/TestHelpers.cmake")
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
  if(TARGET waterwall_unit_tests)
    set(aggregate waterwall_unit_tests)
  else()
    set(aggregate waterwall_platform_unit_tests)
  endif()
  waterwall_register_native_test(${test_name} ${target_name} "${labels}" AGGREGATE ${aggregate})
endfunction()

if(NOT TARGET socket_manager_selection_test)
  waterwall_add_native_executable(socket_manager_selection_test SUPPORT EXCLUDE_FROM_ALL SOURCES
    "${WATERWALL_UNIT_SOURCE_ROOT}/devices/socket_manager/socket_manager_selection_test.c")
  target_include_directories(socket_manager_selection_test PRIVATE "${CMAKE_SOURCE_DIR}/ww/managers")
  target_link_libraries(socket_manager_selection_test PRIVATE ww)
  _waterwall_register_portable_contract(waterwall.socket_manager_selection_unit
    socket_manager_selection_test "unit;net;socket-manager;selection;portable")
endif()

waterwall_add_native_executable(wwapi_header_test EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/base/wwapi_header_test.c")
target_link_libraries(wwapi_header_test PRIVATE ww)
set_target_properties(wwapi_header_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.wwapi_header_unit wwapi_header_test "unit;headers;logger;portable")

waterwall_add_native_executable(lwip_checksum_link_test EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_checksum_link_test.c")
# Start from the standalone archive to exercise its hook dependency. Borrow only
# its lwIP configuration headers; ww's headers and PCH stay out of this consumer.
target_include_directories(lwip_checksum_link_test PRIVATE "$<TARGET_PROPERTY:lwipcore,INCLUDE_DIRECTORIES>")
target_link_libraries(lwip_checksum_link_test PRIVATE lwipcore)
set_target_properties(lwip_checksum_link_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.lwip_checksum_link_unit lwip_checksum_link_test "unit;net;checksum;portable")

waterwall_add_native_executable(buffer_budget_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/bufio/buffer_budget_test.c")
target_link_libraries(buffer_budget_test PRIVATE ww)
set_target_properties(buffer_budget_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.buffer_budget_unit buffer_budget_test "unit;buffer;portable")

waterwall_add_native_executable(atomic_u32_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/base/atomic_u32_test.c")
target_link_libraries(atomic_u32_test PRIVATE ww ww_test_support)
set_target_properties(atomic_u32_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.atomic_u32_unit atomic_u32_test "unit;atomic;portable")

waterwall_add_native_executable(timer_pool_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/net/timer_pool_test.c")
  target_link_libraries(timer_pool_test PRIVATE ww_test_support)
target_link_libraries(timer_pool_test PRIVATE ww)
set_target_properties(timer_pool_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
_waterwall_register_portable_contract(waterwall.timer_pool_unit timer_pool_test "unit;timer;pool;lifetime;portable")

if(WIN32)
  waterwall_add_native_executable(atomic_u32_fallback_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/base/atomic_u32_test.c")
  target_compile_definitions(atomic_u32_fallback_test PRIVATE WW_HAVE_C11_ATOMICS=0)
  target_link_libraries(atomic_u32_fallback_test PRIVATE ww ww_test_support)
  set_target_properties(atomic_u32_fallback_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
  _waterwall_register_portable_contract(
    waterwall.atomic_u32_fallback_unit atomic_u32_fallback_test "unit;atomic;windows")
endif()

if(TARGET HttpProxyClient AND NOT TARGET http_proxy_client_lifecycle_test)
  waterwall_add_native_executable(http_proxy_client_lifecycle_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http_proxy/http_proxy_client_lifecycle_test.c")
  target_link_libraries(http_proxy_client_lifecycle_test PRIVATE HttpProxyClient ww)
  _waterwall_register_portable_contract(
    waterwall.http_proxy_client_lifecycle_unit http_proxy_client_lifecycle_test "unit;http;proxy;portable;lifetime")
endif()

if(TARGET StreamFragmenter)
  waterwall_add_native_executable(streamfragmenter_tls_hello_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/streamfragmenter/streamfragmenter_tls_hello_test.c")
  target_include_directories(streamfragmenter_tls_hello_test PRIVATE
    "${CMAKE_SOURCE_DIR}/tunnels/Internals/StreamFragmenter/include")
  target_link_libraries(streamfragmenter_tls_hello_test PRIVATE StreamFragmenter ww)
  _waterwall_register_portable_contract(
    waterwall.streamfragmenter_tls_hello_unit streamfragmenter_tls_hello_test "unit;tunnels;fragmenter;portable")
endif()

if(TARGET HttpProxyCommon AND NOT TARGET http_proxy_common_parser_test)
  waterwall_add_native_executable(http_proxy_common_parser_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http_proxy/http_proxy_common_parser_test.c")
  target_link_libraries(http_proxy_common_parser_test PRIVATE HttpProxyCommon ww)
  _waterwall_register_portable_contract(
    waterwall.http_proxy_common_parser_unit http_proxy_common_parser_test "unit;http;proxy;portable")
endif()

if(TARGET HttpProxyServer AND NOT TARGET http_proxy_server_parser_test)
  foreach(kind IN ITEMS parser lifecycle)
    waterwall_add_native_executable(http_proxy_server_${kind}_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http_proxy/http_proxy_server_${kind}_test.c")
    target_link_libraries(http_proxy_server_${kind}_test PRIVATE HttpProxyServer AuthenticationClient ww)
    _waterwall_register_portable_contract(
      waterwall.http_proxy_server_${kind}_unit http_proxy_server_${kind}_test "unit;http;proxy;portable")
  endforeach()
endif()

waterwall_add_native_executable(idle_table_contract_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/net/idle_table_contract_test.c")
  target_link_libraries(idle_table_contract_test PRIVATE ww_test_support)
target_link_libraries(idle_table_contract_test PRIVATE ww)
_waterwall_register_portable_contract(
  waterwall.idle_table_contract_unit
  idle_table_contract_test
  "unit;idle-table;local-idle;contract;lifetime;tsan"
)

waterwall_add_native_executable(system_memory_snapshot_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/base/system_memory_snapshot_test.c")
  target_link_libraries(system_memory_snapshot_test PRIVATE ww_test_support)
target_link_libraries(system_memory_snapshot_test PRIVATE ww)
_waterwall_register_portable_contract(
  waterwall.system_memory_snapshot_unit
  system_memory_snapshot_test
  "unit;base;system-memory;sampler;concurrency;tsan"
)

if(TARGET MuxServer AND TARGET MuxClient)
  waterwall_add_native_executable(muxserver_admission_limit_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxserver_admission_limit_test.c")
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
  waterwall_add_native_executable(muxclient_cid_index_test SUPPORT EXCLUDE_FROM_ALL SOURCES "${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/mux/muxclient_cid_index_test.c")
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
