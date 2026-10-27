# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET ww_lwip_engine_test)
  add_test(NAME waterwall.lwip_patch_helpers_unit COMMAND ${CMAKE_COMMAND}
    "-DPATCH_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "-DPATCH_TEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/lwip-patch-helpers/$<CONFIG>"
    -P ${CMAKE_SOURCE_DIR}/tests/cmake/lwip_patch_helpers_test.cmake)
  set_tests_properties(waterwall.lwip_patch_helpers_unit PROPERTIES
    LABELS "unit;net;lwip;cmake" TIMEOUT 30)
  # Keep reuse layouts/options consistent across the private stack and fixture.
  get_target_property(lwip_reuse_sources ww_lwip_engine_test SOURCES)
  get_target_property(lwip_reuse_source_dir ww_lwip_engine_test SOURCE_DIR)
  list(TRANSFORM lwip_reuse_sources PREPEND "${lwip_reuse_source_dir}/" REGEX "^[^/]")
  add_library(ww_lwip_reuse_test STATIC EXCLUDE_FROM_ALL ${lwip_reuse_sources})
  target_include_directories(ww_lwip_reuse_test PUBLIC
    "$<TARGET_PROPERTY:ww_lwip_engine_test,INTERFACE_INCLUDE_DIRECTORIES>"
    PRIVATE ${CMAKE_SOURCE_DIR}/ww/base ${CMAKE_SOURCE_DIR}/ww/libc)
  target_compile_definitions(ww_lwip_reuse_test PUBLIC
    "$<TARGET_PROPERTY:ww_lwip_engine_test,INTERFACE_COMPILE_DEFINITIONS>"
    SO_REUSE=1 SO_REUSE_RXTOALL=1)
  target_compile_options(ww_lwip_reuse_test PUBLIC
    "$<TARGET_PROPERTY:ww_lwip_engine_test,INTERFACE_COMPILE_OPTIONS>")
  target_link_options(ww_lwip_reuse_test PUBLIC
    "$<TARGET_PROPERTY:ww_lwip_engine_test,INTERFACE_LINK_OPTIONS>")
  target_link_libraries(ww_lwip_reuse_test PUBLIC waterwall_runtime_options ww_packet_batch)
  set_target_properties(ww_lwip_reuse_test PROPERTIES UNITY_BUILD OFF)
  waterwall_add_native_executable(lwip_udp_reuse_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_udp_reuse_test.c)
  target_link_libraries(lwip_udp_reuse_test PRIVATE ww_lwip_reuse_test pthread)
  target_link_options(lwip_udp_reuse_test PRIVATE "-Wl,--wrap=sys_now"
    "-Wl,--wrap=pbuf_clone" "-Wl,--wrap=pbuf_free")
  add_dependencies(waterwall_unit_tests lwip_udp_reuse_test)
  add_waterwall_unit_test(waterwall.lwip_udp_reuse_unit lwip_udp_reuse_test "unit;net;lwip;udp;ownership")
  waterwall_add_native_executable(lwip_tcp_capacity_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_tcp_capacity_test.c)
  # Exercise the production pools with this fixture's isolated runtime hooks;
  # linking the ww_lwip target would also pull in the complete ww runtime.
  target_link_libraries(lwip_tcp_capacity_test PRIVATE "$<TARGET_FILE:ww_lwip>" ww_packet_batch pthread)
  target_include_directories(lwip_tcp_capacity_test PRIVATE
    "$<TARGET_PROPERTY:ww_lwip,INTERFACE_INCLUDE_DIRECTORIES>")
  target_compile_definitions(lwip_tcp_capacity_test PRIVATE
    "$<TARGET_PROPERTY:ww_lwip,INTERFACE_COMPILE_DEFINITIONS>")
  add_dependencies(lwip_tcp_capacity_test ww_lwip)
  target_link_options(lwip_tcp_capacity_test PRIVATE "-Wl,--wrap=sys_now")
  add_dependencies(waterwall_unit_tests lwip_tcp_capacity_test)
  add_waterwall_unit_test(waterwall.lwip_tcp_capacity_unit lwip_tcp_capacity_test "unit;net;lwip;capacity")
  waterwall_add_native_executable(lwip_ack_batch_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_ack_batch_test.c)
  target_link_libraries(lwip_ack_batch_test PRIVATE ww_test_support ww_lwip_engine_test pthread)
  target_link_options(lwip_ack_batch_test PRIVATE "-Wl,--wrap=sys_now" "-Wl,--wrap=pbuf_alloc")
  add_dependencies(waterwall_unit_tests lwip_ack_batch_test)
  add_waterwall_unit_test(waterwall.lwip_ack_batch_unit lwip_ack_batch_test "unit;net;lwip;thread;lifetime")
  waterwall_add_native_executable(lwip_sack_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_sack_test.c)
  target_link_libraries(lwip_sack_test PRIVATE ww_test_support ww_lwip_engine_test pthread)
  target_link_options(lwip_sack_test PRIVATE "-Wl,--wrap=sys_now" "-Wl,--wrap=tcp_seg_copy")
  add_dependencies(waterwall_unit_tests lwip_sack_test)
  add_waterwall_unit_test(waterwall.lwip_sack_unit lwip_sack_test "unit;net;lwip;tcp;ownership")
  waterwall_add_native_executable(lwip_tcp_output_tail_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_tcp_output_tail_test.c)
  target_link_libraries(lwip_tcp_output_tail_test PRIVATE ww_test_support ww_lwip_engine_test pthread)
  target_link_options(lwip_tcp_output_tail_test PRIVATE "-Wl,--wrap=sys_now")
  add_dependencies(waterwall_unit_tests lwip_tcp_output_tail_test)
  add_waterwall_unit_test(waterwall.lwip_tcp_output_tail_unit lwip_tcp_output_tail_test "unit;net;lwip;tcp;ownership")
  waterwall_add_native_executable(lwip_engine_isolation_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_engine_isolation_test.c)
  target_link_libraries(lwip_engine_isolation_test PRIVATE ww_test_support)
  target_link_libraries(lwip_engine_isolation_test PRIVATE ww_lwip_engine_test pthread)
  target_link_options(lwip_engine_isolation_test PRIVATE "-Wl,--wrap=sys_now")
  add_dependencies(waterwall_unit_tests lwip_engine_isolation_test)
  add_waterwall_unit_test(waterwall.lwip_engine_isolation_unit lwip_engine_isolation_test "unit;net;lwip;thread")
  waterwall_add_native_executable(lwip_engine_pools_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_engine_pools_test.c)
  target_link_libraries(lwip_engine_pools_test PRIVATE ww_test_support)
  target_link_libraries(lwip_engine_pools_test PRIVATE ww_lwip_engine_test pthread)
  target_link_options(lwip_engine_pools_test PRIVATE "-Wl,--wrap=sys_now" "-Wl,--wrap=sys_arch_protect")
  add_dependencies(waterwall_unit_tests lwip_engine_pools_test)
  add_waterwall_unit_test(waterwall.lwip_engine_pools_unit lwip_engine_pools_test "unit;net;lwip;thread")
  waterwall_add_native_executable(lwip_engine_ports_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_engine_ports_test.c)
  target_link_libraries(lwip_engine_ports_test PRIVATE ww_test_support)
  target_link_libraries(lwip_engine_ports_test PRIVATE ww_lwip_engine_test pthread)
  target_link_options(lwip_engine_ports_test PRIVATE "-Wl,--wrap=sys_now")
  add_dependencies(waterwall_unit_tests lwip_engine_ports_test)
  add_waterwall_unit_test(waterwall.lwip_engine_ports_unit lwip_engine_ports_test "unit;net;lwip;thread")
  waterwall_add_native_executable(lwip_engine_ids_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_engine_ids_test.c)
  target_link_libraries(lwip_engine_ids_test PRIVATE ww_test_support)
  target_link_libraries(lwip_engine_ids_test PRIVATE ww_lwip_engine_test pthread)
  target_link_options(lwip_engine_ids_test PRIVATE "-Wl,--wrap=sys_now")
  add_dependencies(waterwall_unit_tests lwip_engine_ids_test)
  add_waterwall_unit_test(waterwall.lwip_engine_ids_unit lwip_engine_ids_test "unit;net;lwip;thread")
  waterwall_add_native_executable(lwip_engine_runtime_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/lwip/lwip_engine_runtime_test.c ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)
  target_link_libraries(lwip_engine_runtime_test PRIVATE ww_test_support)
  target_link_libraries(lwip_engine_runtime_test PRIVATE ww_lwip_engine_test ww)
  target_link_options(lwip_engine_runtime_test PRIVATE "-Wl,--wrap=sys_now" "-Wl,--wrap=wtimerAdd"

    "-Wl,--wrap=nodemanagerQuiesceWorker" "-Wl,--wrap=workerMessagesDestroyDetached")
  add_dependencies(waterwall_unit_tests lwip_engine_runtime_test)
  add_waterwall_unit_test(waterwall.lwip_engine_runtime_unit lwip_engine_runtime_test "unit;net;lwip;thread;timer;lifetime")
endif()

