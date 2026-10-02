# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET IpOverrider)
  waterwall_add_native_executable(ipoverrider_node_gate_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/ipoverrider/ipoverrider_node_gate_test.c)
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
  waterwall_add_native_executable(softiplimiter_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/softiplimiter/softiplimiter_test.c)
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
  waterwall_add_native_executable(router_geoip_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/router/router_geoip_test.c)
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
  waterwall_add_native_executable(router_geosite_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/router/router_geosite_test.c)
  target_include_directories(router_geosite_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_link_libraries(router_geosite_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_geosite_test)

  add_waterwall_unit_test(waterwall.router_geosite_unit router_geosite_test "unit;tunnels;router;geosite")

  waterwall_add_native_executable(router_sniffing_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/router/router_sniffing_test.c)
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
  ${CMAKE_SOURCE_DIR}/ww/bufio/splice_stream.c
  ${CMAKE_SOURCE_DIR}/ww/bufio/splice_buffer.c
  ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_budget.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_queue.c
  ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_stream.c
)

set(WATERWALL_LINE_FAILURE_WRAPS
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

