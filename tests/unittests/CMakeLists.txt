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
  add_executable(aes256gcm_test aes256gcm_test.c)
  target_link_libraries(aes256gcm_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests aes256gcm_test)

  add_waterwall_unit_test(waterwall.aes256gcm_unit aes256gcm_test "unit;crypto;aes256gcm")

  add_executable(crypto_primitives_test crypto_primitives_test.c)
  target_link_libraries(crypto_primitives_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests crypto_primitives_test)

  add_waterwall_unit_test(waterwall.crypto_primitives_unit crypto_primitives_test "unit;crypto")

  add_executable(wlibc_memcopy_test wlibc_memcopy_test.c)
  target_link_libraries(wlibc_memcopy_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests wlibc_memcopy_test)

  add_waterwall_unit_test(waterwall.wlibc_memcopy_unit wlibc_memcopy_test "unit;libc;memory")

  add_executable(line_user_identifier_test line_user_identifier_test.c)
  target_link_libraries(line_user_identifier_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests line_user_identifier_test)

  add_waterwall_unit_test(waterwall.line_user_identifier_unit line_user_identifier_test "unit;net;line")

  add_executable(users_runtime_migration_test users_runtime_migration_test.c)
  target_link_libraries(users_runtime_migration_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests users_runtime_migration_test)

  add_waterwall_unit_test(waterwall.users_runtime_migration_unit users_runtime_migration_test "unit;objects;users")
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
  target_link_libraries(nghttp2_large_recv_test PRIVATE nghttp2_static)
  add_dependencies(waterwall_unit_tests nghttp2_large_recv_test)

  add_waterwall_unit_test(waterwall.nghttp2_large_recv_unit nghttp2_large_recv_test "unit;tunnels;http;nghttp2")
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
  add_executable(router_sniffing_test router_sniffing_test.c)
  target_include_directories(router_sniffing_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include
    ${CMAKE_SOURCE_DIR}/tunnels/Router
    ${CMAKE_SOURCE_DIR}/tunnels/Router/include/Router
  )
  target_link_libraries(router_sniffing_test PRIVATE Router ww)
  add_dependencies(waterwall_unit_tests router_sniffing_test)

  add_waterwall_unit_test(waterwall.router_sniffing_unit router_sniffing_test "unit;tunnels;router;sniffing")
endif()

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
