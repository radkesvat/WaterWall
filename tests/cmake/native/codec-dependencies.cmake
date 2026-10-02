# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET tcp_over_udp_fec)
  waterwall_add_native_executable(tcp_over_udp_fec_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/tcp_over_udp/tcp_over_udp_fec_test.cc)
  target_compile_features(tcp_over_udp_fec_test PRIVATE cxx_std_17)
  target_link_libraries(tcp_over_udp_fec_test PRIVATE tcp_over_udp_fec)
  add_dependencies(waterwall_unit_tests tcp_over_udp_fec_test)

  add_waterwall_unit_test(waterwall.tcp_over_udp_fec_unit tcp_over_udp_fec_test "unit;tunnels;fec")
endif()

if(TARGET nghttp2_static)
  waterwall_add_native_executable(nghttp2_large_recv_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/nghttp2_large_recv_test.c)
  target_link_libraries(nghttp2_large_recv_test PRIVATE nghttp2_static ww)
  add_dependencies(waterwall_unit_tests nghttp2_large_recv_test)

  add_waterwall_unit_test(waterwall.nghttp2_large_recv_unit nghttp2_large_recv_test "unit;tunnels;http;nghttp2")
endif()

