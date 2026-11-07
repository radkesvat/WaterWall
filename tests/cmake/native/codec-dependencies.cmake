# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET kcp_fec)
  waterwall_add_native_executable(kcp_fec_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/kcp/kcp_fec_test.cc)
  target_compile_features(kcp_fec_test PRIVATE cxx_std_17)
  target_include_directories(kcp_fec_test PRIVATE ${CMAKE_SOURCE_DIR}/ww/libc)
  target_link_libraries(kcp_fec_test PRIVATE kcp_fec "$<LINK_ONLY:ww>")
  if(LINUX AND NOT ALLOCATOR_BYPASS)
    target_compile_definitions(kcp_fec_test PRIVATE WW_FEC_ALLOCATOR_TEST=1)
    target_link_options(kcp_fec_test PRIVATE "-Wl,--wrap=mi_malloc" "-Wl,--wrap=mi_free")
  endif()
  add_dependencies(waterwall_unit_tests kcp_fec_test)

  add_waterwall_unit_test(waterwall.kcp_fec_unit kcp_fec_test "unit;tunnels;fec")
endif()

if(TARGET HttpCommon)
  waterwall_add_native_executable(http_h2_data_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/http_h2_data_test.c)
  target_link_libraries(http_h2_data_test PRIVATE HttpCommon nghttp2_static ww)
  target_link_options(http_h2_data_test PRIVATE
    "-Wl,--wrap=bufferpoolGetLargeBuffer"
    "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit"
    "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer"
    "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer"
    "-Wl,--wrap=sbufDestroy"
  )
  add_dependencies(waterwall_unit_tests http_h2_data_test)
  add_waterwall_unit_test(waterwall.http_h2_data_unit http_h2_data_test "unit;tunnels;http;http2;ownership" 30)
endif()

if(TARGET nghttp2_static)
  waterwall_add_native_executable(nghttp2_large_recv_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/http/nghttp2_large_recv_test.c)
  target_link_libraries(nghttp2_large_recv_test PRIVATE nghttp2_static ww)
  add_dependencies(waterwall_unit_tests nghttp2_large_recv_test)

  add_waterwall_unit_test(waterwall.nghttp2_large_recv_unit nghttp2_large_recv_test "unit;tunnels;http;nghttp2")
endif()

