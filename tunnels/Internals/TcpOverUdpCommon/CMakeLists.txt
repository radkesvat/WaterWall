add_library(tcp_over_udp_kcp OBJECT kcp/ikcp.c)
target_include_directories(tcp_over_udp_kcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/kcp)
target_link_libraries(tcp_over_udp_kcp PRIVATE waterwall_runtime_options)

add_library(tcp_over_udp_fec OBJECT
    fec/ww_fec.cc fec/fec.cc fec/reedsolomon.cc fec/matrix.cc
    fec/galois.cc fec/galois_noasm.cc fec/inversion_tree.cc)
target_compile_features(tcp_over_udp_fec PRIVATE cxx_std_17)
target_include_directories(tcp_over_udp_fec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/fec PRIVATE ${CMAKE_SOURCE_DIR}/ww/libc)
target_link_libraries(tcp_over_udp_fec PRIVATE waterwall_runtime_options)

add_library(TcpOverUdpCommon STATIC src/wire.c src/session.c
    $<TARGET_OBJECTS:tcp_over_udp_kcp> $<TARGET_OBJECTS:tcp_over_udp_fec>)
target_include_directories(TcpOverUdpCommon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/kcp ${CMAKE_CURRENT_SOURCE_DIR}/fec)
target_link_libraries(TcpOverUdpCommon PUBLIC ww)
if(NOT APPLE)
    target_precompile_headers(TcpOverUdpCommon REUSE_FROM ww)
endif()
