
add_library(TcpOverUdpServer STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    upstream/est.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
                    downstream/est.c
  
)

set(TCP_OVER_UDP_FEC_DIR ${CMAKE_CURRENT_LIST_DIR}/../TcpOverUdpClient/fec)
set(TCP_OVER_UDP_KCP_DIR ${CMAKE_CURRENT_LIST_DIR}/kcp)

add_library(tcp_over_udp_server_kcp OBJECT
    ${TCP_OVER_UDP_KCP_DIR}/ikcp.c
)
target_include_directories(tcp_over_udp_server_kcp PUBLIC ${TCP_OVER_UDP_KCP_DIR})

if(NOT TARGET tcp_over_udp_fec)
    add_library(tcp_over_udp_fec OBJECT
        ${TCP_OVER_UDP_FEC_DIR}/ww_fec.cc
        ${TCP_OVER_UDP_FEC_DIR}/fec.cc
        ${TCP_OVER_UDP_FEC_DIR}/reedsolomon.cc
        ${TCP_OVER_UDP_FEC_DIR}/matrix.cc
        ${TCP_OVER_UDP_FEC_DIR}/galois.cc
        ${TCP_OVER_UDP_FEC_DIR}/galois_noasm.cc
        ${TCP_OVER_UDP_FEC_DIR}/inversion_tree.cc
    )
    target_compile_features(tcp_over_udp_fec PRIVATE cxx_std_17)
    target_include_directories(tcp_over_udp_fec PUBLIC ${TCP_OVER_UDP_FEC_DIR})
    set_property(TARGET tcp_over_udp_fec PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
endif()


target_include_directories(TcpOverUdpServer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${TCP_OVER_UDP_FEC_DIR}
    ${TCP_OVER_UDP_KCP_DIR}
)
target_sources(TcpOverUdpServer PRIVATE
    $<TARGET_OBJECTS:tcp_over_udp_fec>
    $<TARGET_OBJECTS:tcp_over_udp_server_kcp>
)

target_link_libraries(TcpOverUdpServer PRIVATE ww)
if(NOT APPLE)
    target_precompile_headers(TcpOverUdpServer REUSE_FROM ww)
endif()
