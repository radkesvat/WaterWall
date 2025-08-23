
add_library(TcpOverUdpClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
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

if(NOT TUNNELS_KCP_INCLUDE_SET)
    set(TUNNELS_KCP_INCLUDE_SET TRUE CACHE INTERNAL "")
    add_library(kcp OBJECT
        kcp/ikcp.c
    )
    target_include_directories(kcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/kcp)

    # add_library(fec OBJECT
    #     fec/fec.cc
    #     fec/reedsolomon.cc
    #     fec/sess.cc
    #     fec/matrix.cc
    #     fec/galois.cc
    #     fec/galois_noasm.cc
    #     fec/inversion_tree.cc
    # )
    # target_include_directories(fec PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/kcp)
    # target_include_directories(fec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/fec)

endif()

target_include_directories(TcpOverUdpClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# target_link_libraries(TcpOverUdpClient fec)
target_link_libraries(TcpOverUdpClient ww kcp)
if(NOT APPLE)
    target_precompile_headers(TcpOverUdpClient REUSE_FROM ww)
endif()
