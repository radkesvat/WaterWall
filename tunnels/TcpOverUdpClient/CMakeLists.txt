
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
endif()



target_include_directories(TcpOverUdpClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(TcpOverUdpClient ww kcp)
