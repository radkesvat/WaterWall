add_library(TcpUdpConnector STATIC
    instance/create.c
    instance/destroy.c
    instance/api.c
    instance/node.c
    instance/chain.c
    instance/index.c
    instance/prepair.c
    instance/start.c
    instance/stop.c
    common/helpers.c
    common/line_state.c
    upstream/init.c
    upstream/est.c
    upstream/fin.c
    upstream/payload.c
    upstream/pause.c
    upstream/resume.c
    downstream/init.c
    downstream/est.c
    downstream/fin.c
    downstream/payload.c
    downstream/pause.c
    downstream/resume.c
)

target_include_directories(TcpUdpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TcpUdpConnector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TcpUdpConnector)

target_link_libraries(TcpUdpConnector PUBLIC ww TcpConnector UdpConnector)

if(NOT APPLE)
    target_precompile_headers(TcpUdpConnector REUSE_FROM ww)
endif()
