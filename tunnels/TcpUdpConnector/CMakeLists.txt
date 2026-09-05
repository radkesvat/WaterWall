add_library(TcpUdpConnector STATIC
    instance/create.c
    instance/destroy.c
    instance/api.c
    instance/node.c
    instance/chain.c
    common/helpers.c
    common/line_state.c
    upstream/init.c
    upstream/est.c
    upstream/fin.c
    upstream/payload.c
    upstream/pause.c
    upstream/resume.c
    downstream/fin.c
)

target_include_directories(TcpUdpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TcpUdpConnector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TcpUdpConnector)

target_link_libraries(TcpUdpConnector PUBLIC ww TcpConnector UdpConnector)

if(NOT APPLE)
    target_precompile_headers(TcpUdpConnector REUSE_FROM ww)
endif()
