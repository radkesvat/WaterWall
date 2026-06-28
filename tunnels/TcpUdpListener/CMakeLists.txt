add_library(TcpUdpListener STATIC
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

target_include_directories(TcpUdpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TcpUdpListener PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TcpUdpListener)

target_link_libraries(TcpUdpListener PUBLIC ww TcpListener UdpListener)

if(NOT APPLE)
    target_precompile_headers(TcpUdpListener REUSE_FROM ww)
endif()
