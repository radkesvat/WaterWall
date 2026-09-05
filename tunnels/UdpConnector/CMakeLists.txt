
add_library(UdpConnector STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/stop.c
                    instance/chain.c
                    common/helpers.c
                    common/line_state.c
                    common/socket_pool.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
  
)

target_include_directories(UdpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(UdpConnector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/UdpConnector)

target_link_libraries(UdpConnector ww DomainResolver)
if(NOT APPLE)
    target_precompile_headers(UdpConnector REUSE_FROM ww)
endif()
