
add_library(TcpConnector STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    common/helpers.c
                    common/line_state.c
                    common/freebind.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
  
)

target_include_directories(TcpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TcpConnector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TcpConnector)

target_link_libraries(TcpConnector ww DomainResolver)
if(NOT APPLE)
    target_precompile_headers(TcpConnector REUSE_FROM ww)
endif()
