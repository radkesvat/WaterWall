
add_library(UdpOverTcpServer STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
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
                    downstream/fin.c
                    downstream/payload.c
  
)

target_include_directories(UdpOverTcpServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(UdpOverTcpServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/UdpOverTcpServer)

target_link_libraries(UdpOverTcpServer ww)
if(NOT APPLE)
    target_precompile_headers(UdpOverTcpServer REUSE_FROM ww)
endif()

