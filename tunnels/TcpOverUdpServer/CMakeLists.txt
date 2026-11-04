
add_library(TcpOverUdpServer STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
                    instance/stop.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/fin.c
                    downstream/payload.c
  
)

target_include_directories(TcpOverUdpServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TcpOverUdpServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TcpOverUdpServer)
target_link_libraries(TcpOverUdpServer PUBLIC TcpOverUdpCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(TcpOverUdpServer REUSE_FROM ww)
endif()
