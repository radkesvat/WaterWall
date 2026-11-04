
add_library(TcpOverUdpClient STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
                    instance/stop.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/fin.c
                    upstream/payload.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
  
)

target_include_directories(TcpOverUdpClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TcpOverUdpClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TcpOverUdpClient)
target_link_libraries(TcpOverUdpClient PUBLIC TcpOverUdpCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(TcpOverUdpClient REUSE_FROM ww)
endif()
