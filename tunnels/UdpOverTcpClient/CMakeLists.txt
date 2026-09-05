
add_library(UdpOverTcpClient STATIC
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
                    upstream/est.c
                    downstream/init.c
                    downstream/fin.c
                    downstream/payload.c
  
)

target_include_directories(UdpOverTcpClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(UdpOverTcpClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/UdpOverTcpClient)

target_link_libraries(UdpOverTcpClient ww)
if(NOT APPLE)
    target_precompile_headers(UdpOverTcpClient REUSE_FROM ww)
endif()
