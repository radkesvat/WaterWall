
add_library(UdpListener STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/stop.c
                    common/helpers.c
                    common/dynamic_endpoint.c
                    common/line_state.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
  
)

target_include_directories(UdpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(UdpListener PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/UdpListener)

target_link_libraries(UdpListener ww)
if(NOT APPLE)
    target_precompile_headers(UdpListener REUSE_FROM ww)
endif()
