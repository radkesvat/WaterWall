
add_library(TcpListener STATIC
                        instance/create.c
                        instance/destroy.c
                        instance/api.c
                        instance/node.c
                        instance/start.c
                        instance/stop.c
                        common/helpers.c
                        common/line_state.c
                        downstream/init.c
                        downstream/est.c
                        downstream/fin.c
                        downstream/payload.c
                        downstream/pause.c
                        downstream/resume.c
  
)

target_include_directories(TcpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TcpListener PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TcpListener)

target_link_libraries(TcpListener ww)
if(NOT APPLE)
    target_precompile_headers(TcpListener REUSE_FROM ww)
endif()
