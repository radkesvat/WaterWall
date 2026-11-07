
add_library(KcpClient STATIC
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

target_include_directories(KcpClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(KcpClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/KcpClient)
target_link_libraries(KcpClient PUBLIC KcpCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(KcpClient REUSE_FROM ww)
endif()
