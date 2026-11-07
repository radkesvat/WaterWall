
add_library(KcpServer STATIC
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

target_include_directories(KcpServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(KcpServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/KcpServer)
target_link_libraries(KcpServer PUBLIC KcpCommon PRIVATE ww)

if(NOT APPLE)
    target_precompile_headers(KcpServer REUSE_FROM ww)
endif()
