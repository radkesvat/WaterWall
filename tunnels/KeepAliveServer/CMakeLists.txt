
add_library(KeepAliveServer STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/fin.c
                    upstream/payload.c
                    downstream/init.c
                    downstream/fin.c
                    downstream/payload.c
  
)

target_include_directories(KeepAliveServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(KeepAliveServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/KeepAliveServer)

target_link_libraries(KeepAliveServer ww)
if(NOT APPLE)
    target_precompile_headers(KeepAliveServer REUSE_FROM ww)
endif()
