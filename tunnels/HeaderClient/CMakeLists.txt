add_library(HeaderClient STATIC
                    instance/create.c
                    instance/api.c
                    instance/node.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    downstream/init.c
                    downstream/fin.c
)

target_include_directories(HeaderClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(HeaderClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HeaderClient)

target_link_libraries(HeaderClient ww)
if(NOT APPLE)
    target_precompile_headers(HeaderClient REUSE_FROM ww)
endif()
