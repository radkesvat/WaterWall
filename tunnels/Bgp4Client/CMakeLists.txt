add_library(Bgp4Client STATIC
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
                    downstream/payload.c
)

target_include_directories(Bgp4Client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Bgp4Client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Bgp4Client)

target_link_libraries(Bgp4Client ww)
if(NOT APPLE)
    target_precompile_headers(Bgp4Client REUSE_FROM ww)
endif()
