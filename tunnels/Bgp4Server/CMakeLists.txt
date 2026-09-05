add_library(Bgp4Server STATIC
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

target_include_directories(Bgp4Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Bgp4Server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Bgp4Server)

target_link_libraries(Bgp4Server ww)
if(NOT APPLE)
    target_precompile_headers(Bgp4Server REUSE_FROM ww)
endif()
