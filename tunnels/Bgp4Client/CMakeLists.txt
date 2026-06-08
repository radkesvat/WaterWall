add_library(Bgp4Client STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
)

target_include_directories(Bgp4Client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(Bgp4Client ww)
if(NOT APPLE)
    target_precompile_headers(Bgp4Client REUSE_FROM ww)
endif()
