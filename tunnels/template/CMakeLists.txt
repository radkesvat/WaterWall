
add_library(Template STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/est.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/est.c
  
)

target_include_directories(Template PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(Template ww)


