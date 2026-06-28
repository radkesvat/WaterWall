add_library(AuthenticationClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
                    common/line_state.c
                    common/protocol.c
                    common/users_api.c
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

target_include_directories(AuthenticationClient PRIVATE
                    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(AuthenticationClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(AuthenticationClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/AuthenticationClient)

target_link_libraries(AuthenticationClient ww)
if(NOT APPLE)
    target_precompile_headers(AuthenticationClient REUSE_FROM ww)
endif()
