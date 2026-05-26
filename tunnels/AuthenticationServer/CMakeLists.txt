add_library(AuthenticationServer STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/chain.c
                    instance/index.c
                    common/database.c
                    common/line_state.c
                    common/protocol.c
                    common/sync.c
                    modules/dispatcher.c
                    modules/add_new_user/add_new_user.c
                    modules/update_user/update_user.c
                    modules/update_user_trafic_stats_diff/update_user_trafic_stats_diff.c
                    modules/get_all_users/get_all_users.c
                    modules/pull_changes_sync/pull_changes_sync.c
                    modules/get_user_by_password/get_user_by_password.c
                    modules/get_user_by_sha256/get_user_by_sha256.c
                    modules/get_user_by_sha256_base64/get_user_by_sha256_base64.c
                    modules/get_user_by_sha256_hex/get_user_by_sha256_hex.c
                    modules/ping/ping.c
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

target_include_directories(AuthenticationServer PRIVATE
                    ${CMAKE_CURRENT_SOURCE_DIR}/include
                    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(AuthenticationServer ww)
if(NOT APPLE)
    target_precompile_headers(AuthenticationServer REUSE_FROM ww)
endif()
