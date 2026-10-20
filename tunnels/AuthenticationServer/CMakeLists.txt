add_library(AuthenticationServer STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/start.c
                    instance/stop.c
                    common/database.c
                    common/private_file.c
                    common/line_state.c
                    common/protocol.c
                    common/session.c
                    common/sync.c
                    common/status.c
                    common/audit_config.c
                    common/audit.c
                    common/audit_writer.c
                    common/user_views.c
                    api/update_apply.c
                    api/create_apply.c
                    api/password_apply.c
                    api/request.c
                    api/response.c
                    api/status.c
                    api/get_user.c
                    api/list_users.c
                    api/edit_token.c
                    api/config_fields.c
                    api/create_request.c
                    api/create_user.c
                    api/password_request.c
                    api/change_user_password.c
                    api/update_request.c
                    api/update_user.c
                    modules/dispatcher.c
                    modules/lookup.c
                    modules/authenticate/authenticate.c
                    modules/add_new_user/add_new_user.c
                    modules/update_user/update_user.c
                    modules/get_all_users/get_all_users.c
                    modules/push_user_stats/push_user_stats.c
                    modules/get_user_by_password/get_user_by_password.c
                    modules/get_user_by_sha224/get_user_by_sha224.c
                    modules/get_user_by_sha224_base64/get_user_by_sha224_base64.c
                    modules/get_user_by_sha224_hex/get_user_by_sha224_hex.c
                    modules/get_user_by_sha256/get_user_by_sha256.c
                    modules/get_user_by_sha256_base64/get_user_by_sha256_base64.c
                    modules/get_user_by_sha256_hex/get_user_by_sha256_hex.c
                    modules/ping/ping.c
                    upstream/init.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
)

target_include_directories(AuthenticationServer PRIVATE
                    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(AuthenticationServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(AuthenticationServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/AuthenticationServer)

target_link_libraries(AuthenticationServer ww)
if(NOT APPLE)
    target_precompile_headers(AuthenticationServer REUSE_FROM ww)
endif()
