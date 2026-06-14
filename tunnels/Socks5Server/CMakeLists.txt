add_library(Socks5Server STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
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

if(NOT TARGET AuthenticationClient)
    message(FATAL_ERROR "Socks5Server requires AuthenticationClient; enable INCLUDE_AUTHENTICATION_CLIENT")
endif()

target_include_directories(Socks5Server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../AuthenticationClient/include
)

target_include_directories(Socks5Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Socks5Server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Socks5Server)

target_link_libraries(Socks5Server PRIVATE ww AuthenticationClient)
if(NOT APPLE)
    target_precompile_headers(Socks5Server REUSE_FROM ww)
endif()
