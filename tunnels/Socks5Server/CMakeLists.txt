add_library(Socks5Server STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/chain.c
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

if(NOT TARGET UserController)
    message(FATAL_ERROR "Socks5Server requires UserController; enable INCLUDE_USER_CONTROLLER")
endif()

if(NOT TARGET UdpListener OR NOT TARGET TcpUdpListener)
    message(FATAL_ERROR "Socks5Server requires UdpListener and TcpUdpListener provider-support targets")
endif()

target_include_directories(Socks5Server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../AuthenticationClient/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../Internals/UserController/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../UdpListener/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../TcpUdpListener/include
)

target_include_directories(Socks5Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(Socks5Server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/Socks5Server)

target_link_libraries(Socks5Server PRIVATE ww AuthenticationClient UserController UdpListener TcpUdpListener)
if(NOT APPLE)
    target_precompile_headers(Socks5Server REUSE_FROM ww)
endif()
