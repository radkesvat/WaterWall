

add_library(Socks5Server STATIC
      socks5_server.c
)

#ww api
target_include_directories(Socks5Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ww)
target_link_libraries(Socks5Server ww)

target_compile_definitions(Socks5Server PRIVATE Socks5Server_VERSION=0.1)
