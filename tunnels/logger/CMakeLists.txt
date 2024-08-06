
add_library(LoggerTunnel STATIC
      logger_tunnel.c
                 
)

target_link_libraries(LoggerTunnel ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(LoggerTunnel PRIVATE  LoggerTunnel_VERSION=0.1)
