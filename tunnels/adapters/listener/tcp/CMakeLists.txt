
add_library(TcpListener STATIC
                    tcp_listener.c
                 
)

#ww api
target_link_libraries(TcpListener ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(TcpListener PRIVATE TcpListener_VERSION=0.1)
