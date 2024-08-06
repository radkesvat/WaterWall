
add_library(UdpListener STATIC
                    udp_listener.c
                 
)

#ww api
target_link_libraries(UdpListener ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(UdpListener PRIVATE UdpListener_VERSION=0.1)
