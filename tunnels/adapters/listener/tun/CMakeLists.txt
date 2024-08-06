
add_library(TunListener STATIC
                    tun_listener.c
                 
)

#ww api
target_link_libraries(TunListener ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(TunListener PRIVATE TunListener_VERSION=0.1)
