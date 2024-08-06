
add_library(Bridge STATIC
                    bridge.c
                 
)

target_link_libraries(Bridge ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(Bridge PRIVATE  Bridge_VERSION=0.1)
