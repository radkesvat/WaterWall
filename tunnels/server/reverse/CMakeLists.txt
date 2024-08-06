
add_library(ReverseServer STATIC
                reverse_server.c
                 
)

target_link_libraries(ReverseServer ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(ReverseServer PRIVATE  ReverseServer_VERSION=0.1)
