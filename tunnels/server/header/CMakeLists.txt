
add_library(HeaderServer STATIC
      header_server.c

)

target_link_libraries(HeaderServer PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(HeaderServer PRIVATE  HeaderServer_VERSION=0.1)

