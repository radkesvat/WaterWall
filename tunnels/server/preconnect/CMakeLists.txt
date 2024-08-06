
add_library(PreConnectServer STATIC
    preconnect_server.c

)

target_link_libraries(PreConnectServer PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(PreConnectServer PRIVATE PreConnectServer_VERSION=0.1)

