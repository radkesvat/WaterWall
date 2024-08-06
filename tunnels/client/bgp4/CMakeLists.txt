
add_library(Bgp4Client STATIC
bgp4_client.c

)

target_link_libraries(Bgp4Client PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(Bgp4Client PRIVATE  Bgp4Client_VERSION=0.1)
