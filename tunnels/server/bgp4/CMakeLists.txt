
add_library(Bgp4Server STATIC
        bgp4_server.c

)

#ww api
target_include_directories(Bgp4Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Bgp4Server PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(Bgp4Server PRIVATE  Bgp4Server_VERSION=0.1)
