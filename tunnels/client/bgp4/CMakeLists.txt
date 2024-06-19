
add_library(Bgp4Client STATIC
bgp4_client.c

)

#ww api
target_include_directories(Bgp4Client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Bgp4Client PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(Bgp4Client PRIVATE  Bgp4Client_VERSION=0.1)
