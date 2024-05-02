

add_library(UdpListener STATIC
                    udp_listener.c
                 
)

# target_include_directories(UdpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(UdpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(UdpListener ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)





target_compile_definitions(UdpListener PRIVATE UdpListener_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(UdpListener PRIVATE  DEBUG=1)

endif()
