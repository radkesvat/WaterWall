

add_library(TcpListener STATIC
                    tcp_listener.c
                 
)

# target_include_directories(TcpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(TcpListener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(TcpListener ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)





target_compile_definitions(TcpListener PRIVATE TcpListener_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(TcpListener PRIVATE  DEBUG=1)

endif()
