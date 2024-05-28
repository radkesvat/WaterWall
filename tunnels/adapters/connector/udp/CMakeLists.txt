
add_library(UdpConnector STATIC
                    udp_connector.c
                 
)

#ww api
target_include_directories(UdpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(UdpConnector ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(UdpConnector PRIVATE  UdpConnector_VERSION=0.1)
