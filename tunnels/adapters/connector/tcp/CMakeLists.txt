

add_library(TcpConnector STATIC
                    tcp_connector.c
                 
)


#ww api
target_include_directories(TcpConnector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(TcpConnector ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(TcpConnector PRIVATE TcpConnector_VERSION=0.1)
