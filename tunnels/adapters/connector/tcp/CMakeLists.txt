

add_library(TcpConnector STATIC
                    tcp_connector.c
                 
)


target_link_libraries(TcpConnector ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(TcpConnector PRIVATE TcpConnector_VERSION=0.1)
