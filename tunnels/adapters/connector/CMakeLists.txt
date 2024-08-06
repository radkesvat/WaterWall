

add_library(Connector STATIC
                    connector.c
  
)

target_link_libraries(Connector ww)
# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(Connector PRIVATE  Connector_VERSION=0.1)
