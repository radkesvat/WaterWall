

add_library(Connector STATIC
                    connector.c
  
)

#ww api
target_include_directories(Connector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Connector ww)
# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(Connector PRIVATE  Connector_VERSION=0.1)
