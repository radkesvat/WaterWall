

add_library(Layer3IpRoutingTable STATIC
                    ip_routing_table.c
  
)

target_link_libraries(Layer3IpRoutingTable ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(Layer3IpRoutingTable PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared/layer3)


target_compile_definitions(Layer3IpRoutingTable PRIVATE  Layer3IpRoutingTable_VERSION=0.1)
