

add_library(Layer3IpOverrider STATIC
                    connector.c
  
)

target_link_libraries(Layer3IpOverrider ww)
# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(Layer3IpOverrider PRIVATE  Layer3IpOverrider_VERSION=0.1)
