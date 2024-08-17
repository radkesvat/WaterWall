

add_library(Layer3IpManipulator STATIC
                    ip_manipulator.c
  
)

target_link_libraries(Layer3IpManipulator ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(Layer3IpManipulator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared/layer3)


target_compile_definitions(Layer3IpManipulator PRIVATE  Layer3IpManipulator_VERSION=0.1)
