

add_library(Layer3TcpManipulator STATIC
                    tcp_manipulator.c
  
)

target_link_libraries(Layer3TcpManipulator ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(Layer3TcpManipulator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared/layer3)


target_compile_definitions(Layer3TcpManipulator PRIVATE  Layer3TcpManipulator_VERSION=0.1)
