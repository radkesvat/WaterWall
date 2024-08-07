

add_library(Layer3Receiver STATIC
                    receiver.c
  
)

target_link_libraries(Layer3Receiver ww)
# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(Layer3Receiver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/layer3)


target_compile_definitions(Layer3Receiver PRIVATE  Layer3Receiver_VERSION=0.1)
