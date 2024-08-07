

add_library(Layer3Sender STATIC
                    sender.c
  
)

target_link_libraries(Layer3Sender ww)
# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(Layer3Sender PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/layer3)


target_compile_definitions(Layer3Sender PRIVATE  Layer3Sender_VERSION=0.1)
