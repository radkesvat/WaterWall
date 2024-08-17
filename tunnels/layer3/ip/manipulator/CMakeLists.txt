

add_library(Layer3IPManipulator STATIC
                    ip_manipulator.c
  
)

target_link_libraries(Layer3IPManipulator ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(Layer3IPManipulator PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared/layer3)


target_compile_definitions(Layer3IPManipulator PRIVATE  Layer3IPManipulator_VERSION=0.1)
