

add_library(Listener STATIC
                    listener.c
  
)

# target_include_directories(Listener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
#ww api
target_include_directories(Listener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Listener ww)
# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(Listener PRIVATE  Listener_VERSION=0.1)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(Listener PRIVATE  DEBUG=1)
endif()
