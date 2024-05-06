

add_library(Bridge STATIC
                    bridge.c
                 
)


#ww api
target_include_directories(Bridge PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Bridge ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)





target_compile_definitions(Bridge PRIVATE  Bridge_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(Bridge PRIVATE  DEBUG=1)

endif()
