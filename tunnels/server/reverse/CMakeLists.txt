

add_library(ReverseServer STATIC
                reverse_server.c
                 
)


#ww api
target_include_directories(ReverseServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(ReverseServer ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(ReverseServer PRIVATE  ReverseServer_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(ReverseServer PRIVATE  DEBUG=1)

endif()
