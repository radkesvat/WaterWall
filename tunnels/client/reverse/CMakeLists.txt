
add_library(ReverseClient STATIC
                reverse_client.c
                 
)

#ww api
target_include_directories(ReverseClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(ReverseClient ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(ReverseClient PRIVATE ReverseClient_VERSION=0.1)
