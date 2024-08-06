
add_library(HeaderClient STATIC
      header_client.c

)

target_link_libraries(HeaderClient PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(HeaderClient PRIVATE  HeaderClient_VERSION=0.1)
