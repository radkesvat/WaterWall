
add_library(PreConnectClient STATIC
      preconnect_client.c

)

target_link_libraries(PreConnectClient PUBLIC ww)



# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(PreConnectClient PRIVATE  PreConnectClient_VERSION=0.1)
