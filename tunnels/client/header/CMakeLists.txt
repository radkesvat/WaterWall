add_library(HeaderClient STATIC
      header_client.c

)



#ww api
target_include_directories(HeaderClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(HeaderClient PUBLIC ww)



# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(HeaderClient PRIVATE  HeaderClient_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(HeaderClient PRIVATE  DEBUG=1)
endif()
