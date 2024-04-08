add_library(HeaderServer STATIC
      header_server.c

)



#ww api
target_include_directories(HeaderServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(HeaderServer PUBLIC ww)



# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)



target_compile_definitions(HeaderServer PRIVATE  HeaderServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(HeaderServer PRIVATE  DEBUG=1)
endif()
