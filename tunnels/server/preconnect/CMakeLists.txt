add_library(PreConnectServer STATIC
    preconnect_server.c

)



#ww api
target_include_directories(PreConnectServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(PreConnectServer PUBLIC ww)



# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)



target_compile_definitions(PreConnectServer PRIVATE PreConnectServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(PreConnectServer PRIVATE  DEBUG=1)
endif()
