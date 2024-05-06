

add_library(TrojanAuthServer STATIC
      trojan_auth_server.c
      ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tunnels/shared/trojan/sha2.c         
)


#ww api
target_include_directories(TrojanAuthServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../ww)
target_include_directories(TrojanAuthServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tunnels/)
target_link_libraries(TrojanAuthServer ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(TrojanAuthServer PRIVATE TrojanAuthServer_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(TrojanAuthServer PRIVATE  DEBUG=1)

endif()