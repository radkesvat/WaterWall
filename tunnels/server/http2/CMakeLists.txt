add_library(Http2Server STATIC
      http2_server.c
)


#ww api
target_include_directories(Http2Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Http2Server PUBLIC ww)


target_include_directories(Http2Server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/http2)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)



CPMAddPackage(
    NAME nghttp2
    GIT_TAG v1.60.0
    GITHUB_REPOSITORY nghttp2/nghttp2
    OPTIONS 
    "BUILD_STATIC_LIBS ON"
    "BUILD_TESTING OFF"
    # "ENABLE_DEBUG ON "
         

)

target_link_libraries(Http2Server PUBLIC nghttp2_static)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(Http2Server PRIVATE  DEBUG=1)
endif()
