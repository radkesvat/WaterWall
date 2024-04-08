

add_library(BoringSSLServer STATIC
      boringssl_server.c
      
)

# target_include_directories(BoringSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(BoringSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(BoringSSLServer ww)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)





CPMAddPackage(
    NAME boringssl
    GIT_TAG  "fips-20220613"
    GITHUB_REPOSITORY google/boringssl
    OPTIONS
    "BUILD_SHARED_LIBS OFF"

)

target_compile_definitions(BoringSSLServer PRIVATE BoringSSLServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(BoringSSLServer PRIVATE  DEBUG=1)
endif()

target_link_libraries(BoringSSLServer ssl)
