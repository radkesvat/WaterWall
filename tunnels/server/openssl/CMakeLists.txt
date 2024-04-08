

add_library(OpenSSLServer STATIC
      openssl_server.c
      
)

# target_include_directories(OpenSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(OpenSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(OpenSSLServer ww)


target_include_directories(OpenSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/openssl)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)



# add openssl (default version is 3.2)
CPMAddPackage(
    NAME openssl-cmake
    URL https://github.com/jimmy-park/openssl-cmake/archive/main.tar.gz
    OPTIONS
    "OPENSSL_CONFIGURE_OPTIONS no-shared\\\\;no-tests"
    "BUILD_SHARED_LIBS OFF"
)

target_link_libraries(OpenSSLServer 
    OpenSSL::SSL
    OpenSSL::Crypto
    OpenSSL::applink
)

target_compile_definitions(OpenSSLServer PRIVATE OpenSSLServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(OpenSSLServer PRIVATE  DEBUG=1)

endif()