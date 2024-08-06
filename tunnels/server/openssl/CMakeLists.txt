
add_library(OpenSSLServer STATIC
      openssl_server.c
)

target_link_libraries(OpenSSLServer ww OpenSSLGlobals)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)    

# add openssl (default version is latest 3.3.0 +)
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

set(BUILD_OPENSSL_GLOBALS TRUE PARENT_SCOPE)

target_compile_definitions(OpenSSLServer PRIVATE OpenSSLServer_VERSION=0.1)
