
add_library(RealityServer STATIC
        reality_server.c
      
)

#ww api
target_include_directories(RealityServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(RealityServer ww)

target_include_directories(RealityServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/openssl)
target_include_directories(RealityServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/reality)

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

target_link_libraries(RealityServer 
    OpenSSL::SSL
    OpenSSL::Crypto
    OpenSSL::applink
)

target_compile_definitions(RealityServer PRIVATE RealityServer_VERSION=0.1)
