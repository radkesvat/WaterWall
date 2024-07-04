
add_library(RealityClient STATIC
    reality_client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/openssl/openssl_globals.c
      
)

#ww api
target_include_directories(RealityClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(RealityClient ww)
target_include_directories(RealityClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/openssl)
target_include_directories(RealityClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/reality)


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

target_link_libraries(RealityClient 
    OpenSSL::SSL
    OpenSSL::Crypto
    OpenSSL::applink
)

target_compile_definitions(RealityClient PRIVATE RealityClient_VERSION=0.1)

