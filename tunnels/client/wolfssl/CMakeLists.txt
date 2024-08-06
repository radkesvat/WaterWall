
add_library(WolfSSLClient STATIC
      wolfssl_client.c                 
)

# This paragraph is disabled since wolfssl 5.7 update now has much better cmake interface
## ./configure  --enable-distro --enable-sp=rsa2048,asm --enable-harden --enable-static --enable-fast-rsa --enable-opensslall --enable-opensslextra --enable-tls13 --disable-oldtls --enable-intelasm --enable-aesni 
## generate configure with autoreconf -i  (sudo apt-get install autoconf) (sudo apt-get install libtool-bin)
## Note: before configure, add 
## AC_DEFINE([NO_WOLFSSL_STUB], [1], [Description here])
## to configure.ac !
## if compiling for ARM: ./configure  --enable-distro --enable-sp=rsa2048,asm --enable-harden --enable-static --enable-fast-rsa --enable-opensslall --enable-opensslextra --enable-tls13 --disable-oldtls
## libs will be saved at: /src/.libs/libwolfssl.a

target_link_libraries(WolfSSLClient ww)

target_include_directories(WolfSSLClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/wolfssl)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

# todo (WOLFSSL_CRYPTOCB) check this option doing anything useful and required or not (enables padding settings like openssl?)
CPMAddPackage(
    NAME wolfssl
    VERSION 5.7.0-stable
    GITHUB_REPOSITORY wolfSSL/wolfssl
    OPTIONS
    "WOLFSSL_REPRODUCIBLE_BUILD ON"
    "WOLFSSL_ALPN ON"
    "WOLFSSL_HARDEN ON"
    "WOLFSSL_OPENSSLEXTRA ON"
    "WOLFSSL_OPENSSLALL ON"
    "WOLFSSL_SNI  ON"
    "WOLFSSL_SESSION_TICKET ON"
    "WOLFSSL_EXAMPLES OFF"
    "WOLFSSL_CRYPT_TESTS OFF"
    "WOLFSSL_ASYNC_THREADS OFF"
    "BUILD_SHARED_LIBS OFF"
)
target_compile_definitions(wolfssl PRIVATE  NO_WOLFSSL_STUB=1 DEBUG_WOLFSSL_VERBOSE=1)
target_compile_definitions(WolfSSLClient PRIVATE  WolfSSLClient_VERSION=0.1)


# this code is used for linking with prebuilt .a (which you built with autoconf)
# target_link_directories(WolfSSLClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/wolfssl)
# if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "aarch64")
# target_link_libraries(WolfSSLClient libwolfssl_arm64.a)
# else()
# target_link_libraries(WolfSSLClient libwolfssl_amd64.a)
# endif()
# target_include_directories(WolfSSLClient PRIVATE $<TARGET_PROPERTY:wolfssl,INTERFACE_INCLUDE_DIRECTORIES>)

# this code is used for linking with cmake built wolfssl
target_link_libraries(WolfSSLClient wolfssl)
