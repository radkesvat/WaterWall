

add_library(WolfSSLServer STATIC
      wolfssl_server.c                 
)

#cmake is not able to build fastest version of wolfssl yet (because all asm options are not provided in cmakelist), we used this:
# ./configure  --enable-distro --enable-sp=rsa2048,asm --enable-harden --enable-static --enable-fast-rsa --enable-opensslall --enable-opensslextra --enable-tls13 --disable-oldtls --enable-intelasm	--enable-aesni 
# generate configure with autoreconf -i  (sudo apt-get install autoconf) (sudo apt-get install libtool-bin)
# Note: before configure, add 
# AC_DEFINE([NO_WOLFSSL_STUB], [1], [Description here])
# to configure.ac !

# if compiling for ARM: ./configure  --enable-distro --enable-sp=rsa2048,asm --enable-harden --enable-static --enable-fast-rsa --enable-opensslall --enable-opensslextra --enable-tls13 --disable-oldtls
# /src/.libs/libwolfssl.a


#ww api
target_include_directories(WolfSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(WolfSSLServer ww)
# todo select correct processor
if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "aarch64")
target_link_libraries(WolfSSLServer libwolfssl_arm64.a)
else()
target_link_libraries(WolfSSLServer libwolfssl_amd64.a)
endif()

# target_compile_options(ww PUBLIC -fPIC)  

target_include_directories(WolfSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/wolfssl)


# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)



CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)


if(stc_ADDED)
  target_include_directories(WolfSSLServer PUBLIC ${stc_SOURCE_DIR}/include)
endif()


CPMAddPackage(
    NAME wolfssl
    VERSION 5.6.6-stable
    GITHUB_REPOSITORY wolfSSL/wolfssl
    OPTIONS
    "WOLFSSL_OPENSSLEXTRA ON"
    "WOLFSSL_OPENSSLALL ON"
    "WOLFSSL_EXAMPLES OFF"
    "WOLFSSL_CRYPT_TESTS OFF"
    "WOLFSSL_EXAMPLES OFF"
    "WOLFSSL_EXAMPLES OFF"
    "BUILD_SHARED_LIBS OFF"
)

target_compile_definitions(WolfSSLServer PRIVATE STC_STATIC=1 WolfSSLServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(WolfSSLServer PRIVATE  DEBUG=1)
endif()

target_include_directories(WolfSSLServer PRIVATE $<TARGET_PROPERTY:wolfssl,INTERFACE_INCLUDE_DIRECTORIES>)
