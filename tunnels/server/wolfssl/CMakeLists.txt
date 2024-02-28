

add_library(WolfSSLServer STATIC
      wolfssl_server.c
      libwolfssl.a
                 
)

#cmake is not able to build faster version of wolfssl yet, we used this:
# ./configure  --enable-distro --enable-sp=rsa2048,asm --enable-harden --enable-static --enable-fast-rsa --enable-opensslall --enable-opensslextra --enable-tls13 --disable-oldtls --enable-intelasm	--enable-aesni 
# generate configure with autoreconf -i
# Note: before configure, add 
# AC_DEFINE([NO_WOLFSSL_STUB], [1], [Description here])
# to configure.ac !


#ww api
target_include_directories(WolfSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(WolfSSLServer ww)
target_link_libraries(WolfSSLServer libwolfssl.a)
# target_compile_options(ww PUBLIC -fPIC)  

# add dependencies
include(../../../cmake/CPM.cmake)


CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)


if(stc_ADDED)
  target_include_directories(WolfSSLServer PUBLIC ${stc_SOURCE_DIR}/include)
endif()


# add openssl (default version is 3.2)
CPMAddPackage(
    NAME wolfssl
    VERSION 5.6.6-stable
    GITHUB_REPOSITORY wolfSSL/wolfssl
    OPTIONS
    "WOLFSSL_OPENSSLEXTRA ON"
    "WOLFSSL_OPENSSLALL ON"
)

target_compile_options(WolfSSLServer PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(WolfSSLServer PRIVATE STC_STATIC=1 WolfSSLServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(WolfSSLServer PRIVATE  DEBUG=1)
endif()

target_include_directories(WolfSSLServer PRIVATE $<TARGET_PROPERTY:wolfssl,INTERFACE_INCLUDE_DIRECTORIES>)
