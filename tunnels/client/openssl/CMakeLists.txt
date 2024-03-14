

add_library(OpenSSLClient STATIC
      openssl_client.c
      
)

# target_include_directories(OpenSSLClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(OpenSSLClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(OpenSSLClient ww)
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
  target_include_directories(OpenSSLClient PUBLIC ${stc_SOURCE_DIR}/include)
endif()


# add openssl (default version is 3.2)
CPMAddPackage(
    NAME openssl-cmake
    URL https://github.com/jimmy-park/openssl-cmake/archive/main.tar.gz
    OPTIONS
    "OPENSSL_CONFIGURE_OPTIONS no-shared\\\\;no-tests"
    "BUILD_SHARED_LIBS OFF"
)

target_compile_options(OpenSSLClient PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(OpenSSLClient PRIVATE STC_STATIC=1 OpenSSLClient_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(OpenSSLClient PRIVATE  DEBUG=1)

endif()