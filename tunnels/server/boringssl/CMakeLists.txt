

add_library(BoringSSLServer STATIC
      boringssl_server.c
      
)

# target_include_directories(BoringSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(BoringSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(BoringSSLServer ww)
# target_compile_options(ww PUBLIC -fPIC)  

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)


if(stc_ADDED)
  target_include_directories(BoringSSLServer PUBLIC ${stc_SOURCE_DIR}/include)
endif()



CPMAddPackage(
    NAME boringssl
    GIT_TAG  "fips-20220613"
    GITHUB_REPOSITORY google/boringssl
    OPTIONS
    "BUILD_SHARED_LIBS OFF"

)

target_compile_options(BoringSSLServer PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(BoringSSLServer PRIVATE STC_STATIC=1 BoringSSLServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(BoringSSLServer PRIVATE  DEBUG=1)
endif()

target_link_libraries(BoringSSLServer ssl)
