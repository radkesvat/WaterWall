

add_library(OpenSSLServer STATIC
      openssl_server.c
                 
)

# target_include_directories(OpenSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#ww api
target_include_directories(OpenSSLServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(OpenSSLServer ww)
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
  target_include_directories(OpenSSLServer PUBLIC ${stc_SOURCE_DIR}/include)
endif()



target_compile_options(OpenSSLServer PRIVATE -ftrack-macro-expansion=0)
target_compile_definitions(OpenSSLServer PRIVATE STC_STATIC=1 OpenSSLServer_VERSION=0.1)


if(CMAKE_BUILD_TYPE STREQUAL "DEBUG")
target_compile_definitions(OpenSSLServer PRIVATE  DEBUG=1)

endif()