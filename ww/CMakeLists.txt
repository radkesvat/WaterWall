

add_library(ww STATIC
                  ww.c
                  tunnel.c
                  shiftbuffer.c
                  library_loader.c
                  context_queue.c
                  buffer_stream.c
                  config_file.c
                  buffer_pool.c
                  http_def.c
                  cacert.c
                  utils/utils.c
                  managers/socket_manager.c
                  managers/node_manager.c
                  loggers/core_logger.c
                  loggers/network_logger.c
                  loggers/dns_logger.c


  
)

target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


CPMAddPackage(
  NAME komihash
  GIT_REPOSITORY https://github.com/avaneev/komihash.git
  GIT_TAG 5.10
  DOWNLOAD_ONLY True
)


if(komihash_ADDED)
  target_include_directories(ww PUBLIC ${komihash_SOURCE_DIR})
endif()


CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)


if(stc_ADDED)
  target_include_directories(ww PUBLIC ${stc_SOURCE_DIR}/include)
  # target_sources(ww PRIVATE ${stc_SOURCE_DIR}/src/libstc.c)

endif()



# add cJson
CPMAddPackage(
    NAME cjson
    VERSION 1.7.17
    GITHUB_REPOSITORY DaveGamble/cJSON
    OPTIONS "BUILD_SHARED_LIBS OFF" "BUILD_SHARED_AND_STATIC_LIBS On"
    DOWNLOAD_ONLY True

)
if(cjson_ADDED)
  target_include_directories(ww PUBLIC ${cjson_SOURCE_DIR})
  target_sources(ww PRIVATE ${cjson_SOURCE_DIR}/cJSON.c)

endif()


# add libhv
CPMAddPackage(
    NAME libhv
    GIT_TAG HEAD
    GITHUB_REPOSITORY radkesvat/libhv
    OPTIONS 
    "WITH_OPENSSL OFF"
    "WITH_EVPP OFF"
    "WITH_HTTP OFF"
    "WITH_HTTP_SERVER OFF"
    "WITH_HTTP_CLIENT OFF"
    "BUILD_SHARED OFF"
    "BUILD_EXAMPLES OFF"
    

)
# target_compile_options(hv_static PRIVATE -fPIC) 
# target_compile_options(ww PUBLIC -fPIC)  
# message( FATAL_ERROR "Y" )

# target_compile_options(ww PUBLIC -pg)
# target_link_options(ww PUBLIC -pg)

if(ENABLE_ASAN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(ww PUBLIC -fsanitize=address)
  target_link_options(ww PUBLIC -fsanitize=address)
endif()

# clang-tidy dose not like this even if cc = gcc
# if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
# target_compile_options(ww PUBLIC -ftrack-macro-expansion=0)
# endif()

target_compile_definitions(ww PUBLIC STC_STATIC=1 WW_VERSION=0.1)
target_link_libraries(ww hv_static) 


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(ww PRIVATE DEBUG=1)
endif()

