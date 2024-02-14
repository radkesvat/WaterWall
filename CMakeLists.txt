cmake_minimum_required(VERSION 3.14 FATAL_ERROR)


# create project
project(Waterwall VERSION 0.1)




# add executable
add_executable(Waterwall src/main.c
                   src/connection.c
                   src/tunnel.c
                   src/router.c
                   src/shiftbuffer.c
                   src/utils/context_buffer.c
                   src/utils/utils.c
                   src/dispatchers/buffer_dispatcher.c
                   src/dispatchers/socket_dispatcher.c
                   src/dispatchers/node_dispatcher.c
                   src/tunnels/client/mux_client.c
                   src/tunnels/client/zero_rtt_client.c
                   src/adapters/listeners/tcp_listener.c
)




target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)


# add dependencies
include(cmake/CPM.cmake)

# add komi hash
# CPMAddPackage("gh:avaneev/komihash#5.10")
# CPMAddPackage("gh:JacksonAllan/CC#v1.0.4")

CPMAddPackage(
  NAME komihash
  GIT_REPOSITORY https://github.com/avaneev/komihash.git
  GIT_TAG 5.10
  DOWNLOAD_ONLY True
)


if(komihash_ADDED)
  target_include_directories(Waterwall PUBLIC ${komihash_SOURCE_DIR})
endif()



CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)
target_compile_definitions(Waterwall PUBLIC STC_STATIC=1)


if(stc_ADDED)
  target_include_directories(Waterwall PUBLIC ${stc_SOURCE_DIR}/include)
  target_sources(Waterwall PUBLIC ${stc_SOURCE_DIR}/src/libstc.c)

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
  target_include_directories(Waterwall PUBLIC ${cjson_SOURCE_DIR})
  target_sources(Waterwall PUBLIC ${cjson_SOURCE_DIR}/cJSON.c)

endif()



# CPMAddPackage(
#   NAME uuid4
#   GIT_REPOSITORY https://github.com/gpakosz/uuid4.git 
#   GIT_TAG HEAD
#   DOWNLOAD_ONLY True
# )


# if(uuid4_ADDED)
#   target_include_directories(Waterwall PUBLIC ${uuid4_SOURCE_DIR}/src/)
#   target_sources(Waterwall PUBLIC ${uuid4_SOURCE_DIR}/src/uuid4.c)


# endif()






# add openssl (default version is 3.2)
CPMAddPackage(
    NAME openssl-cmake
    URL https://github.com/jimmy-park/openssl-cmake/archive/main.tar.gz
    OPTIONS
    "OPENSSL_CONFIGURE_OPTIONS no-shared\\\\;no-tests"
)

# add libhv
CPMAddPackage(
    NAME libhv
    VERSION 1.3.2
    GITHUB_REPOSITORY ithewei/libhv
    OPTIONS "WITH_OPENSSL ON"
)

# for release, define NDEBUG !
target_compile_definitions(Waterwall PUBLIC DEBUG=1)
# target_compile_definitions(Waterwall PRIVATE NDEBUG=1)


target_compile_options(Waterwall PUBLIC -ftrack-macro-expansion=0)



message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Waterwall version: ${Waterwall_VERSION}")

# link dependencies
target_link_libraries(Waterwall hv_static)

# set_property(TARGET Waterwall PROPERTY C_STANDARD 99)

# set output path to build/bin/
set_target_properties(Waterwall
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)