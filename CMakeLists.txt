cmake_minimum_required(VERSION 3.14 FATAL_ERROR)



option(CORE_BUILD_RELEASE "compile core for release build"  FALSE)
option(WW_BUILD_RELEASE "compile runtime lib for release build"  FALSE)
option(NODES_BUILD_RELEASE "compile runtime nodes for release build"  FALSE)

option(INCLUDE_TCP_LISTENER "link TcpListener staticly to the core"  TRUE)

# set(CMAKE_BUILD_TYPE Release)


# create project
project(Waterwall VERSION 0.1)



# file(GLOB_RECURSE ltdlcore RELATIVE ${CMAKE_SOURCE_DIR} "core/libltdl/*.c")

# add executable
add_executable(Waterwall core/main.c
                   core/core_settings.c
                  #  core/tunnels/server/trojan/trojan_auth_server.c
                  #  core/tunnels/shared/trojan/sha2.c
                  #  core/tunnels/adapters/listeners/tcp_listener.c
)



target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core)
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)





#ww api
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_link_libraries(Waterwall ww)

#tcp listener
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/tcp_listener)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/tcp_listener)
target_link_libraries(Waterwall ww)





# add dependencies
include(cmake/CPM.cmake)

# komihash
CPMAddPackage(
  NAME komihash
  GIT_REPOSITORY https://github.com/avaneev/komihash.git
  GIT_TAG 5.10
  DOWNLOAD_ONLY True
)
if(komihash_ADDED)
  target_include_directories(Waterwall PUBLIC ${komihash_SOURCE_DIR})
endif()


# stc - cstdlib
CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/stclib/STC
  GIT_TAG 09790f024ad29fca6fe60528461eeb589d4a917b
  DOWNLOAD_ONLY True
)
if(stc_ADDED)
  target_include_directories(Waterwall PUBLIC ${stc_SOURCE_DIR}/include)
  # target_sources(Waterwall PUBLIC ${stc_SOURCE_DIR}/core/libstc.c)
endif()



# cJson
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



# openssl (default version is 3.2)
CPMAddPackage(
    NAME openssl-cmake
    URL https://github.com/jimmy-park/openssl-cmake/archive/main.tar.gz
    OPTIONS
    "OPENSSL_CONFIGURE_OPTIONS no-shared\\\\;no-tests"
)

# libhv
CPMAddPackage(
    NAME libhv
    VERSION 1.3.2
    GITHUB_REPOSITORY ithewei/libhv
    OPTIONS "WITH_OPENSSL ON" "BUILD_SHARED OFF"
)


target_compile_definitions(Waterwall PUBLIC STC_STATIC=1 WATERWALL_VERSION=${Waterwall_VERSION})
target_compile_definitions(Waterwall PUBLIC NODES_STATIC=1)
if(CORE_BUILD_RELEASE)
target_compile_definitions(Waterwall PRIVATE g NDEBUG=1)
else()
target_compile_definitions(Waterwall PRIVATE O3 DEBUG=1)

endif()


target_compile_options(Waterwall PUBLIC -ftrack-macro-expansion=0)
# target_compile_options(Waterwall PUBLIC -pedantic)

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


# get_target_property(target_options Waterwall COMPILE_OPTIONS)
# list(REMOVE_ITEM target_options "-pedantic")
# set_property(TARGET Waterwall PROPERTY COMPILE_OPTIONS ${target_options})
# set_property(TARGET Waterwall PROPERTY C_STANDARD 11)
