cmake_minimum_required(VERSION 3.14 FATAL_ERROR)


set(CMAKE_C_STANDARD 17  CACHE INTERNAL  "C standard version" FORCE)
set(CMAKE_CXX_STANDARD 17 CACHE INTERNAL  "CXX standard version" FORCE)
set(CMAKE_C_STANDARD_REQUIRED TRUE CACHE BOOL "request not to use lower versions" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE CACHE BOOL "request not to use lower versions" FORCE)

# set(CMAKE_VERBOSE_MAKEFILE ON CACHE STRING "my configurable string" FORCE)
# set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address" CACHE STRING "my configurable string" FORCE)
# set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address" CACHE STRING "my configurable string" FORCE)
# set(CMAKE_EXE_LINKER_FLAGS_DEBUG  "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer  -fsanitize=address" CACHE STRING "my configurable string" FORCE)

set(ENABLE_ASAN OFF CACHE BOOL "enable address sanitizer" FORCE)

option(INCLUDE_TCP_LISTENER "link TcpListener staticly to the core"  TRUE)
option(INCLUDE_LOGGER_TUNNEL "link LoggerTunnel staticly to the core"  TRUE)
option(INCLUDE_CONNECTOR "link Connector staticly to the core"  TRUE)
option(INCLUDE_TCPCONNECTOR "link TcpConnector staticly to the core"  TRUE)
option(INCLUDE_BRIDGE "link Bridge staticly to the core"  TRUE)

option(INCLUDE_OPENSSL_SERVER "link OpenSSlServer staticly to the core"  TRUE)
option(INCLUDE_OPENSSL_CLIENT "link OpenSSLClient staticly to the core"  TRUE)
option(INCLUDE_TROJAN_AUTH_SERVER "link TrojanAuthServer staticly to the core"  TRUE)
option(INCLUDE_TROJAN_SOCKS_SERVER "link TrojanSocksServer staticly to the core"  TRUE)
option(INCLUDE_WOLFSSL_SERVER "link WolfSSLServer staticly to the core"  TRUE)
option(INCLUDE_BORINGSSL_SERVER "link BoringSSLServer staticly to the core"  FALSE) #conflicts with openssl/noprefix
option(INCLUDE_HTTP2_SERVER "link Http2Server staticly to the core"  TRUE)
option(INCLUDE_HTTP2_CLIENT "link Http2Client staticly to the core"  TRUE)
option(INCLUDE_PROTOBUF_SERVER "link ProtoBufServer staticly to the core"  TRUE)
option(INCLUDE_PROTOBUF_CLIENT "link ProtoBufClient staticly to the core"  TRUE)
option(INCLUDE_REVERSE_SERVER "link ReverseServer staticly to the core"  TRUE)
option(INCLUDE_REVERSE_CLIENT "link ReverseClient staticly to the core"  TRUE)
# option(INCLUDE_HEADER_SERVER "link HeaderServer staticly to the core"  TRUE)
option(INCLUDE_HEADER_CLIENT "link HeaderClient staticly to the core"  TRUE)

# create project
project(Waterwall VERSION 0.1)

set(OPENSSL_CONFIGURE_VERBOSE ON)


# file(GLOB_RECURSE ltdlcore RELATIVE ${CMAKE_SOURCE_DIR} "core/libltdl/*.c")

# add executable
add_executable(Waterwall core/main.c
                  core/core_settings.c
                  core/static_tunnels.c
               
)


# download CPM.cmake
file(
  DOWNLOAD
  https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.38.7/CPM.cmake
  ${CMAKE_BINARY_DIR}/cmake/CPM.cmake
)
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)



target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core)
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)



#ww api
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_link_libraries(Waterwall ww)

#tcp listener
if (INCLUDE_TCP_LISTENER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_TCP_LISTENER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/tcp_listener)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/tcp_listener)
target_link_libraries(Waterwall TcpListener)
endif()

#connector
if (INCLUDE_CONNECTOR)
target_compile_definitions(Waterwall PUBLIC INCLUDE_CONNECTOR=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/connector)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/connector)
target_link_libraries(Waterwall Connector)
endif()

#tcp connector
if (INCLUDE_TCPCONNECTOR)
target_compile_definitions(Waterwall PUBLIC INCLUDE_TCPCONNECTOR=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/bridge)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/bridge)
target_link_libraries(Waterwall Bridge)
endif()

#bridge
if (INCLUDE_BRIDGE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_BRIDGE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/tcp_connector)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/tcp_connector)
target_link_libraries(Waterwall TcpConnector)
endif()

#http2 server
if (INCLUDE_OPENSSL_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_HTTP2_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/http2)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/http2)
target_link_libraries(Waterwall Http2Server)
endif()

#http2 client
if (INCLUDE_HTTP2_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_HTTP2_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/http2)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/http2)
target_link_libraries(Waterwall Http2Client)
endif()

#openssl server
if (INCLUDE_OPENSSL_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_OPENSSL_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/openssl)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/openssl)
target_link_libraries(Waterwall OpenSSLServer)
endif()

#openssl client
if (INCLUDE_OPENSSL_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_OPENSSL_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/openssl)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/openssl)
target_link_libraries(Waterwall OpenSSLClient)
endif()

#trojan auth server
if (INCLUDE_TROJAN_AUTH_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_TROJAN_AUTH_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/auth)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/socks)
target_link_libraries(Waterwall TrojanAuthServer)
endif()

#trojan socks server
if (INCLUDE_TROJAN_SOCKS_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_TROJAN_SOCKS_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/socks)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/socks)
target_link_libraries(Waterwall TrojanSocksServer)
endif()

#wolf ssl server
if (INCLUDE_WOLFSSL_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_WOLFSSL_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/wolfssl)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/wolfssl)
target_link_libraries(Waterwall WolfSSLServer)
endif()

#boring ssl server
if (INCLUDE_BORINGSSL_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_BORINGSSL_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/boringssl)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/boringssl)
target_link_libraries(Waterwall BoringSSLServer)
endif()

#logger tunnel
if (INCLUDE_LOGGER_TUNNEL)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LOGGER_TUNNEL=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/logger)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/logger)
target_link_libraries(Waterwall LoggerTunnel)
endif()


#protobuf server
if (INCLUDE_PROTOBUF_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_PROTOBUF_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/protobuf)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/protobuf)
target_link_libraries(Waterwall ProtoBufServer)
endif()

#protobuf client
if (INCLUDE_PROTOBUF_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_PROTOBUF_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/protobuf)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/protobuf)
target_link_libraries(Waterwall ProtoBufClient)
endif()


#reverse server
if (INCLUDE_REVERSE_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_REVERSE_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/reverse)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/reverse)
target_link_libraries(Waterwall ReverseServer)
endif()

#reverse client
if (INCLUDE_REVERSE_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_REVERSE_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/reverse)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/reverse)
target_link_libraries(Waterwall ReverseClient)
endif()


#reverse client
if (INCLUDE_HEADER_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_HEADER_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/header)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/header)
target_link_libraries(Waterwall HeaderClient)
endif()




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


target_compile_definitions(Waterwall PUBLIC STC_STATIC=1 WATERWALL_VERSION=${Waterwall_VERSION})
target_compile_definitions(Waterwall PUBLIC NODES_STATIC=1 )
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(Waterwall PRIVATE  DEBUG=1)
endif()

add_compile_options(
  $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Werror>
)


if(ENABLE_ASAN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(Waterwall PUBLIC -fsanitize=address)
  target_link_options(Waterwall PUBLIC -fsanitize=address)
endif()
# target_compile_options(Waterwall PUBLIC -pedantic)

message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Waterwall version: ${Waterwall_VERSION}")

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
