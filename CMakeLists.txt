cmake_minimum_required(VERSION 3.25 FATAL_ERROR)

cmake_policy(SET CMP0091 NEW)

if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD) 
  set(CMAKE_POLICY_DEFAULT_CMP0169 OLD)
endif()


project(Waterwall VERSION 1.32)


set(CMAKE_C_STANDARD 11  CACHE INTERNAL  "C standard version" FORCE)
set(CMAKE_CXX_STANDARD 11 CACHE INTERNAL  "CXX standard version" FORCE)
set(CMAKE_C_STANDARD_REQUIRED TRUE CACHE BOOL "request not to use lower versions" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE CACHE BOOL "request not to use lower versions" FORCE)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")      for 32 bit build, note that ssl libs need tweaks
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")

# set(CMAKE_EXE_LINKER_FLAGS ""  CACHE INTERNAL "")

# untill they update the CPM library, i don't want a dirty build log system
#   CMake Warning (dev) at /snap/cmake/1408/share/cmake-3.30/Modules/FetchContent.cmake:1953 (message):
#   [cmake]   Calling FetchContent_Populate(komihash) is deprecated, call
#   [cmake]   FetchContent_MakeAvailable(komihash) instead.  Policy CMP0169 can be set to
#   [cmake]   OLD to allow FetchContent_Populate(komihash) to be called directly for now,
#   [cmake]   but the ability to call it with declared details will be removed completely
#   [cmake]   in a future version.


if(CMAKE_BUILD_TYPE STREQUAL "Release")
  cmake_policy(SET CMP0069 NEW) 
  set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
  include(CheckIPOSupported)
  check_ipo_supported()
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

  # enabling lto for clang is done thisway, because thin-lto is the clang default 
  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_C_COMPILE_OPTIONS_IPO  "-flto")
    set(CMAKE_CXX_COMPILE_OPTIONS_IPO  "-flto")
    
    # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-instr-generate")
    # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-instr-use=${CMAKE_CURRENT_SOURCE_DIR}/build/bin/code.profdata")
    # add_compile_options(-Wno-profile-instr-unprofiled)

  endif()
endif()

# force link glibc ver 2.27
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -include  ${CMAKE_CURRENT_SOURCE_DIR}/core/force_link_glibc_2.27.h")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include  ${CMAKE_CURRENT_SOURCE_DIR}/core/force_link_glibc_2.27.h")


set(ENABLE_ASAN OFF CACHE BOOL "enable address sanitizer" FORCE)
set(ENABLE_TSAN OFF CACHE BOOL "enable thread sanitizer" FORCE)
set(ENABLE_LSAN OFF CACHE BOOL "enable leak sanitizer" FORCE)
set(ENABLE_USAN OFF CACHE BOOL "enable undefined behaviour sanitizer" FORCE)


option(INCLUDE_TEMPLATE "link Template staticly to the core"  TRUE)


option(INCLUDE_WIREGUARD_DEVICE "link WireGuardDevice staticly to the core"  TRUE)
option(INCLUDE_LAYER3_RECEIVER "link Layer3Receiver staticly to the core"  FALSE)
option(INCLUDE_LAYER3_SENDER "link Layer3Sender staticly to the core"  FALSE)
option(INCLUDE_LAYER3_IP_ROUTING_TABLE "link Layer3IpRoutingTable staticly to the core"  FALSE)
option(INCLUDE_LAYER3_IP_OVERRIDER "link Layer3IpOverrider staticly to the core"  FALSE)
option(INCLUDE_LAYER3_IP_MANIPULATOR "link Layer3IPManipulator staticly to the core"  FALSE)
option(INCLUDE_LAYER3_TCP_MANIPULATOR "link Layer3TcpManipulator staticly to the core"  FALSE)

option(INCLUDE_TCP_LISTENER "link TcpListener staticly to the core"  TRUE)
option(INCLUDE_UDP_LISTENER "link UdpListener staticly to the core"  FALSE)
option(INCLUDE_LISTENER "link Listener staticly to the core"  FALSE)
option(INCLUDE_LOGGER_TUNNEL "link LoggerTunnel staticly to the core"  FALSE)
option(INCLUDE_CONNECTOR "link Connector staticly to the core"  FALSE)
option(INCLUDE_TCPCONNECTOR "link TcpConnector staticly to the core"  TRUE)
option(INCLUDE_UDP_CONNECTOR "link UdpConnector staticly to the core"  FALSE)
option(INCLUDE_BRIDGE "link Bridge staticly to the core"  FALSE)

if(LINUX) # todo (other platforms)
  option(INCLUDE_TUNDEVICE "link TunDevice staticly to the core"  FALSE)
  option(INCLUDE_RAWDEVICE "link RawDevice staticly to the core"  FALSE)
  option(INCLUDE_CAPTUREDEVICE "link CapTureDevice staticly to the core"  FALSE)
endif()

option(INCLUDE_OPENSSL_SERVER "link OpenSSlServer staticly to the core"  FALSE)
option(INCLUDE_OPENSSL_CLIENT "link OpenSSLClient staticly to the core"  FALSE)
option(INCLUDE_TROJAN_AUTH_SERVER "link TrojanAuthServer staticly to the core"  FALSE)
option(INCLUDE_TROJAN_SOCKS_SERVER "link TrojanSocksServer staticly to the core"  FALSE)
option(INCLUDE_WOLFSSL_SERVER "link WolfSSLServer staticly to the core"  OFF)  # this downloads 750 mb of data!
option(INCLUDE_WOLFSSL_CLIENT "link WolfSSLClient staticly to the core"  OFF)  # this downloads 750 mb of data!
option(INCLUDE_HTTP2_SERVER "link Http2Server staticly to the core"  FALSE)
option(INCLUDE_HTTP2_CLIENT "link Http2Client staticly to the core"  FALSE)
option(INCLUDE_PROTOBUF_SERVER "link ProtoBufServer staticly to the core"  FALSE)
option(INCLUDE_PROTOBUF_CLIENT "link ProtoBufClient staticly to the core"  FALSE)
option(INCLUDE_REVERSE_SERVER "link ReverseServer staticly to the core"  FALSE)
option(INCLUDE_REVERSE_CLIENT "link ReverseClient staticly to the core"  FALSE)
option(INCLUDE_HEADER_SERVER "link HeaderServer staticly to the core"  FALSE)
option(INCLUDE_HEADER_CLIENT "link HeaderClient staticly to the core"  FALSE)
option(INCLUDE_PRECONNECT_SERVER "link PreConnectServer staticly to the core"  FALSE)
option(INCLUDE_PRECONNECT_CLIENT "link PreConnectClient staticly to the core"  FALSE)
option(INCLUDE_SOCKS_5_SERVER "link Socks5Server staticly to the core"  FALSE)
option(INCLUDE_REALITY_SERVER "link RealityServer staticly to the core"  FALSE)
option(INCLUDE_REALITY_CLIENT "link RealityClient staticly to the core"  FALSE)
option(INCLUDE_HALFDUPLEX_SERVER "link HalfDuplexServer staticly to the core"  FALSE)
option(INCLUDE_HALFDUPLEX_CLIENT "link HalfDuplexClient staticly to the core"  FALSE)
option(INCLUDE_BGP4_SERVER "link Bgp4Server staticly to the core"  FALSE)
option(INCLUDE_BGP4_CLIENT "link Bgp4Client staticly to the core"  FALSE)
option(INCLUDE_MUX_SERVER "link MuxServer staticly to the core"  FALSE)
option(INCLUDE_MUX_CLIENT "link MuxClient staticly to the core"  FALSE)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Platform-specific flags
if(MINGW OR MSYS)
    # On Windows (MinGW), statically link libgcc, libstdc++, and libwinpthread
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
elseif(UNIX AND NOT APPLE)
    # On Linux, statically link libstdc++ and libgcc
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()


# add executable
add_executable(Waterwall
                  core/main.c
                  core/core_settings.c
                  core/imported_tunnels.c
                  core/os_helpers.c
                  # core/tests/bench_memcpy.c
)



# download CPM.cmake
file(
  DOWNLOAD
  https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.40.0/CPM.cmake
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





#template
if (INCLUDE_TEMPLATE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_TEMPLATE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/template)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/template)
target_link_libraries(Waterwall Template)
endif()


#tun device
if (INCLUDE_TUNDEVICE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_TUNDEVICE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/device/tun)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/device/tun)
target_link_libraries(Waterwall TunDevice)
endif()

#raw device
if (INCLUDE_RAWDEVICE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_RAWDEVICE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/device/raw)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/device/raw)
target_link_libraries(Waterwall RawDevice)
endif()

#capture device
if (INCLUDE_CAPTUREDEVICE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_CAPTUREDEVICE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/device/capture)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/device/capture)
target_link_libraries(Waterwall CaptureDevice)
endif()

#layer3 receiver
if (INCLUDE_WIREGUARD_DEVICE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_WIREGUARD_DEVICE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/WireGuardDevice)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/WireGuardDevice)
target_link_libraries(Waterwall WireGuardDevice)
endif()


#layer3 receiver
if (INCLUDE_LAYER3_RECEIVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_RECEIVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/receiver)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/receiver)
target_link_libraries(Waterwall Layer3Receiver)
endif()

#layer3 sender
if (INCLUDE_LAYER3_SENDER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_SENDER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/sender)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/sender)
target_link_libraries(Waterwall Layer3Sender)
endif()

#layer3 ip route table
if (INCLUDE_LAYER3_IP_ROUTING_TABLE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_IP_ROUTING_TABLE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/routing_table)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/routing_table)
target_link_libraries(Waterwall Layer3IpRoutingTable)
endif()

#layer3 ip overrider
if (INCLUDE_LAYER3_IP_OVERRIDER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_IP_OVERRIDER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/overrider)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/overrider)
target_link_libraries(Waterwall Layer3IpOverrider)
endif()

#layer3 ip manipulator
if (INCLUDE_LAYER3_IP_MANIPULATOR)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_IP_MANIPULATOR=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/manipulator)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/manipulator)
target_link_libraries(Waterwall Layer3IpManipulator)
endif()

#layer3 tcp manipulator
if (INCLUDE_LAYER3_TCP_MANIPULATOR)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_TCP_MANIPULATOR=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/tcp/manipulator)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/tcp/manipulator)
target_link_libraries(Waterwall Layer3TcpManipulator)
endif()

#tcp listener
if (INCLUDE_TCP_LISTENER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_TCP_LISTENER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpListener)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpListener)
target_link_libraries(Waterwall TcpListener)
endif()

#udp listener
if (INCLUDE_UDP_LISTENER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_LISTENER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/listener/udp)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/listener/udp)
target_link_libraries(Waterwall UdpListener)
endif()

#listener
if (INCLUDE_LISTENER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_LISTENER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/listener)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/listener)
target_link_libraries(Waterwall Listener)
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
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpConnector)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpConnector)
target_link_libraries(Waterwall TcpConnector)
endif()

#udp connector
if (INCLUDE_UDP_CONNECTOR)
target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_CONNECTOR=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/connector/udp)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/connector/udp)
target_link_libraries(Waterwall UdpConnector)
endif()

#bridge
if (INCLUDE_BRIDGE)
target_compile_definitions(Waterwall PUBLIC INCLUDE_BRIDGE=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/bridge)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/bridge)
target_link_libraries(Waterwall Bridge)
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

#wolf ssl client
if (INCLUDE_WOLFSSL_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_WOLFSSL_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/wolfssl)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/wolfssl)
target_link_libraries(Waterwall WolfSSLClient)
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

#header server 
if (INCLUDE_HEADER_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_HEADER_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/header)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/header)
target_link_libraries(Waterwall HeaderServer)
endif()

#header client
if (INCLUDE_HEADER_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_HEADER_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/header)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/header)
target_link_libraries(Waterwall HeaderClient)
endif()

#preconnect server
if (INCLUDE_PRECONNECT_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_PRECONNECT_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/preconnect)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/preconnect)
target_link_libraries(Waterwall PreConnectServer)
endif()

#preconnect client
if (INCLUDE_PRECONNECT_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_PRECONNECT_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/preconnect)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/preconnect)
target_link_libraries(Waterwall PreConnectClient)
endif()

#socks5 server
if (INCLUDE_SOCKS_5_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_SOCKS_5_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/socks/5)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/socks/5)
target_link_libraries(Waterwall Socks5Server)
endif()

#reality server
if (INCLUDE_REALITY_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_REALITY_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/reality)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/reality)
target_link_libraries(Waterwall RealityServer)
endif()

#reality client
if (INCLUDE_REALITY_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_REALITY_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/reality)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/reality)
target_link_libraries(Waterwall RealityClient)
endif()

#halfduplex server
if (INCLUDE_HALFDUPLEX_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_HALFDUPLEX_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/halfduplex)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/halfduplex)
target_link_libraries(Waterwall HalfDuplexServer)
endif()

#halfduplex client
if (INCLUDE_HALFDUPLEX_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_HALFDUPLEX_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/halfduplex)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/halfduplex)
target_link_libraries(Waterwall HalfDuplexClient)
endif()

#bgp4server server
if (INCLUDE_BGP4_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_BGP4_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/bgp4)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/bgp4)
target_link_libraries(Waterwall Bgp4Server)
endif()

#bgp4client client
if (INCLUDE_BGP4_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_BGP4_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/bgp4)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/bgp4)
target_link_libraries(Waterwall Bgp4Client)
endif()

#mux server
if (INCLUDE_MUX_SERVER)
target_compile_definitions(Waterwall PUBLIC INCLUDE_MUX_SERVER=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/mux)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/mux)
target_link_libraries(Waterwall MuxServer)
endif()


#mux client
if (INCLUDE_MUX_CLIENT)
target_compile_definitions(Waterwall PUBLIC INCLUDE_MUX_CLIENT=1)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/mux)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/mux)
target_link_libraries(Waterwall MuxClient)
endif()




#------------------------------------------------------------------------------------------
if (BUILD_OPENSSL_GLOBALS)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/shared/openssl)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/shared/openssl)
endif()


target_compile_definitions(Waterwall PUBLIC WATERWALL_VERSION=${Waterwall_VERSION})
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
target_compile_definitions(Waterwall PRIVATE  DEBUG=1)
endif()


if(OPENSSL_VERSION)
  message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
endif()
message(STATUS "Waterwall version: ${Waterwall_VERSION}")

# set output path to build/bin/

set_target_properties(Waterwall
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

