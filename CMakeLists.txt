#--------------------------------------------------------------------------------
# Project Definition and Basic Configuration
#--------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.25 FATAL_ERROR)

cmake_policy(SET CMP0091 NEW)

if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
  set(CMAKE_POLICY_DEFAULT_CMP0169 OLD)
endif()



project(Waterwall
  VERSION 1.39
  DESCRIPTION "A fast and secure VPN tunnel"
  HOMEPAGE_URL "https://github.com/radkesvat/waterwall"
  LANGUAGES C CXX
)

file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/ww/cmake/version.txt" "${PROJECT_VERSION}\n")

#--------------------------------------------------------------------------------
# Build Type Configuration
#--------------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "CMAKE_BUILD_TYPE not set - defaulting to Release build, on multi-config generators this will be ignored")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: ${CMAKE_CONFIGURATION_TYPES}." FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE} (ignored on multi-config generators)")

# Set static runtime library for MSVC - this is the modern CMake way (dont move this line)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

#--------------------------------------------------------------------------------
# Executable and C/CXX Standards
#--------------------------------------------------------------------------------
set(FINAL_EXECUTABLE_NAME "Waterwall" CACHE STRING "Final executable name" FORCE)

# since Waterwall 1.40, we use C++17 as the minimum standard which is necessary for BoringSSL
set(CMAKE_C_STANDARD 11 CACHE INTERNAL "C standard version" FORCE)
set(CMAKE_CXX_STANDARD 17 CACHE INTERNAL "CXX standard version" FORCE)
set(CMAKE_C_STANDARD_REQUIRED TRUE CACHE BOOL "request not to use lower versions" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE CACHE BOOL "request not to use lower versions" FORCE)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


#--------------------------------------------------------------------------------
# Deprecated CPM Library Warning Suppression
#--------------------------------------------------------------------------------
# The following policy settings are to manage warnings from the CPM library.
# A newer version of CPM might resolve this.
#   CMake Warning (dev) at /snap/cmake/1408/share/cmake-3.30/Modules/FetchContent.cmake:1953 (message):
#   [cmake]   Calling FetchContent_Populate(komihash) is deprecated, call
#   [cmake]   FetchContent_MakeAvailable(komihash) instead.  Policy CMP0169 can be set to
#   [cmake]   OLD to allow FetchContent_Populate(komihash) to be called directly for now,
#   [cmake]   but the ability to call it with declared details will be removed completely
#   [cmake]   in a future version.
cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

#--------------------------------------------------------------------------------
# Interprocedural Optimization (IPO)
#--------------------------------------------------------------------------------
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_output)

if(ipo_supported)
  message(STATUS "IPO is supported")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
else()
  message(WARNING "IPO is not supported: ${ipo_output}")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE FALSE)
endif()

#--------------------------------------------------------------------------------
# Profiling Flags (Commented Out)
#--------------------------------------------------------------------------------
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-instr-generate")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-instr-use=${CMAKE_CURRENT_SOURCE_DIR}/build/bin/code.profdata")
# add_compile_options(-Wno-profile-instr-unprofiled)

#--------------------------------------------------------------------------------
# GLIBC Version Force Link (Commented Out)
#--------------------------------------------------------------------------------
# force link glibc ver 2.27
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -include  ${CMAKE_CURRENT_SOURCE_DIR}/core/force_link_glibc_2.27.h")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include  ${CMAKE_CURRENT_SOURCE_DIR}/core/force_link_glibc_2.27.h")

#--------------------------------------------------------------------------------
# Sanitizer Options
#--------------------------------------------------------------------------------
set(ENABLE_ASAN OFF CACHE BOOL "enable address sanitizer" FORCE)
set(ENABLE_TSAN OFF CACHE BOOL "enable thread sanitizer" FORCE)
set(ENABLE_LSAN OFF CACHE BOOL "enable leak sanitizer" FORCE)
set(ENABLE_USAN OFF CACHE BOOL "enable undefined behaviour sanitizer" FORCE)

#--------------------------------------------------------------------------------
# Tunnel and Core Feature Inclusion Options
#--------------------------------------------------------------------------------
option(INCLUDE_TEMPLATE                 "link Template staticly to the core"             TRUE)
option(INCLUDE_WIREGUARD_DEVICE         "link WireGuardDevice staticly to the core"      TRUE)
option(INCLUDE_PACKET_TO_CONNECTION     "link PacketToConnection staticly to the core"   TRUE)
option(INCLUDE_DATA_AS_PACKET           "link DataAsPacket staticly to the core"         TRUE)
option(INCLUDE_PACKET_AS_DATA           "link PacketAsData staticly to the core"         TRUE)
option(INCLUDE_LAYER3_IP_ROUTING_TABLE  "link Layer3IpRoutingTable staticly to the core" FALSE)
option(INCLUDE_IP_OVERRIDER             "link IpOverrider staticly to the core"          TRUE)
option(INCLUDE_IP_MANIPULATOR           "link IPManipulator staticly to the core"        TRUE)
option(INCLUDE_LAYER3_TCP_MANIPULATOR   "link Layer3TcpManipulator staticly to the core" FALSE)
option(INCLUDE_TCP_LISTENER             "link TcpListener staticly to the core"          TRUE)
option(INCLUDE_UDP_LISTENER             "link UdpListener staticly to the core"          TRUE)
option(INCLUDE_LISTENER                 "link Listener staticly to the core"             FALSE)
option(INCLUDE_LOGGER_TUNNEL            "link LoggerTunnel staticly to the core"         FALSE)
option(INCLUDE_CONNECTOR                "link Connector staticly to the core"            FALSE)
option(INCLUDE_TCPCONNECTOR             "link TcpConnector staticly to the core"         TRUE)
option(INCLUDE_UDP_CONNECTOR            "link UdpConnector staticly to the core"         TRUE)
option(INCLUDE_UDP_STATELESS_SOCKET     "link UdpStatelessSocket staticly to the core"   TRUE)
option(INCLUDE_BRIDGE                   "link Bridge staticly to the core"               TRUE)
option(INCLUDE_OPENSSL_SERVER           "link OpenSSlServer staticly to the core"        FALSE)
option(INCLUDE_TLS_CLIENT               "link TLSClient staticly to the core"            TRUE)
option(INCLUDE_TROJAN_AUTH_SERVER       "link TrojanAuthServer staticly to the core"     FALSE)
option(INCLUDE_TROJAN_SOCKS_SERVER      "link TrojanSocksServer staticly to the core"    FALSE)
option(INCLUDE_WOLFSSL_SERVER           "link WolfSSLServer staticly to the core"        OFF)  # this downloads 750 mb of data!
option(INCLUDE_WOLFSSL_CLIENT           "link WolfSSLClient staticly to the core"        OFF)  # this downloads 750 mb of data!
option(INCLUDE_HTTP2_SERVER             "link Http2Server staticly to the core"          FALSE)
option(INCLUDE_HTTP2_CLIENT             "link Http2Client staticly to the core"          FALSE)
option(INCLUDE_PROTOBUF_SERVER          "link ProtoBufServer staticly to the core"       FALSE)
option(INCLUDE_PROTOBUF_CLIENT          "link ProtoBufClient staticly to the core"       FALSE)
option(INCLUDE_REVERSE_SERVER           "link ReverseServer staticly to the core"        TRUE)
option(INCLUDE_REVERSE_CLIENT           "link ReverseClient staticly to the core"        TRUE)
option(INCLUDE_HEADER_SERVER            "link HeaderServer staticly to the core"         FALSE)
option(INCLUDE_HEADER_CLIENT            "link HeaderClient staticly to the core"         FALSE)
option(INCLUDE_PRECONNECT_SERVER        "link PreConnectServer staticly to the core"     FALSE)
option(INCLUDE_PRECONNECT_CLIENT        "link PreConnectClient staticly to the core"     FALSE)
option(INCLUDE_SOCKS_5_SERVER           "link Socks5Server staticly to the core"         FALSE)
option(INCLUDE_REALITY_SERVER           "link RealityServer staticly to the core"        FALSE)
option(INCLUDE_REALITY_CLIENT           "link RealityClient staticly to the core"        FALSE)
option(INCLUDE_HALFDUPLEX_SERVER        "link HalfDuplexServer staticly to the core"     TRUE)
option(INCLUDE_HALFDUPLEX_CLIENT        "link HalfDuplexClient staticly to the core"     TRUE)
option(INCLUDE_BGP4_SERVER              "link Bgp4Server staticly to the core"           FALSE)
option(INCLUDE_BGP4_CLIENT              "link Bgp4Client staticly to the core"           FALSE)
option(INCLUDE_MUX_SERVER               "link MuxServer staticly to the core"            TRUE)
option(INCLUDE_MUX_CLIENT               "link MuxClient staticly to the core"            TRUE)

# tun device works on android but requires root access
if(NOT APPLE AND NOT ANDROID)
  option(INCLUDE_TUN_DEVICE             "link TunDevice staticly to the core"            TRUE)
endif()

if(NOT ANDROID AND NOT (CMAKE_SYSTEM_NAME STREQUAL "NetBSD"
    OR CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD"))

  if(LINUX OR (WIN32 AND CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"))
  
    option(INCLUDE_RAWSOCKET              "link RawSocket staticly to the core"          TRUE)
    
  endif()

endif()



#--------------------------------------------------------------------------------
# Main Executable and Sources
#--------------------------------------------------------------------------------
add_executable(Waterwall
  core/main.c
  core/core_settings.c
  core/imported_tunnels.c
  core/os_helpers.c
  # core/tests/bench_memcpy.c
)

#--------------------------------------------------------------------------------
# Windows and iOS Specific Settings
#--------------------------------------------------------------------------------
if(WIN32)
  if(MSVC)
    set_target_properties(Waterwall PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
  else()
    target_sources(Waterwall PRIVATE core/rc/app.rc)
  endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "iOS" AND CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  message(STATUS "Compiling for iOS on a macOS host")

  set_target_properties(Waterwall PROPERTIES
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "com.alireza.Waterwall"
    XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO" # for test, later we need apple developer account
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "" # for test, later we need apple developer account
  )
endif()

#--------------------------------------------------------------------------------
# Include Directories
#--------------------------------------------------------------------------------
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/core)
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)

#--------------------------------------------------------------------------------
# WW Library
#--------------------------------------------------------------------------------
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_include_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ww)
target_link_libraries(Waterwall ww)

#--------------------------------------------------------------------------------
# Tunnel Libraries
#--------------------------------------------------------------------------------

#template
if(INCLUDE_TEMPLATE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TEMPLATE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/template)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/template)
  target_link_libraries(Waterwall Template)
endif()

#tun device
if(INCLUDE_TUN_DEVICE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TUN_DEVICE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TunDevice)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TunDevice)
  target_link_libraries(Waterwall TunDevice)
endif()

#packet to connection
if(INCLUDE_PACKET_TO_CONNECTION)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PACKET_TO_CONNECTION=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketToConnection)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketToConnection)
  target_link_libraries(Waterwall PacketToConnection)
endif()

#data as packet
if(INCLUDE_DATA_AS_PACKET)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_DATA_AS_PACKET=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/DataAsPacket)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/DataAsPacket)
  target_link_libraries(Waterwall DataAsPacket)
endif()

#packet as data
if(INCLUDE_PACKET_AS_DATA)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PACKET_AS_DATA=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketAsData)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketAsData)
  target_link_libraries(Waterwall PacketAsData)
endif()

#raw socket
if(INCLUDE_RAWSOCKET)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_RAWSOCKET=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/RawSocket)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/RawSocket)
  target_link_libraries(Waterwall RawSocket)
endif()

#wiregurad device
if(INCLUDE_WIREGUARD_DEVICE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_WIREGUARD_DEVICE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/WireGuardDevice)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/WireGuardDevice)
  target_link_libraries(Waterwall WireGuardDevice)
endif()

#layer3 ip route table
if(INCLUDE_LAYER3_IP_ROUTING_TABLE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_IP_ROUTING_TABLE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/routing_table)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/ip/routing_table)
  target_link_libraries(Waterwall Layer3IpRoutingTable)
endif()

#ip overrider
if(INCLUDE_IP_OVERRIDER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_IP_OVERRIDER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/IpOverrider)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/IpOverrider)
  target_link_libraries(Waterwall IpOverrider)
endif()

#ip manipulator
if(INCLUDE_IP_MANIPULATOR)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_IP_MANIPULATOR=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/IpManipulator)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/IpManipulator)
  target_link_libraries(Waterwall IpManipulator)
endif()

#layer3 tcp manipulator
if(INCLUDE_LAYER3_TCP_MANIPULATOR)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_LAYER3_TCP_MANIPULATOR=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/tcp/manipulator)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/layer3/tcp/manipulator)
  target_link_libraries(Waterwall Layer3TcpManipulator)
endif()

#tcp listener
if(INCLUDE_TCP_LISTENER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TCP_LISTENER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpListener)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpListener)
  target_link_libraries(Waterwall TcpListener)
endif()

#udp listener
if(INCLUDE_UDP_LISTENER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_LISTENER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpListener)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpListener)
  target_link_libraries(Waterwall UdpListener)
endif()

#listener
if(INCLUDE_LISTENER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_LISTENER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/listener)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/listener)
  target_link_libraries(Waterwall Listener)
endif()

#connector
if(INCLUDE_CONNECTOR)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_CONNECTOR=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/connector)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/adapters/connector)
  target_link_libraries(Waterwall Connector)
endif()

#tcp connector
if(INCLUDE_TCPCONNECTOR)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TCPCONNECTOR=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpConnector)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpConnector)
  target_link_libraries(Waterwall TcpConnector)
endif()

#udp connector
if(INCLUDE_UDP_CONNECTOR)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_CONNECTOR=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpConnector)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpConnector)
  target_link_libraries(Waterwall UdpConnector)
endif()

#udp stateless socket
if(INCLUDE_UDP_STATELESS_SOCKET)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_STATELESS_SOCKET=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpStatelessSocket)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpStatelessSocket)
  target_link_libraries(Waterwall UdpStatelessSocket)
endif()

#bridge
if(INCLUDE_BRIDGE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_BRIDGE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bridge)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bridge)
  target_link_libraries(Waterwall Bridge)
endif()

#http2 server
if(INCLUDE_OPENSSL_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HTTP2_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/http2)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/http2)
  target_link_libraries(Waterwall Http2Server)
endif()

#http2 client
if(INCLUDE_HTTP2_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HTTP2_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/http2)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/http2)
  target_link_libraries(Waterwall Http2Client)
endif()

#openssl server
if(INCLUDE_OPENSSL_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_OPENSSL_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/openssl)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/openssl)
  target_link_libraries(Waterwall OpenSSLServer)
endif()

#tls client
if(INCLUDE_TLS_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TLS_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TlsClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TlsClient)
  target_link_libraries(Waterwall TlsClient)
endif()

#trojan auth server
if(INCLUDE_TROJAN_AUTH_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TROJAN_AUTH_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/auth)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/socks)
  target_link_libraries(Waterwall TrojanAuthServer)
endif()

#trojan socks server
if(INCLUDE_TROJAN_SOCKS_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TROJAN_SOCKS_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/socks)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/trojan/socks)
  target_link_libraries(Waterwall TrojanSocksServer)
endif()

#wolf ssl server
if(INCLUDE_WOLFSSL_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_WOLFSSL_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/wolfssl)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/wolfssl)
  target_link_libraries(Waterwall WolfSSLServer)
endif()

#wolf ssl client
if(INCLUDE_WOLFSSL_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_WOLFSSL_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/wolfssl)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/wolfssl)
  target_link_libraries(Waterwall WolfSSLClient)
endif()

#logger tunnel
if(INCLUDE_LOGGER_TUNNEL)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_LOGGER_TUNNEL=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/logger)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/logger)
  target_link_libraries(Waterwall LoggerTunnel)
endif()

#protobuf server
if(INCLUDE_PROTOBUF_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PROTOBUF_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/protobuf)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/protobuf)
  target_link_libraries(Waterwall ProtoBufServer)
endif()

#protobuf client
if(INCLUDE_PROTOBUF_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PROTOBUF_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/protobuf)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/protobuf)
  target_link_libraries(Waterwall ProtoBufClient)
endif()

#reverse server
if(INCLUDE_REVERSE_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REVERSE_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseServer)
  target_link_libraries(Waterwall ReverseServer)
endif()

#reverse client
if(INCLUDE_REVERSE_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REVERSE_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseClient)
  target_link_libraries(Waterwall ReverseClient)
endif()

#header server
if(INCLUDE_HEADER_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HEADER_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/header)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/header)
  target_link_libraries(Waterwall HeaderServer)
endif()

#header client
if(INCLUDE_HEADER_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HEADER_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/header)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/header)
  target_link_libraries(Waterwall HeaderClient)
endif()

#preconnect server
if(INCLUDE_PRECONNECT_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PRECONNECT_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/preconnect)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/preconnect)
  target_link_libraries(Waterwall PreConnectServer)
endif()

#preconnect client
if(INCLUDE_PRECONNECT_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PRECONNECT_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/preconnect)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/preconnect)
  target_link_libraries(Waterwall PreConnectClient)
endif()

#socks5 server
if(INCLUDE_SOCKS_5_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SOCKS_5_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/socks/5)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/socks/5)
  target_link_libraries(Waterwall Socks5Server)
endif()

#reality server
if(INCLUDE_REALITY_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REALITY_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/reality)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/reality)
  target_link_libraries(Waterwall RealityServer)
endif()

#reality client
if(INCLUDE_REALITY_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REALITY_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/reality)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/reality)
  target_link_libraries(Waterwall RealityClient)
endif()

#halfduplex server
if(INCLUDE_HALFDUPLEX_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HALFDUPLEX_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HalfDuplexServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HalfDuplexServer)
  target_link_libraries(Waterwall HalfDuplexServer)
endif()

#halfduplex client
if(INCLUDE_HALFDUPLEX_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HALFDUPLEX_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HalfDuplexClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HalfDuplexClient)
  target_link_libraries(Waterwall HalfDuplexClient)
endif()

#bgp4server server
if(INCLUDE_BGP4_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_BGP4_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/bgp4)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/server/bgp4)
  target_link_libraries(Waterwall Bgp4Server)
endif()

#bgp4client client
if(INCLUDE_BGP4_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_BGP4_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/bgp4)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/client/bgp4)
  target_link_libraries(Waterwall Bgp4Client)
endif()

#mux server
if(INCLUDE_MUX_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_MUX_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/MuxServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/MuxServer)
  target_link_libraries(Waterwall MuxServer)
endif()

#mux client
if(INCLUDE_MUX_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_MUX_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/MuxClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/MuxClient)
  target_link_libraries(Waterwall MuxClient)
endif()


#--------------------------------------------------------------------------------
# Platform-Specific Linker and Compiler Flags
#--------------------------------------------------------------------------------


# Use C++ linker for proper C++ runtime handling (especially for BoringSSL)
set_target_properties(Waterwall PROPERTIES LINKER_LANGUAGE CXX)

# Platform-specific flags
if(MINGW OR MSYS)
  # On Windows (MinGW), statically link libgcc, libstdc++, and libwinpthread
  target_link_options(Waterwall PRIVATE -static -static-libgcc -static-libstdc++)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # Ensure static linking of C++ standard library for BoringSSL (but not glibc)
  target_link_options(Waterwall PRIVATE -static-libstdc++ -static-libgcc)
endif()

#------------------------------------------------------------------------------------------
# Final Configuration
#------------------------------------------------------------------------------------------
if(BUILD_OPENSSL_GLOBALS)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/shared/openssl)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/shared/openssl)
endif()

target_compile_definitions(Waterwall PUBLIC WATERWALL_VERSION=${Waterwall_VERSION})

if(OPENSSL_VERSION)
  message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
endif()

message(STATUS "Waterwall version: ${Waterwall_VERSION}")