#--------------------------------------------------------------------------------
# Project Definition and Basic Configuration
#--------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.25 FATAL_ERROR)

cmake_policy(SET CMP0091 NEW)

if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
  set(CMAKE_POLICY_DEFAULT_CMP0169 OLD)
endif()

# CMAKE_UNITY_BUILD is off by default but most of cmake presets enable it
# it must be disabled in order to allow language server to work correctly
set(CMAKE_UNITY_BUILD_BATCH_SIZE 500)

project(Waterwall
  VERSION 1.46.9
  DESCRIPTION "A fast and secure VPN tunnel"
  HOMEPAGE_URL "https://github.com/radkesvat/waterwall"
  LANGUAGES C CXX
)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/ww/cmake")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/ww/cmake/version.txt" "${PROJECT_VERSION}\n")

#--------------------------------------------------------------------------------
# Build Type Configuration
#--------------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "CMAKE_BUILD_TYPE not set - defaulting to Release build, on multi-config generators this will be ignored")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: ${CMAKE_CONFIGURATION_TYPES}." FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE} (ignored on multi-config generators)")

# Set static runtime library for MSVC - this is the modern CMake way (dont move this line)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_definitions(
    _ITERATOR_DEBUG_LEVEL=0
    _HAS_ITERATOR_DEBUGGING=0
  )
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
else()
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()


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

include(CTest)

#--------------------------------------------------------------------------------
# Interprocedural Optimization (IPO)
#--------------------------------------------------------------------------------
option(WW_ENABLE_IPO "Enable interprocedural optimization for production targets" ON)
option(WW_BUILD_UNIT_TESTS "Register compiled native unit-test targets" OFF)
option(WW_NATIVE_UNIT_TEST_EXECUTABLE_RUNNABLE
  "The selected native unit-test binaries are runnable on this CI host" OFF)

if(WW_BUILD_UNIT_TESTS AND NOT BUILD_TESTING)
  message(FATAL_ERROR "WW_BUILD_UNIT_TESTS=ON requires BUILD_TESTING=ON")
endif()

if(WW_BUILD_UNIT_TESTS AND WW_ENABLE_IPO)
  message(FATAL_ERROR
    "WW_BUILD_UNIT_TESTS=ON requires WW_ENABLE_IPO=OFF; configure the dedicated no-LTO unit-test tree")
endif()

if(WW_ENABLE_IPO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT ipo_output)

  if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    set(WW_EFFECTIVE_RELEASE_IPO ON)
  else()
    message(WARNING "IPO is not supported: ${ipo_output}")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE FALSE)
    set(WW_EFFECTIVE_RELEASE_IPO OFF)
  endif()
else()
  # This must happen before ww, lwIP, dependencies, tunnels, or tests create a
  # target. A per-test property cannot turn LTO archives back into native code.
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE FALSE)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF)
  set(WW_EFFECTIVE_RELEASE_IPO OFF)
endif()
message(STATUS "IPO policy: requested=${WW_ENABLE_IPO}; Release effective=${WW_EFFECTIVE_RELEASE_IPO}")

# Linux owns the comprehensive aggregate in tests/unittests. Other native
# platforms register their portable/runtime tests from this root file, so give
# those configurations an equivalent build aggregate. Production trees never
# create either target.
if(WW_BUILD_UNIT_TESTS AND NOT (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING))
  add_custom_target(waterwall_platform_unit_tests)

  function(waterwall_register_platform_native_unit test_name target_name labels)
    if(NOT TARGET ${target_name})
      message(FATAL_ERROR "platform native-unit target is missing: ${target_name}")
    endif()
    add_dependencies(waterwall_platform_unit_tests ${target_name})
  endfunction()
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
option(ENABLE_ASAN "enable address sanitizer" OFF)
option(ENABLE_TSAN "enable thread sanitizer" OFF)
option(ENABLE_LSAN "enable leak sanitizer" OFF)
option(ENABLE_USAN "enable undefined behaviour sanitizer" OFF)
option(ALLOCATOR_BYPASS "use the system allocator instead of mimalloc" OFF)
if(ENABLE_TSAN)
  # TSAN observes allocation lifetimes through the system allocator interceptors.
  set(ALLOCATOR_BYPASS ON)
endif()

#--------------------------------------------------------------------------------
# Tunnel and Core Feature Inclusion Options
#--------------------------------------------------------------------------------

# Define conditional variables for platform-specific options


if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
  set(TUNDEVICE_SUPPORTED FALSE)
else()
  set(TUNDEVICE_SUPPORTED TRUE)
endif()

if(NOT ANDROID AND NOT (CMAKE_SYSTEM_NAME STREQUAL "NetBSD"
    OR CMAKE_SYSTEM_NAME STREQUAL "OpenBSD" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD"))
  if(LINUX OR (WIN32 AND CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"))
    set(RAWSOCKET_SUPPORTED TRUE)
  else()
    set(RAWSOCKET_SUPPORTED FALSE)
  endif()
else()
  set(RAWSOCKET_SUPPORTED FALSE)
endif()

option(INCLUDE_TEMPLATE                 "link Template staticly to the core"                                        TRUE)
option(INCLUDE_TESTER_CLIENT            "link TesterClient staticly to the core"                                    TRUE)
option(INCLUDE_TESTER_SERVER            "link TesterServer staticly to the core"                                    TRUE)
option(INCLUDE_SPEEDTEST_CLIENT         "link SpeedTestClient staticly to the core"                                 TRUE)
option(INCLUDE_SPEEDTEST_SERVER         "link SpeedTestServer staticly to the core"                                 TRUE)
option(INCLUDE_AUTHENTICATION_CLIENT    "link AuthenticationClient staticly to the core"                            TRUE)
option(INCLUDE_AUTHENTICATION_SERVER    "link AuthenticationServer staticly to the core"                            TRUE)
option(INCLUDE_WIREGUARD_DEVICE         "link WireGuardDevice staticly to the core"                                 TRUE)
option(INCLUDE_PACKET_TO_CONNECTION     "link PacketsToConnection staticly to the core"                             TRUE)
option(INCLUDE_CONNECTION_TO_PACKETS    "link ConnectionToPackets staticly to the core"                             TRUE)
option(INCLUDE_STREAM_TO_PACKETS        "link StreamToPackets staticly to the core"                                 TRUE)
option(INCLUDE_PACKETS_TO_STREAM        "link PacketsToStream staticly to the core"                                 TRUE)
option(INCLUDE_PACKET_SPLIT_STREAM      "link PacketSplitStream staticly to the core"                               TRUE)
option(INCLUDE_LAYER3_IP_ROUTING_TABLE  "link Layer3IpRoutingTable staticly to the core"                            FALSE)
option(INCLUDE_IP_OVERRIDER             "link IpOverrider staticly to the core"                                     TRUE)
option(INCLUDE_IP_MANIPULATOR           "link IPManipulator staticly to the core"                                   TRUE)
option(INCLUDE_PING_CLIENT              "link PingClient staticly to the core"                                      TRUE)
option(INCLUDE_PING_SERVER              "link PingServer staticly to the core"                                      TRUE)
option(INCLUDE_KEEPALIVE_CLIENT         "link KeepAliveClient staticly to the core"                                 TRUE)
option(INCLUDE_KEEPALIVE_SERVER         "link KeepAliveServer staticly to the core"                                 TRUE)
option(INCLUDE_CONNECTION_FISHER_CLIENT "link ConnectionFisherClient staticly to the core"                          TRUE)
option(INCLUDE_CONNECTION_FISHER_SERVER "link ConnectionFisherServer staticly to the core"                          TRUE)
option(INCLUDE_TCP_LISTENER             "link TcpListener staticly to the core"                                     TRUE)
option(INCLUDE_UDP_LISTENER             "link UdpListener staticly to the core"                                     TRUE)
option(INCLUDE_TCP_UDP_LISTENER         "link TcpUdpListener staticly to the core"                                  TRUE)
option(INCLUDE_LOGGER_TUNNEL            "link LoggerTunnel staticly to the core"                                    TRUE)
option(INCLUDE_TCP_UDP_CONNECTOR        "link TcpUdpConnector staticly to the core"                                 TRUE)
option(INCLUDE_TCPCONNECTOR             "link TcpConnector staticly to the core"                                    TRUE)
option(INCLUDE_UDP_CONNECTOR            "link UdpConnector staticly to the core"                                    TRUE)
option(INCLUDE_UDP_STATELESS_SOCKET     "link UdpStatelessSocket staticly to the core"                              TRUE)
option(INCLUDE_UDP_OVER_TCP_CLIENT      "link UdpOverTcpClient staticly to the core"                                TRUE)
option(INCLUDE_UDP_OVER_TCP_SERVER      "link UdpOverTcpServer staticly to the core"                                TRUE)
option(INCLUDE_TCP_OVER_UDP_CLIENT      "link TcpOverUdpClient staticly to the core"                                TRUE)
option(INCLUDE_TCP_OVER_UDP_SERVER      "link TcpOverUdpServer staticly to the core"                                TRUE)
option(INCLUDE_BRIDGE                   "link Bridge staticly to the core"                                          TRUE)
option(INCLUDE_SNIFF_ROUTER             "link SniffRouter staticly to the core"                                     TRUE)
option(INCLUDE_ROUTER                   "link Router staticly to the core"                                          TRUE)
option(router_enable_quic_sniffing      "Enable Router QUIC SNI sniffing support (requires OpenSSL)"                TRUE)
option(router_enable_http2_sniffing     "Enable Router HTTP/2 plaintext domain sniffing support (requires nghttp2)" TRUE)
option(INCLUDE_TLS_CLIENT               "link TLSClient staticly to the core"                                       TRUE)
option(INCLUDE_TLS_SERVER               "link TLSServer staticly to the core"                                       TRUE)
option(INCLUDE_TROJAN_CLIENT            "link TrojanClient staticly to the core"                                    TRUE)
option(INCLUDE_TROJAN_SERVER            "link TrojanServer staticly to the core"                                    TRUE)
option(INCLUDE_VLESS_CLIENT             "link VlessClient staticly to the core"                                     TRUE)
option(INCLUDE_VLESS_SERVER             "link VlessServer staticly to the core"                                     TRUE)
option(INCLUDE_HTTP_SERVER              "link HttpServer staticly to the core"                                      TRUE)
option(INCLUDE_HTTP_CLIENT              "link HttpClient staticly to the core"                                      TRUE)
option(INCLUDE_SOCKS5_CLIENT            "link Socks5Client staticly to the core"                                    TRUE)
option(INCLUDE_PROTOBUF_SERVER          "link ProtoBufServer staticly to the core"                                  FALSE)
option(INCLUDE_PROTOBUF_CLIENT          "link ProtoBufClient staticly to the core"                                  FALSE)
option(INCLUDE_REVERSE_SERVER           "link ReverseServer staticly to the core"                                   TRUE)
option(INCLUDE_REVERSE_CLIENT           "link ReverseClient staticly to the core"                                   TRUE)
option(INCLUDE_HEADER_SERVER            "link HeaderServer staticly to the core"                                    TRUE)
option(INCLUDE_HEADER_CLIENT            "link HeaderClient staticly to the core"                                    TRUE)
option(INCLUDE_OBFUSCATOR_CLIENT        "link ObfuscatorClient staticly to the core"                                TRUE)
option(INCLUDE_OBFUSCATOR_SERVER        "link ObfuscatorServer staticly to the core"                                TRUE)
option(INCLUDE_ENCRYPTION_CLIENT        "link EncryptionClient staticly to the core"                                TRUE)
option(INCLUDE_ENCRYPTION_SERVER        "link EncryptionServer staticly to the core"                                TRUE)
option(INCLUDE_PRECONNECT_SERVER        "link PreConnectServer staticly to the core"                                FALSE)
option(INCLUDE_PRECONNECT_CLIENT        "link PreConnectClient staticly to the core"                                FALSE)
option(INCLUDE_SOCKS_5_SERVER           "link Socks5Server staticly to the core"                                    TRUE)
option(INCLUDE_REALITY_SERVER           "link RealityServer staticly to the core"                                   TRUE)
option(INCLUDE_REALITY_CLIENT           "link RealityClient staticly to the core"                                   TRUE)
option(INCLUDE_HALFDUPLEX_SERVER        "link HalfDuplexServer staticly to the core"                                TRUE)
option(INCLUDE_HALFDUPLEX_CLIENT        "link HalfDuplexClient staticly to the core"                                TRUE)
option(INCLUDE_BGP4_SERVER              "link Bgp4Server staticly to the core"                                      TRUE)
option(INCLUDE_BGP4_CLIENT              "link Bgp4Client staticly to the core"                                      TRUE)
option(INCLUDE_MUX_SERVER               "link MuxServer staticly to the core"                                       TRUE)
option(INCLUDE_MUX_CLIENT               "link MuxClient staticly to the core"                                       TRUE)
option(INCLUDE_TUN_DEVICE               "link TunDevice staticly to the core"                                       ${TUNDEVICE_SUPPORTED})
option(INCLUDE_PACKET_SENDER            "link PacketSender staticly to the core"                                    TRUE)
option(INCLUDE_PACKET_RECEIVER          "link PacketReceiver staticly to the core"                                  TRUE)
option(INCLUDE_RAWSOCKET                "link RawSocket staticly to the core"                                       ${RAWSOCKET_SUPPORTED})
option(INCLUDE_DISTURBER                "link Disturber staticly to the core"                                       TRUE)
option(INCLUDE_JUNK_DATAGRAM_SENDER     "link JunkDatagramSender staticly to the core"                              TRUE)
option(INCLUDE_BLACKHOLE                "link BlackHole staticly to the core"                                       TRUE)
option(INCLUDE_SPEEDLIMIT               "link SpeedLimit staticly to the core"                                      TRUE)
option(INCLUDE_SOFT_IP_LIMITER          "link SoftIpLimiter staticly to the core"                                   TRUE)
option(INCLUDE_DOMAIN_RESOLVER          "link DomainResolver staticly to the core"                                  TRUE)
option(INCLUDE_USER_CONTROLLER          "link UserController staticly to the core"                                  TRUE)

if((INCLUDE_TCPCONNECTOR OR INCLUDE_UDP_CONNECTOR OR INCLUDE_SOCKS5_CLIENT OR INCLUDE_VLESS_CLIENT OR INCLUDE_TROJAN_CLIENT OR INCLUDE_ROUTER OR INCLUDE_CONNECTION_TO_PACKETS) AND NOT INCLUDE_DOMAIN_RESOLVER)
  message(STATUS "Forcing DomainResolver because connector/client/router tunnels use it internally")
  set(INCLUDE_DOMAIN_RESOLVER TRUE CACHE BOOL "link DomainResolver staticly to the core" FORCE)
endif()

# Determine if OpenSSL is required based on included tunnels
if(INCLUDE_TLS_SERVER OR router_enable_quic_sniffing)
  set(PROJECT_REQUIRES_OPENSSL TRUE CACHE INTERNAL "if any of the tunnels that require openssl is included, this will be set to true" FORCE)
else()
  set(PROJECT_REQUIRES_OPENSSL FALSE CACHE INTERNAL "if any of the tunnels that require openssl is included, this will be set to true" FORCE)
endif()

if(INCLUDE_HTTP_SERVER OR INCLUDE_HTTP_CLIENT OR (INCLUDE_ROUTER AND router_enable_http2_sniffing))
  set(PROJECT_REQUIRES_NGHTTP2 TRUE CACHE INTERNAL "if any of the tunnels that require nghttp2 is included, this will be set to true" FORCE)
else()
  set(PROJECT_REQUIRES_NGHTTP2 FALSE CACHE INTERNAL "if any of the tunnels that require nghttp2 is included, this will be set to true" FORCE)
endif()


#--------------------------------------------------------------------------------
# Main Executable and Sources
#--------------------------------------------------------------------------------
set(WATERWALL_STARTUP_GUARD_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/core/startup_guard.c")
set(WATERWALL_INNER_MAIN_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/core/main.c")

# The CPU startup guard owns the process entry point and verifies required CPU
# instruction sets before any optimized code runs. It is disabled on MinGW GCC
# (mingw64/ucrt64): there it is not built at all and core/main.c provides main()
# directly, accepting that the process may crash on an unsupported CPU.
set(WW_USE_STARTUP_GUARD TRUE)
if(MINGW AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
  set(WW_USE_STARTUP_GUARD FALSE)
endif()

set(WATERWALL_STARTUP_GUARD_OBJECTS "")
if(WW_USE_STARTUP_GUARD)
  add_library(WaterwallStartupGuard OBJECT
    ${WATERWALL_STARTUP_GUARD_SOURCE}
  )

  target_include_directories(WaterwallStartupGuard PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/ww
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/ww
  )
  target_compile_definitions(WaterwallStartupGuard PRIVATE WATERWALL_VERSION=${Waterwall_VERSION})
  set_target_properties(WaterwallStartupGuard PROPERTIES
    UNITY_BUILD OFF
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  set(WATERWALL_STARTUP_GUARD_OBJECTS $<TARGET_OBJECTS:WaterwallStartupGuard>)
endif()

add_executable(Waterwall
  ${WATERWALL_STARTUP_GUARD_OBJECTS}
  ${WATERWALL_INNER_MAIN_SOURCE}
  core/core_settings.c
  core/imported_tunnels.c
  core/os_helpers.c
  # core/tests/bench_memcpy.c
)

if(WW_USE_STARTUP_GUARD)
  # main.c suppresses its own main(); startup_guard.c provides the entry point.
  target_compile_definitions(Waterwall PRIVATE WATERWALL_HAS_STARTUP_GUARD=1)

  set_source_files_properties(${WATERWALL_STARTUP_GUARD_SOURCE}
    PROPERTIES
      SKIP_UNITY_BUILD_INCLUSION ON
      SKIP_PRECOMPILE_HEADERS ON
  )

  if((CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
      AND CMAKE_SIZEOF_VOID_P EQUAL 8
      AND (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"))
    set_property(SOURCE ${WATERWALL_STARTUP_GUARD_SOURCE} APPEND PROPERTY COMPILE_OPTIONS
      -march=x86-64
      -mtune=generic
      -mno-ssse3
      -mno-sse3
      -mno-sse4.1
      -mno-sse4.2
      -mno-avx
      -mno-avx2
      -mno-avx512f
      -mno-fma
      -mno-f16c
      -mno-bmi
      -mno-bmi2
      -mno-lzcnt
      -mno-popcnt
      -mno-movbe
      -fno-lto
    )
  endif()
endif()

#--------------------------------------------------------------------------------
# Windows and iOS Specific Settings
#--------------------------------------------------------------------------------
if(WIN32)
  if(MSVC)
    set_target_properties(Waterwall PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
  else()
    # Keep the resource compiler isolated from Waterwall's many tunnel-specific
    # include directories and definitions.
    add_library(waterwall_resources OBJECT core/rc/app.rc)

    target_compile_definitions(waterwall_resources PRIVATE
      FINAL_EXECUTABLE_NAME="${FINAL_EXECUTABLE_NAME}.exe"
      WATERWALL_VERSION=${Waterwall_VERSION}
      WW_VERSION=1.1.0
    )

    target_include_directories(waterwall_resources PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/core
      ${CMAKE_CURRENT_SOURCE_DIR}/core/rc
    )

    target_sources(Waterwall PRIVATE $<TARGET_OBJECTS:waterwall_resources>)
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

# Xcode/iOS simulator links are more reliable when the final executable links
# the imported OpenSSL targets directly instead of only through the static ww
# library's transitive link interface.
if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
  target_link_libraries(Waterwall OpenSSL::SSL OpenSSL::Crypto)
  if(TARGET OpenSSL::applink)
    target_link_libraries(Waterwall OpenSSL::applink)
  endif()
endif()

#--------------------------------------------------------------------------------
# Tunnel Libraries
#--------------------------------------------------------------------------------

if(INCLUDE_TLS_CLIENT OR INCLUDE_TLS_SERVER)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/TlsRecordShapingCommon)
endif()

#template
if(INCLUDE_TEMPLATE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TEMPLATE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/template)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/template)
  target_link_libraries(Waterwall Template)
endif()

#tester client
if(INCLUDE_TESTER_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TESTER_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TesterClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TesterClient)
  target_link_libraries(Waterwall TesterClient)
endif()

#tester server
if(INCLUDE_TESTER_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TESTER_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TesterServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TesterServer)
  target_link_libraries(Waterwall TesterServer)
endif()

#speedtest client
if(INCLUDE_SPEEDTEST_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SPEEDTEST_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SpeedTestClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SpeedTestClient)
  target_link_libraries(Waterwall SpeedTestClient)
endif()

#speedtest server
if(INCLUDE_SPEEDTEST_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SPEEDTEST_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SpeedTestServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SpeedTestServer)
  target_link_libraries(Waterwall SpeedTestServer)
endif()

#authentication client
if(INCLUDE_AUTHENTICATION_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_AUTHENTICATION_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/AuthenticationClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/AuthenticationClient)
  target_link_libraries(Waterwall AuthenticationClient)
endif()

#authentication server
if(INCLUDE_AUTHENTICATION_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_AUTHENTICATION_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/AuthenticationServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/AuthenticationServer)
  target_link_libraries(Waterwall AuthenticationServer)
endif()

#user controller
if(INCLUDE_USER_CONTROLLER AND INCLUDE_AUTHENTICATION_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_USER_CONTROLLER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/UserController)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/UserController)
  target_link_libraries(Waterwall UserController)
elseif(INCLUDE_USER_CONTROLLER)
  message(STATUS "Skipping UserController because INCLUDE_AUTHENTICATION_CLIENT is OFF")
endif()

#domain resolver
if(INCLUDE_DOMAIN_RESOLVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_DOMAIN_RESOLVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/DomainResolver)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/DomainResolver)
  target_link_libraries(Waterwall DomainResolver)
endif()

#tun device
if(INCLUDE_TUN_DEVICE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TUN_DEVICE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TunDevice)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TunDevice)
  target_link_libraries(Waterwall TunDevice)
endif()

#packet sender
if(INCLUDE_PACKET_SENDER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PACKET_SENDER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketSender)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketSender)
  target_link_libraries(Waterwall PacketSender)
endif()

#packet receiver
if(INCLUDE_PACKET_RECEIVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PACKET_RECEIVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketReceiver)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketReceiver)
  target_link_libraries(Waterwall PacketReceiver)
endif()

#packet to connection
if(INCLUDE_PACKET_TO_CONNECTION)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PACKET_TO_CONNECTION=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketsToConnection)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketsToConnection)
  target_link_libraries(Waterwall PacketsToConnection)
endif()

#connection to packets
if(INCLUDE_CONNECTION_TO_PACKETS)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_CONNECTION_TO_PACKETS=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ConnectionToPackets)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ConnectionToPackets)
  target_link_libraries(Waterwall ConnectionToPackets)
endif()

#data as packet
if(INCLUDE_STREAM_TO_PACKETS)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_STREAM_TO_PACKETS=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/StreamToPackets)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/StreamToPackets)
  target_link_libraries(Waterwall StreamToPackets)
endif()

#packet as data
if(INCLUDE_PACKETS_TO_STREAM)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PACKETS_TO_STREAM=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketsToStream)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketsToStream)
  target_link_libraries(Waterwall PacketsToStream)
endif()

#packet split stream
if(INCLUDE_PACKET_SPLIT_STREAM)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PACKET_SPLIT_STREAM=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketSplitStream)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PacketSplitStream)
  target_link_libraries(Waterwall PacketSplitStream)
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
  if(NOT INCLUDE_TLS_CLIENT)
    message(FATAL_ERROR "IpManipulator requires INCLUDE_TLS_CLIENT=ON")
  endif()
  target_compile_definitions(Waterwall PUBLIC INCLUDE_IP_MANIPULATOR=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/IpManipulator)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/IpManipulator)
  target_link_libraries(Waterwall IpManipulator)
endif()

# Ping wire v2 codec is shared by either endpoint.  Keep it independent of
# whether a build includes one node or both for plugin/minimal builds.
if(INCLUDE_PING_CLIENT OR INCLUDE_PING_SERVER)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/PingCommon)
endif()

#ping client
if(INCLUDE_PING_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PING_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PingClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PingClient)
  target_link_libraries(Waterwall PingClient)
endif()

#ping server
if(INCLUDE_PING_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_PING_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PingServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/PingServer)
  target_link_libraries(Waterwall PingServer)
endif()

#keepalive client
if(INCLUDE_KEEPALIVE_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_KEEPALIVE_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/KeepAliveClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/KeepAliveClient)
  target_link_libraries(Waterwall KeepAliveClient)
endif()

#keepalive server
if(INCLUDE_KEEPALIVE_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_KEEPALIVE_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/KeepAliveServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/KeepAliveServer)
  target_link_libraries(Waterwall KeepAliveServer)
endif()

#connection fisher client
if(INCLUDE_CONNECTION_FISHER_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_CONNECTION_FISHER_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ConnectionFisherClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ConnectionFisherClient)
  target_link_libraries(Waterwall ConnectionFisherClient)
endif()

#connection fisher server
if(INCLUDE_CONNECTION_FISHER_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_CONNECTION_FISHER_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ConnectionFisherServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ConnectionFisherServer)
  target_link_libraries(Waterwall ConnectionFisherServer)
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

#tcp/udp listener
if(INCLUDE_TCP_UDP_LISTENER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TCP_UDP_LISTENER=1)
  if(NOT TARGET TcpListener)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpListener)
  endif()
  if(NOT TARGET UdpListener)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpListener)
  endif()
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpUdpListener)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpUdpListener)
  target_link_libraries(Waterwall TcpUdpListener)
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

#tcp/udp connector
if(INCLUDE_TCP_UDP_CONNECTOR)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TCP_UDP_CONNECTOR=1)
  if(NOT TARGET TcpConnector)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpConnector)
  endif()
  if(NOT TARGET UdpConnector)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpConnector)
  endif()
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpUdpConnector)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpUdpConnector)
  target_link_libraries(Waterwall TcpUdpConnector)
endif()

#udp stateless socket
if(INCLUDE_UDP_STATELESS_SOCKET)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_STATELESS_SOCKET=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpStatelessSocket)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpStatelessSocket)
  target_link_libraries(Waterwall UdpStatelessSocket)
endif()

#udp over tcp client
if(INCLUDE_UDP_OVER_TCP_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_OVER_TCP_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpOverTcpClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpOverTcpClient)
  target_link_libraries(Waterwall UdpOverTcpClient)
endif()

#udp over tcp server
if(INCLUDE_UDP_OVER_TCP_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_UDP_OVER_TCP_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpOverTcpServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpOverTcpServer)
  target_link_libraries(Waterwall UdpOverTcpServer)
endif()

#tcp over udp client
if(INCLUDE_TCP_OVER_UDP_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TCP_OVER_UDP_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpOverUdpClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpOverUdpClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_BINARY_DIR}/tunnels/TcpOverUdpClient)
  target_link_libraries(Waterwall TcpOverUdpClient)
endif()

#tcp over udp server
if(INCLUDE_TCP_OVER_UDP_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TCP_OVER_UDP_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpOverUdpServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpOverUdpServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_BINARY_DIR}/tunnels/TcpOverUdpServer)
  target_link_libraries(Waterwall TcpOverUdpServer)
endif()

#bridge
if(INCLUDE_BRIDGE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_BRIDGE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bridge)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bridge)
  target_link_libraries(Waterwall Bridge)
endif()

#reverse client
if(INCLUDE_REVERSE_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REVERSE_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseClient)
  target_link_libraries(Waterwall ReverseClient)
endif()

#sniff router
if(INCLUDE_SNIFF_ROUTER)
  if(NOT TARGET ReverseClient)
    message(FATAL_ERROR "SniffRouter requires INCLUDE_REVERSE_CLIENT=ON")
  endif()
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SNIFF_ROUTER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SniffRouter)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SniffRouter)
  target_link_libraries(Waterwall SniffRouter)
endif()

#router
if(INCLUDE_ROUTER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_ROUTER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Router)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Router)
  target_link_libraries(Waterwall Router)
endif()

#http server
if(INCLUDE_HTTP_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HTTP_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HttpServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HttpServer)
  target_link_libraries(Waterwall HttpServer)
endif()

#http client
if(INCLUDE_HTTP_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HTTP_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HttpClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HttpClient)
  target_link_libraries(Waterwall HttpClient)
endif()

#socks5 client
if(INCLUDE_SOCKS5_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SOCKS5_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Socks5Client)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Socks5Client)
  target_link_libraries(Waterwall Socks5Client)
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

#tls server
if(INCLUDE_TLS_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TLS_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TlsServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TlsServer)
  target_link_libraries(Waterwall TlsServer)
endif()

#trojan client
if(INCLUDE_TROJAN_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TROJAN_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TrojanClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TrojanClient)
  target_link_libraries(Waterwall TrojanClient)
endif()

#vless client
if(INCLUDE_VLESS_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_VLESS_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/VlessClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/VlessClient)
  target_link_libraries(Waterwall VlessClient)
endif()

#trojan server
if(INCLUDE_TROJAN_SERVER)
  if(NOT INCLUDE_USER_CONTROLLER)
    message(FATAL_ERROR "TrojanServer requires INCLUDE_USER_CONTROLLER because it creates an internal UserController")
  endif()
  target_compile_definitions(Waterwall PUBLIC INCLUDE_TROJAN_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TrojanServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TrojanServer)
  target_link_libraries(Waterwall TrojanServer)
endif()

#vless server
if(INCLUDE_VLESS_SERVER)
  if(NOT INCLUDE_USER_CONTROLLER)
    message(FATAL_ERROR "VlessServer requires INCLUDE_USER_CONTROLLER because auth mode creates an internal UserController")
  endif()
  target_compile_definitions(Waterwall PUBLIC INCLUDE_VLESS_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/VlessServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/VlessServer)
  target_link_libraries(Waterwall VlessServer)
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
  if(NOT TARGET ReverseClient)
    message(FATAL_ERROR "ReverseServer requires INCLUDE_REVERSE_CLIENT=ON")
  endif()
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REVERSE_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ReverseServer)
  target_link_libraries(Waterwall ReverseServer)
endif()

#header server
if(INCLUDE_HEADER_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HEADER_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HeaderServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HeaderServer)
  target_link_libraries(Waterwall HeaderServer)
endif()

#header client
if(INCLUDE_HEADER_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_HEADER_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HeaderClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/HeaderClient)
  target_link_libraries(Waterwall HeaderClient)
endif()

#obfuscator client
if(INCLUDE_OBFUSCATOR_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_OBFUSCATOR_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ObfuscatorClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ObfuscatorClient)
  target_link_libraries(Waterwall ObfuscatorClient)
endif()

#obfuscator server
if(INCLUDE_OBFUSCATOR_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_OBFUSCATOR_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ObfuscatorServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/ObfuscatorServer)
  target_link_libraries(Waterwall ObfuscatorServer)
endif()

#encryption client
if(INCLUDE_ENCRYPTION_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_ENCRYPTION_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/EncryptionClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/EncryptionClient)
  target_link_libraries(Waterwall EncryptionClient)
endif()

#encryption server
if(INCLUDE_ENCRYPTION_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_ENCRYPTION_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/EncryptionServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/EncryptionServer)
  target_link_libraries(Waterwall EncryptionServer)
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
  if(NOT INCLUDE_USER_CONTROLLER)
    message(FATAL_ERROR "Socks5Server requires INCLUDE_USER_CONTROLLER because it creates an internal UserController")
  endif()
  # Socks5Server's typed UDP-provider capability is compiled even when the
  # provider nodes themselves are not registered in this build. This keeps a
  # TCP-only Socks5Server usable in reduced builds while allowing udp: true to
  # fail at topology preparation instead of creating a link-time feature gap.
  if(NOT TARGET UdpListener)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/UdpListener)
  endif()
  if(NOT TARGET TcpListener)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpListener)
  endif()
  if(NOT TARGET TcpUdpListener)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/TcpUdpListener)
  endif()
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SOCKS_5_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Socks5Server)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Socks5Server)
  target_link_libraries(Waterwall Socks5Server)
endif()

if(INCLUDE_REALITY_SERVER OR INCLUDE_REALITY_CLIENT)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/RealityCommon)
endif()

#reality server
if(INCLUDE_REALITY_SERVER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REALITY_SERVER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/RealityServer)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/RealityServer)
  target_link_libraries(Waterwall RealityServer)
endif()

#reality client
if(INCLUDE_REALITY_CLIENT)
  if(NOT TARGET TlsClient)
    message(FATAL_ERROR "RealityClient requires INCLUDE_TLS_CLIENT=ON")
  endif()
  target_compile_definitions(Waterwall PUBLIC INCLUDE_REALITY_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/RealityClient)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/RealityClient)
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
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bgp4Server)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bgp4Server)
  target_link_libraries(Waterwall Bgp4Server)
endif()

#bgp4client client
if(INCLUDE_BGP4_CLIENT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_BGP4_CLIENT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bgp4Client)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Bgp4Client)
  target_link_libraries(Waterwall Bgp4Client)
endif()

if(INCLUDE_MUX_SERVER OR INCLUDE_MUX_CLIENT)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Internals/MuxCommon)
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

#disturber
if(INCLUDE_DISTURBER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_DISTURBER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Disturber)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/Disturber)
  target_link_libraries(Waterwall Disturber)
endif()

#junk datagram sender
if(INCLUDE_JUNK_DATAGRAM_SENDER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_JUNK_DATAGRAM_SENDER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/JunkDatagramSender)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/JunkDatagramSender)
  target_link_libraries(Waterwall JunkDatagramSender)
endif()

#blackhole
if(INCLUDE_BLACKHOLE)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_BLACKHOLE=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/BlackHole)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/BlackHole)
  target_link_libraries(Waterwall BlackHole)
endif()

if(INCLUDE_SPEEDLIMIT)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SPEEDLIMIT=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SpeedLimit)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SpeedLimit)
  target_link_libraries(Waterwall SpeedLimit)
endif()

if(INCLUDE_SOFT_IP_LIMITER)
  target_compile_definitions(Waterwall PUBLIC INCLUDE_SOFT_IP_LIMITER=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SoftIpLimiter)
  target_link_directories(Waterwall PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tunnels/SoftIpLimiter)
  target_link_libraries(Waterwall SoftIpLimiter)
endif()

#--------------------------------------------------------------------------------
# Platform-Specific Linker and Compiler Flags
#--------------------------------------------------------------------------------

# Enable Unity Build (already enabled globally)
# set_target_properties(Waterwall PROPERTIES UNITY_BUILD ON)

# Use C++ linker for proper C++ runtime handling (especially for BoringSSL)
set_target_properties(Waterwall PROPERTIES LINKER_LANGUAGE CXX)

# Disable import library generation for the executable
set_target_properties(Waterwall PROPERTIES ENABLE_EXPORTS FALSE)

# Ensure no import library is generated
if(WIN32 AND (MINGW OR MSYS))
  set_target_properties(Waterwall PROPERTIES 
    ARCHIVE_OUTPUT_NAME ""
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/symbols_archive"
    WINDOWS_EXPORT_ALL_SYMBOLS FALSE
  )
endif()

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
target_compile_definitions(Waterwall PUBLIC WATERWALL_VERSION=${Waterwall_VERSION})

if(BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  target_compile_definitions(Waterwall PRIVATE WATERWALL_TEST_HOOKS=1)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
elseif(BUILD_TESTING)
  # The tests/ subtree above is Linux-only, but neither tunnel hard-abort test
  # depends on it: the policy check is a pure source scan and the runtime cases
  # use no POSIX-only header or process API. Both are registered here so Windows
  # and macOS keep the same abort coverage.
  #
  # Python is REQUIRED rather than optional: silently dropping the policy test
  # would leave the 234 Category-D candidates unchecked on this platform, so a
  # missing interpreter must fail configuration instead of failing open.
  find_program(WATERWALL_POLICY_TEST_PYTHON NAMES python3 python REQUIRED)

  add_test(
    NAME waterwall.tunnels_abort_policy_test
    COMMAND
      "${WATERWALL_POLICY_TEST_PYTHON}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/tunnels_abort_policy_test.py"
      "--mutation-test"
  )
  set_tests_properties(
    waterwall.tunnels_abort_policy_test
    PROPERTIES
      TIMEOUT 120
      LABELS "unit;tunnels;policy;abort"
  )

  include("${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/tunnels_abort_runtime_test.cmake")
endif()

# Register the same portable sampler, idle, and MUX contracts in the supported
# non-Linux native-unit trees. Native Linux includes this module from its full
# tests/unittests configuration above.
if(BUILD_TESTING AND WW_BUILD_UNIT_TESTS AND
   NOT (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING))
  include("${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/portable_contract_tests.cmake")
endif()

# Windows does not add the tests/ subtree, so register the focused interface-name
# test here as well. The test remains build-on-demand through its CTest runner.
if(BUILD_TESTING AND WW_BUILD_UNIT_TESTS AND WIN32)
  target_compile_definitions(ww PUBLIC SIGNAL_MANAGER_TEST_HOOKS=1)
  add_executable(windows_console_shutdown_test EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/windows_console_shutdown_test.c)
  set_target_properties(windows_console_shutdown_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_compile_definitions(windows_console_shutdown_test PRIVATE SIGNAL_MANAGER_TEST_HOOKS=1)
  target_link_libraries(windows_console_shutdown_test PRIVATE ww)
  add_test(
    NAME waterwall.windows_console_shutdown_unit
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=windows_console_shutdown_test"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:windows_console_shutdown_test>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/run_unit_test.cmake"
  )
  set_tests_properties(waterwall.windows_console_shutdown_unit PROPERTIES
    TIMEOUT 120
    LABELS "unit;signal-manager;shutdown;windows"
    RESOURCE_LOCK waterwall_unit_test_build)
  waterwall_register_platform_native_unit(
    waterwall.windows_console_shutdown_unit
    windows_console_shutdown_test
    "unit;signal-manager;shutdown;windows")

  add_executable(wtime_epoch_test EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/wtime_epoch_test.c)
  set_target_properties(wtime_epoch_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_link_libraries(wtime_epoch_test PRIVATE ww)
  add_test(
    NAME waterwall.wtime_epoch_unit
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=wtime_epoch_test"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:wtime_epoch_test>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/run_unit_test.cmake"
  )
  set_tests_properties(waterwall.wtime_epoch_unit PROPERTIES
    TIMEOUT 120
    LABELS "unit;libc;time;epoch;overflow;windows"
    RESOURCE_LOCK waterwall_unit_test_build)
  waterwall_register_platform_native_unit(
    waterwall.wtime_epoch_unit wtime_epoch_test "unit;libc;time;epoch;overflow;windows")

  add_executable(wsocket_windows_interface_test EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/wsocket_windows_interface_test.c)
  set_target_properties(wsocket_windows_interface_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_link_libraries(wsocket_windows_interface_test PRIVATE ww)
  add_test(
    NAME waterwall.wsocket_windows_interface_unit
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=wsocket_windows_interface_test"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:wsocket_windows_interface_test>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/run_unit_test.cmake"
  )
  set_tests_properties(waterwall.wsocket_windows_interface_unit PROPERTIES
    TIMEOUT 120
    LABELS "unit;net;socket;windows;interface"
    RESOURCE_LOCK waterwall_unit_test_build)
  waterwall_register_platform_native_unit(
    waterwall.wsocket_windows_interface_unit wsocket_windows_interface_test "unit;net;socket;windows;interface")
endif()

# Native-IOCP-only tests. The Linux tests/ subdirectory is not added on Windows,
# so the native IOCP backend registers its own test executable here, and only
# when that backend is actually selected (windows-iocp preset).
if(BUILD_TESTING AND WW_BUILD_UNIT_TESTS AND WIN32 AND WITH_NATIVE_IOCP)
  # Narrow AcceptEx fault-injection seam. PUBLIC so the ww static library and the
  # test executable agree on the declaration; it stays out of production builds
  # because this block only runs for a testing-enabled native IOCP configuration.
  target_compile_definitions(ww PUBLIC WATERWALL_IOCP_TEST_HOOKS=1)

  add_executable(iocp_native_test EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/iocp_native_test.c)
  set_target_properties(iocp_native_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
  )
  target_link_libraries(iocp_native_test PRIVATE ww ws2_32 mswsock)
  add_test(
    NAME waterwall.iocp_native
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=iocp_native_test"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:iocp_native_test>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/unittests/run_unit_test.cmake"
  )
  set_tests_properties(waterwall.iocp_native PROPERTIES
    TIMEOUT 120
    LABELS "unit;net;iocp;windows;native"
    RESOURCE_LOCK waterwall_unit_test_build)
  waterwall_register_platform_native_unit(
    waterwall.iocp_native iocp_native_test "unit;net;iocp;windows;native")
endif()

if(TARGET waterwall_platform_unit_tests)
  set(waterwall_platform_lto_artifacts "")
  foreach(waterwall_platform_lto_target IN ITEMS ww ww_lwip TlsClient)
    if(TARGET ${waterwall_platform_lto_target})
      add_dependencies(waterwall_platform_unit_tests ${waterwall_platform_lto_target})
      string(APPEND waterwall_platform_lto_artifacts
        "${waterwall_platform_lto_target}\t$<TARGET_FILE:${waterwall_platform_lto_target}>\n")
    endif()
  endforeach()
  file(GENERATE
    OUTPUT "${CMAKE_BINARY_DIR}/unit_lto_contract-$<CONFIG>.tsv"
    CONTENT "${waterwall_platform_lto_artifacts}")

  add_test(
    NAME waterwall.unit_release_no_lto_policy
    COMMAND
      "${WATERWALL_POLICY_TEST_PYTHON}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit_release_no_lto_policy_test.py"
      --unit-build "${CMAKE_BINARY_DIR}"
      --configuration "$<CONFIG>"
      --target waterwall_platform_unit_tests
      --manifest "${CMAKE_BINARY_DIR}/unit_lto_contract-$<CONFIG>.tsv"
    CONFIGURATIONS Release)
  set_tests_properties(waterwall.unit_release_no_lto_policy PROPERTIES
    TIMEOUT 120
    LABELS "unit;policy;build;ipo;lto")
endif()


message(STATUS "Waterwall version: ${Waterwall_VERSION}")
