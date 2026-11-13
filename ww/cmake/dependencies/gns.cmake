# Native CMake embedding of Valve GameNetworkingSockets for plain UDP connections
# over a datagram transport that WaterWall supplies. The pinned upstream sources
# are compiled as they are, apart from the exact text replacements below, and
# tunnels/Internals/GnsCommon/transport/steamnetworkingsockets_externaltransport.cpp
# is compiled in place of upstream's steamnetworkingsockets_socketthread.cpp, so
# the library cannot create, poll or close an OS socket. Sources are listed, not
# globbed; the list follows upstream src/CMakeLists.txt at the revision below.
include_guard(GLOBAL)
include("${CMAKE_CURRENT_LIST_DIR}/protobuf.cmake")

# Replaces one exact text in the source held by ${variable}. The text must occur
# exactly once: a pin update that moves or repeats it stops the configuration
# instead of building an unpatched source.
function(waterwall_gns_replace variable upstream replacement)
  string(FIND "${${variable}}" "${upstream}" first)
  string(FIND "${${variable}}" "${upstream}" last REVERSE)
  if(first EQUAL -1 OR NOT first EQUAL last)
    message(FATAL_ERROR "GameNetworkingSockets overlay: expected exactly one occurrence of:\n${upstream}")
  endif()
  string(REPLACE "${upstream}" "${replacement}" patched "${${variable}}")
  set(${variable} "${patched}" PARENT_SCOPE)
endfunction()

# Rewrites an overlay file only when its text changes, so a reconfiguration does
# not rebuild it.
function(waterwall_gns_write path text)
  if(EXISTS "${path}")
    file(READ "${path}" existing)
    if(existing STREQUAL text)
      return()
    endif()
  endif()
  file(WRITE "${path}" "${text}")
endfunction()

function(waterwall_enable_gns)
  if(TARGET WaterWall::Gns)
    return()
  endif()
  if(NOT TARGET WaterWall::BoringSSL)
    message(FATAL_ERROR "GameNetworkingSockets requires the shared prefixed WaterWall BoringSSL provider")
  endif()

  waterwall_dependency_source(ww_gns
    "https://codeload.github.com/ValveSoftware/GameNetworkingSockets/tar.gz/d534c19aa760df3fb75fd20db13ba1932b8a5463"
    099d4b0ff1837f0f27c83d4ce05869ec1d32136866f69a3336cc137e951189ab)
  set(source "${ww_gns_SOURCE_DIR}/src")
  set(overlay "${CMAKE_BINARY_DIR}/ww-dependencies/gns-overlay")
  set(generated "${CMAKE_BINARY_DIR}/ww-dependencies/gns-generated")
  set(transport "${PROJECT_SOURCE_DIR}/tunnels/Internals/GnsCommon/transport")
  file(MAKE_DIRECTORY "${overlay}" "${generated}")
  set(gns_sources "")

  # The messages are built for the lite runtime that QUICHE already links. The
  # full runtime's descriptors and reflection are not part of this build.
  get_property(host_protoc GLOBAL PROPERTY WATERWALL_HOST_PROTOC)
  foreach(proto IN ITEMS steamnetworkingsockets_messages_certs steamnetworkingsockets_messages
      steamnetworkingsockets_messages_udp)
    file(READ "${source}/common/${proto}.proto" text)
    waterwall_gns_replace(text "option optimize_for = SPEED;" "option optimize_for = LITE_RUNTIME;")
    waterwall_gns_write("${overlay}/${proto}.proto" "${text}")
    add_custom_command(OUTPUT "${generated}/${proto}.pb.cc" "${generated}/${proto}.pb.h"
      COMMAND "${host_protoc}" "--proto_path=${overlay}" "--cpp_out=${generated}" "${overlay}/${proto}.proto"
      DEPENDS "${host_protoc}" "${overlay}/${proto}.proto"
      VERBATIM COMMENT "Generating GameNetworkingSockets lite protobuf ${proto}")
    list(APPEND gns_sources "${generated}/${proto}.pb.cc")
  endforeach()

  # protobuf-lite keeps unknown fields as a string and cannot count or list them.
  file(READ "${source}/steamnetworkingsockets/steamnetworkingsockets_certs.cpp" text)
  waterwall_gns_replace(text
    "if ( msgIdentity.unknown_fields().field_count() > 0 )"
    "if ( !msgIdentity.unknown_fields().empty() )")
  waterwall_gns_replace(text
    "V_sprintf_safe( errMsg, \"Unrecognized identity format.  (%d unknown field(s), first ID=%d)\", msgIdentity.unknown_fields().field_count(), msgIdentity.unknown_fields().field(0).number() );"
    "V_strcpy_safe( errMsg, \"Unrecognized identity format.  (Unknown fields present)\" );")
  waterwall_gns_write("${overlay}/steamnetworkingsockets_certs.cpp" "${text}")

  # BoringSSL has no EVP_PKEY_new_mac_key. The one-shot HMAC() exists in OpenSSL
  # and in BoringSSL, and upstream's SHA-1 variant in the same file uses it.
  file(READ "${source}/common/crypto_digest_opensslevp.cpp" text)
  string(CONCAT hmac_upstream
    "\tEVPCTXPointer<EVP_MD_CTX *, EVP_MD_CTX_free> mdctx(EVP_MD_CTX_create());\n"
    "\tEVPCTXPointer<EVP_PKEY *, EVP_PKEY_free> pkey(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pubKey, cubKey));\n"
    "\tconst EVP_MD *digest = EVP_sha256();\n"
    "\n"
    "\tVerifyFatal(mdctx.ctx != NULL && pkey.ctx != NULL);\n"
    "\tVerifyFatal(EVP_DigestInit_ex(mdctx.ctx, digest, NULL) == 1);\n"
    "\tVerifyFatal(EVP_DigestSignInit(mdctx.ctx, NULL, digest, NULL, pkey.ctx) == 1);\n"
    "\tVerifyFatal(EVP_DigestSignUpdate(mdctx.ctx, pubData, cubData) == 1);\n"
    "\n"
    "\tsize_t needed = sizeof(SHA256Digest_t);\n"
    "\tVerifyFatal(EVP_DigestSignFinal(mdctx.ctx, *pOutputDigest, &needed) == 1);\n")
  string(CONCAT hmac_portable
    "\tunsigned int needed = sizeof(SHA256Digest_t);\n"
    "\tVerifyFatal(HMAC(EVP_sha256(), pubKey, cubKey, pubData, cubData, *pOutputDigest, &needed) != NULL);\n")
  waterwall_gns_replace(text "${hmac_upstream}" "${hmac_portable}")
  waterwall_gns_write("${overlay}/crypto_digest_opensslevp.cpp" "${text}")

  # BoringSSL reports an OpenSSL 1.1.1 version number but has neither the custom
  # RAND method that this file installs nor CRYPTO_cleanup_all_ex_data.
  file(READ "${source}/common/opensslwrapper.cpp" text)
  waterwall_gns_replace(text
    "#if !IsAndroid() && ( OPENSSL_VERSION_NUMBER < 0x30000000 )\n"
    "#if !IsAndroid() && ( OPENSSL_VERSION_NUMBER < 0x30000000 ) && !defined( OPENSSL_IS_BORINGSSL )\n")
  waterwall_gns_replace(text
    "\t\tCRYPTO_cleanup_all_ex_data();\n"
    "#ifndef OPENSSL_IS_BORINGSSL\n\t\tCRYPTO_cleanup_all_ex_data();\n#endif\n")
  waterwall_gns_write("${overlay}/opensslwrapper.cpp" "${text}")

  # Upstream's GNS_COMMON_SRCS, GNS_CLIENTLIB_SRCS and its OpenSSL crypto
  # sources. Not compiled: the socket file named above, the ICE and WebRTC
  # transports, ISteamNetworkingMessages and the flat C interface.
  foreach(relative IN ITEMS
      common/crypto.cpp common/crypto_25519_openssl.cpp common/crypto_openssl.cpp
      common/crypto_symmetric_opensslevp.cpp common/crypto_textencode.cpp common/keypair.cpp
      common/steamid.cpp
      steamnetworkingsockets/steamnetworkingsockets_certstore.cpp
      steamnetworkingsockets/steamnetworkingsockets_shared.cpp
      steamnetworkingsockets/steamnetworkingsockets_stats.cpp
      steamnetworkingsockets/steamnetworkingsockets_thinker.cpp
      steamnetworkingsockets/clientlib/csteamnetworkingsockets.cpp
      steamnetworkingsockets/clientlib/steamnetworkingsockets_connections.cpp
      steamnetworkingsockets/clientlib/steamnetworkingsockets_lowlevel_misc.cpp
      steamnetworkingsockets/clientlib/steamnetworkingsockets_p2p.cpp
      steamnetworkingsockets/clientlib/steamnetworkingsockets_snp.cpp
      steamnetworkingsockets/clientlib/steamnetworkingsockets_spew.cpp
      steamnetworkingsockets/clientlib/steamnetworkingsockets_taskqueue.cpp
      steamnetworkingsockets/clientlib/steamnetworkingsockets_udp.cpp
      tier0/dbg.cpp tier0/platformtime.cpp tier0/valve_tracelogging.cpp
      tier1/ipv6text.c tier1/netadr.cpp tier1/utlbuffer.cpp tier1/utlmemory.cpp
      vstdlib/strtools.cpp)
    list(APPEND gns_sources "${source}/${relative}")
  endforeach()
  list(APPEND gns_sources "${overlay}/steamnetworkingsockets_certs.cpp"
    "${overlay}/crypto_digest_opensslevp.cpp" "${overlay}/opensslwrapper.cpp"
    "${transport}/steamnetworkingsockets_externaltransport.cpp")

  add_library(waterwall_gns STATIC ${gns_sources})
  add_library(WaterWall::Gns ALIAS waterwall_gns)
  add_dependencies(waterwall_gns waterwall_host_protoc)
  target_include_directories(waterwall_gns SYSTEM PUBLIC "${ww_gns_SOURCE_DIR}/include")
  target_include_directories(waterwall_gns PUBLIC "${transport}")
  # The overlay and transport sources use the include lines of the directories
  # they replace files in.
  target_include_directories(waterwall_gns PRIVATE "${source}/common" "${source}/public"
    "${source}/steamnetworkingsockets" "${source}/steamnetworkingsockets/clientlib" "${generated}")
  # STATIC_LINK keeps the interface functions plain extern "C". FOREXPORT is
  # upstream's name for "this is the library itself": among other things it
  # routes failed assertions to the debug output function instead of stderr.
  target_compile_definitions(waterwall_gns PUBLIC STEAMNETWORKINGSOCKETS_STATIC_LINK)
  target_compile_definitions(waterwall_gns PRIVATE STEAMNETWORKINGSOCKETS_FOREXPORT
    VALVE_CRYPTO_ENABLE_25519 VALVE_CRYPTO_OPENSSL VALVE_CRYPTO_25519_OPENSSLEVP ENABLE_OPENSSLCONNECTION
    STEAMNETWORKINGSOCKETS_DISABLE_STEAMNETWORKINGMESSAGES)
  # Upstream's self-check level for release builds, in every configuration. Its
  # level for debug builds walks the whole in-flight packet map on every packet,
  # which stalls a connection under load.
  target_compile_definitions(waterwall_gns PRIVATE STEAMNETWORKINGSOCKETS_SNP_PARANOIA=1)
  # Upstream's platform names (set_target_common_gns_properties).
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(waterwall_gns PUBLIC LINUX)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    target_compile_definitions(waterwall_gns PUBLIC ANDROID)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR CMAKE_SYSTEM_NAME STREQUAL "visionOS")
    target_compile_definitions(waterwall_gns PUBLIC IOS)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "tvOS")
    target_compile_definitions(waterwall_gns PUBLIC TVOS)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "watchOS")
    target_compile_definitions(waterwall_gns PUBLIC WATCHOS)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_compile_definitions(waterwall_gns PUBLIC OSX)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    target_compile_definitions(waterwall_gns PUBLIC FREEBSD)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_compile_definitions(waterwall_gns PUBLIC OPENBSD)
  elseif(WIN32)
    target_compile_definitions(waterwall_gns PUBLIC _WINDOWS)
    # Windows has no struct iovec. The library defines one with the layout of
    # WSABUF and QUICHE defines one with the POSIX layout, and two types of one
    # name in one program break the One Definition Rule. The library's own
    # sources see theirs under a name of its own.
    target_compile_definitions(waterwall_gns PRIVATE iovec=waterwall_gns_iovec)
    if(MSVC)
      target_compile_definitions(waterwall_gns PRIVATE _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
      if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID MATCHES "^ARM")
        # Upstream's platform header does not know MSVC's names for Arm
        # targets. Windows on Arm is little-endian.
        target_compile_definitions(waterwall_gns PRIVATE VALVE_LITTLE_ENDIAN=1)
      endif()
    else()
      target_compile_definitions(waterwall_gns PRIVATE __STDC_FORMAT_MACROS=1 __USE_MINGW_ANSI_STDIO=0)
    endif()
  else()
    message(FATAL_ERROR "GameNetworkingSockets has no platform name for ${CMAKE_SYSTEM_NAME}")
  endif()
  find_package(Threads REQUIRED)
  target_link_libraries(waterwall_gns PUBLIC WaterWall::BoringSSL protobuf::libprotobuf-lite Threads::Threads)
  if(WIN32)
    # timeBeginPeriod: the service thread sleeps in whole milliseconds, as upstream's does.
    target_link_libraries(waterwall_gns PUBLIC winmm)
  endif()

  waterwall_configure_runtime_dependency(waterwall_gns)
  target_link_libraries(waterwall_gns PRIVATE waterwall_cpu_options)
  # The same C++ standard as the protobuf and Abseil headers it includes.
  set_target_properties(waterwall_gns PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS ON UNITY_BUILD OFF DISABLE_PRECOMPILE_HEADERS ON)
  if(NOT MSVC)
    target_compile_options(waterwall_gns PRIVATE -fno-strict-aliasing)
  endif()
endfunction()

waterwall_enable_gns()
