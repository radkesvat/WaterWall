if(NOT WW_BUILD_UNIT_TESTS)
  message(FATAL_ERROR "tests/unittests requires WW_BUILD_UNIT_TESTS=ON")
endif()

# The ww target publishes a PCH for production consumers. Unit tests are many
# independent executables, so inheriting it would create one large PCH per test
# and configuration. Keep PCH enabled for the runtime and tunnel targets only.
set(CMAKE_DISABLE_PRECOMPILE_HEADERS ON)

include_directories(
  ${CMAKE_SOURCE_DIR}/tests/support/c
  ${CMAKE_SOURCE_DIR}/ww
  ${CMAKE_SOURCE_DIR}/ww/base
  ${CMAKE_SOURCE_DIR}/ww/base/internal_types
  ${CMAKE_SOURCE_DIR}/ww/node_builder
  ${CMAKE_SOURCE_DIR}/ww/bufio
  ${CMAKE_SOURCE_DIR}/ww/event
  ${CMAKE_SOURCE_DIR}/ww/net
  ${CMAKE_SOURCE_DIR}/ww/instance
  ${CMAKE_SOURCE_DIR}/ww/libc
  ${CMAKE_SOURCE_DIR}/ww/crypto
  ${CMAKE_SOURCE_DIR}/ww/lwip
  ${CMAKE_SOURCE_DIR}/ww/lwip/contrib/ports/unix/port/include
  ${CMAKE_SOURCE_DIR}/ww/vendor/asmlib
  ${CMAKE_SOURCE_DIR}/ww/vendor/cjson
  ${CMAKE_BINARY_DIR}/ww
  ${CMAKE_BINARY_DIR}/ww/generated
  ${CMAKE_BINARY_DIR}/patched-deps/lwip/src/include
  ${CMAKE_BINARY_DIR}/patched-deps/lwip/contrib
  ${CMAKE_BINARY_DIR}/_deps/cares-build
  ${cares_SOURCE_DIR}
  ${cares_SOURCE_DIR}/include
  ${komihash_SOURCE_DIR}
  ${stc_SOURCE_DIR}/include
)

if(NOT APPLE)
  add_compile_definitions(LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS=1)
endif()

add_custom_target(waterwall_unit_tests)
add_dependencies(waterwall_unit_tests test_support_regression test_support_cpp_header)

include("${CMAKE_SOURCE_DIR}/tests/cmake/TestHelpers.cmake")


include("${CMAKE_SOURCE_DIR}/tests/cmake/native/lwip-engines.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/fragmenter.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/http-proxy.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/runtime.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/codec-dependencies.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/tls.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/reality-codec.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/wireguard-encryption.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/reality-runtime.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/sniff-router.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/stream-bridges.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/portable.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/worker-contracts.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/ipmanipulator.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/router.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/tls-failure.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/failure-fixtures.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/line-failure.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/packet-bridges.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/rawsocket.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/obfuscator.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/mux.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/socket-lifetime.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/orderly-shutdown.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/socket-io.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/core-settings.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/hard-abort.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/splice-protocols.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/socks-codecs.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/native/support-linkage.cmake")
