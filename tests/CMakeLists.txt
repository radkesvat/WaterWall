include("${CMAKE_SOURCE_DIR}/tests/cmake/TestHelpers.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/Helpers.cmake")
find_program(BASH_EXECUTABLE bash REQUIRED)
find_program(PYTHON3_EXECUTABLE python3 REQUIRED)

set(WATERWALL_TEST_TARGET "Waterwall")

option(
  WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS
  "Enable integration tests that require root/CAP_NET_ADMIN and TUN device support"
  ON
)

option(
  WATERWALL_ENABLE_TUN_TCP_SPEEDTEST
  "Enable the optional iperf3 TunDevice TCP chain GSO comparison"
  OFF
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  set(WATERWALL_DEFAULT_INTEGRATION_TEST_NETNS ON)
else()
  set(WATERWALL_DEFAULT_INTEGRATION_TEST_NETNS OFF)
endif()

option(
  WATERWALL_ENABLE_INTEGRATION_TEST_NETNS
  "Run Linux integration tests inside private user + network namespaces"
  ${WATERWALL_DEFAULT_INTEGRATION_TEST_NETNS}
)

if(WATERWALL_ENABLE_INTEGRATION_TEST_NETNS)
  find_program(UNSHARE_EXECUTABLE unshare REQUIRED)
  find_program(IP_EXECUTABLE ip REQUIRED)
  set(waterwall_test_network_mode "isolated")
else()
  set(waterwall_test_network_mode "host-serial")
endif()

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/waterwall_test_network_mode.txt" "${waterwall_test_network_mode}\n")

set(waterwall_production_lto_artifacts "")
foreach(waterwall_production_lto_target IN ITEMS ww ww_lwip TlsClient)
  if(TARGET ${waterwall_production_lto_target})
    string(APPEND waterwall_production_lto_artifacts
      "${waterwall_production_lto_target}\t$<TARGET_FILE:${waterwall_production_lto_target}>\n")
  endif()
endforeach()
file(GENERATE
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/production_lto_contract-$<CONFIG>.tsv"
  CONTENT "${waterwall_production_lto_artifacts}"
)

if(WW_BUILD_UNIT_TESTS)
  add_subdirectory(unittests EXCLUDE_FROM_ALL)

  set(waterwall_unit_lto_artifacts "")
  foreach(waterwall_unit_lto_target IN ITEMS ww ww_lwip TlsClient)
    if(TARGET ${waterwall_unit_lto_target})
      add_dependencies(waterwall_unit_tests ${waterwall_unit_lto_target})
      string(APPEND waterwall_unit_lto_artifacts
        "${waterwall_unit_lto_target}\t$<TARGET_FILE:${waterwall_unit_lto_target}>\n")
    endif()
  endforeach()
  file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/unit_lto_contract-$<CONFIG>.tsv"
    CONTENT "${waterwall_unit_lto_artifacts}")

  add_test(
    NAME waterwall.unit_release_no_lto_policy
    COMMAND
      "${PYTHON3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/unit_release_no_lto_policy_test.py"
      --unit-build "${CMAKE_BINARY_DIR}"
      --configuration "$<CONFIG>"
      --target waterwall_unit_tests
      --manifest "${CMAKE_CURRENT_BINARY_DIR}/unit_lto_contract-$<CONFIG>.tsv"
    CONFIGURATIONS Release)
  set_tests_properties(waterwall.unit_release_no_lto_policy PROPERTIES
    TIMEOUT 120
    LABELS "unit;policy;build;ipo;lto")
endif()
add_subdirectory(benchmarks)

include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/support.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/stream-codecs.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/socks.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/trojan-vless.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/http-framing.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/mux.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/packet-bridges.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/ping.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/reverse.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/wireguard-packets.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/speed.cmake")
include("${CMAKE_SOURCE_DIR}/tests/cmake/integration/http-proxy.cmake")
