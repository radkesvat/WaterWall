# Explicit integration registrations; preserve namespace and family variants.
if(TARGET HttpProxyServer AND TARGET AuthenticationServer AND TARGET Router AND TARGET Socks5Server)
  add_waterwall_probe_integration_test(waterwall.http_proxy_acceptance http_proxy 60)
  add_waterwall_isolated_test(waterwall.http_proxy_fallback_config
    "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/http_proxy_fallback_config_test.py"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>")
  set_tests_properties(waterwall.http_proxy_fallback_config PROPERTIES TIMEOUT 120)
  add_waterwall_test_labels(waterwall.http_proxy_fallback_config "integration" "http" "proxy" "configuration")
endif()

add_custom_target(check_waterwall_tests
  COMMAND
    "${BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_test_lane.sh"
    all
    "${CMAKE_BINARY_DIR}"
    "$<CONFIG>"
  DEPENDS ${WATERWALL_TEST_TARGET}
  USES_TERMINAL
)

add_waterwall_expected_failure_integration_test(
  waterwall.device_fragment_policy_invalid device_fragment_policy_invalid
  "Device source fragment-policy must be reassemble or preserve-fragments")
add_waterwall_privileged_probe_integration_test(
  waterwall.device_fragment_preserve_stack_roundtrip device_fragment_preserve_stack_roundtrip 20)
add_waterwall_privileged_probe_integration_test(
  waterwall.device_fragment_normalized_sink device_fragment_normalized_sink 20)
add_waterwall_privileged_probe_integration_test(
  waterwall.device_fragment_normalized_roundtrip device_fragment_normalized_roundtrip 25)
add_waterwall_privileged_probe_integration_test(
  waterwall.device_fragment_raw_forward device_fragment_raw_forward 20)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  if(WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS)
    add_waterwall_isolated_test(waterwall.tundevice_gso_live
      "${BASH_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/cases/tundevice_gso_live/run.sh"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>"
      "${CMAKE_CURRENT_SOURCE_DIR}/cases/tundevice_gso_live"
      "${PYTHON3_EXECUTABLE}")
    set_tests_properties(waterwall.tundevice_gso_live PROPERTIES
      TIMEOUT 180
      SKIP_RETURN_CODE 77
      LABELS "integration;linux;privileged;tundevice;gso")
    add_waterwall_case_resource_lock(waterwall.tundevice_gso_live tundevice_gso_live)
  else()
    add_waterwall_skipped_integration_test(waterwall.tundevice_gso_live
      "privileged TUN GSO integration requires enabled Linux privileged tests")
  endif()

  if(WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS)
    add_test(NAME waterwall.tundevice_tcp_chain
      COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tun_tcp_chain.py"
        --binary "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" --mode integration)
    set_tests_properties(waterwall.tundevice_tcp_chain PROPERTIES
      TIMEOUT 90
      SKIP_RETURN_CODE 77)
    add_waterwall_case_resource_lock(waterwall.tundevice_tcp_chain tun_tcp_chain)
  else()
    add_waterwall_skipped_integration_test(waterwall.tundevice_tcp_chain
      "TUN TCP chain integration requires -DWATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS=ON")
  endif()
  add_waterwall_test_labels(waterwall.tundevice_tcp_chain
    "integration" "linux" "privileged" "tundevice" "gso" "tcp-chain"
    "network-isolated" "self-managed-network-namespace")

  if(WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS)
    add_test(NAME waterwall.tundevice_trusted_checksum
      COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tun_trusted_checksum.py"
        --binary "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>")
    set_tests_properties(waterwall.tundevice_trusted_checksum PROPERTIES TIMEOUT 150 SKIP_RETURN_CODE 77)
    add_waterwall_case_resource_lock(waterwall.tundevice_trusted_checksum tun_trusted_checksum)
  else()
    add_waterwall_skipped_integration_test(waterwall.tundevice_trusted_checksum
      "TUN checksum integration requires enabled Linux privileged tests")
  endif()
  add_waterwall_test_labels(waterwall.tundevice_trusted_checksum
    "integration" "linux" "privileged" "tundevice" "checksum"
    "network-isolated" "self-managed-network-namespace")

  if(WATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS AND WATERWALL_ENABLE_TUN_TCP_SPEEDTEST)
    add_test(NAME waterwall.speedtest_tundevice_tcp_chain
      COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tun_tcp_chain.py"
        --binary "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" --mode speed)
    set_tests_properties(waterwall.speedtest_tundevice_tcp_chain PROPERTIES
      TIMEOUT 360
      SKIP_RETURN_CODE 77
      RUN_SERIAL TRUE)
    add_waterwall_case_resource_lock(waterwall.speedtest_tundevice_tcp_chain tun_tcp_chain)
  else()
    add_waterwall_skipped_integration_test(waterwall.speedtest_tundevice_tcp_chain
      "TUN TCP chain speed test requires -DWATERWALL_ENABLE_PRIVILEGED_INTEGRATION_TESTS=ON and -DWATERWALL_ENABLE_TUN_TCP_SPEEDTEST=ON")
  endif()
  add_waterwall_test_labels(waterwall.speedtest_tundevice_tcp_chain
    "integration" "linux" "privileged" "speedtest" "tundevice" "gso"
    "network-isolated" "self-managed-network-namespace")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND TARGET HttpProxyClient)
  add_waterwall_isolated_test(waterwall.httpproxyclient_pending_dns_shutdown
    "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/httpproxyclient_splice_integration.py"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" pending_shutdown)
  set_tests_properties(waterwall.httpproxyclient_pending_dns_shutdown PROPERTIES TIMEOUT 30)
  add_waterwall_test_labels(waterwall.httpproxyclient_pending_dns_shutdown "integration" "http" "proxy" "lifetime")
  add_waterwall_case_resource_lock(waterwall.httpproxyclient_pending_dns_shutdown httpproxyclient_splice)
  set(_hpc_modes connect fixed chunked response_chunked response_eof resolve_fixed)
  if(TARGET HttpProxyServer)
    list(APPEND _hpc_modes resolve_dynamic)
  endif()
  if(TARGET Router)
    list(APPEND _hpc_modes resolve_branch)
  endif()
  foreach(mode IN LISTS _hpc_modes)
    foreach(splice_mode IN ITEMS true false)
      add_waterwall_isolated_test(waterwall.httpproxyclient_${mode}_splice_${splice_mode}
        "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/httpproxyclient_splice_integration.py"
        "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${mode}" "${splice_mode}" direct)
      set_tests_properties(waterwall.httpproxyclient_${mode}_splice_${splice_mode} PROPERTIES TIMEOUT 60)
      add_waterwall_test_labels(waterwall.httpproxyclient_${mode}_splice_${splice_mode} "integration" "http" "proxy")
      add_waterwall_case_resource_lock(waterwall.httpproxyclient_${mode}_splice_${splice_mode} httpproxyclient_splice)
    endforeach()
  endforeach()
  if(TARGET HttpProxyServer)
    foreach(auth IN ITEMS noauth local tracked)
      foreach(mode IN ITEMS connect fixed chunked)
        foreach(splice_mode IN ITEMS true false)
          add_waterwall_isolated_test(waterwall.httpproxyclient_${auth}_${mode}_${splice_mode}
            "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/httpproxyclient_splice_integration.py"
            "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${mode}" "${splice_mode}" "${auth}")
          set_tests_properties(waterwall.httpproxyclient_${auth}_${mode}_${splice_mode} PROPERTIES TIMEOUT 60)
          add_waterwall_test_labels(waterwall.httpproxyclient_${auth}_${mode}_${splice_mode} "integration" "http" "proxy")
          add_waterwall_case_resource_lock(waterwall.httpproxyclient_${auth}_${mode}_${splice_mode} httpproxyclient_splice)
        endforeach()
      endforeach()
    endforeach()
  endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND TARGET HttpProxyClient AND TARGET TlsClient AND TARGET TlsServer)
  # TLS disables splice for this topology; enabled mode checks that capability gate.
  add_waterwall_isolated_test(waterwall.httpproxyclient_tls_splice_true
    "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/httpproxyclient_splice_integration.py"
    "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" connect true tls)
  set_tests_properties(waterwall.httpproxyclient_tls_splice_true PROPERTIES TIMEOUT 60)
  add_waterwall_test_labels(waterwall.httpproxyclient_tls_splice_true "integration" "http" "proxy")
  add_waterwall_case_resource_lock(waterwall.httpproxyclient_tls_splice_true httpproxyclient_splice)
endif()
