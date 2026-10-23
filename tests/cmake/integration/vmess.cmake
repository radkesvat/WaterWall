# Independent V2Ray peer, provisioned explicitly before the loopback-only tests.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   TARGET VmessServer AND TARGET TcpListener AND TARGET TcpConnector AND TARGET UdpConnector)
  set(vmess_reference_cache "${CMAKE_SOURCE_DIR}/build/test-tools/v2ray-5.53.0")
  set(WATERWALL_VMESS_REFERENCE "${vmess_reference_cache}/v2ray" CACHE FILEPATH
      "Pinned V2Ray 5.53.0 executable used by VMess interoperability tests")
  add_custom_target(waterwall_vmess_reference
    COMMAND "${PYTHON3_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/provision_vmess_reference.py"
      --cache-dir "${vmess_reference_cache}"
    COMMENT "Provisioning the pinned V2Ray 5.53.0 interoperability reference"
    VERBATIM)

  function(add_waterwall_vmess_interop test_suffix)
    set(test_name "waterwall.vmess_${test_suffix}")
    add_waterwall_isolated_test(${test_name}
      "${PYTHON3_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/vmess_interop.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${WATERWALL_VMESS_REFERENCE}" ${ARGN})
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 75)
    add_waterwall_test_labels(${test_name} "integration" "tunnels" "vmess" "interoperability")
    if(NOT WATERWALL_ENABLE_INTEGRATION_TEST_NETNS)
      set_tests_properties(${test_name} PROPERTIES RESOURCE_LOCK waterwall_vmess_ports)
    endif()
  endfunction()

  set(vmess_auth_modes local)
  if(TARGET AuthenticationClient AND TARGET AuthenticationServer AND TARGET UserController)
    list(APPEND vmess_auth_modes database)
  endif()
  foreach(auth IN LISTS vmess_auth_modes)
    foreach(cipher IN ITEMS aes-128-gcm chacha20-poly1305 none zero)
      string(REPLACE "-" "_" cipher_label "${cipher}")
      add_waterwall_vmess_interop("${auth}_${cipher_label}_tcp"
        --auth "${auth}" --cipher "${cipher}" --protocol tcp)
      if(NOT cipher STREQUAL "zero")
        add_waterwall_vmess_interop("${auth}_${cipher_label}_udp"
          --auth "${auth}" --cipher "${cipher}" --protocol udp)
      endif()
    endforeach()
  endforeach()
  add_waterwall_vmess_interop(wrong_uuid --scenario wrong_uuid)
  add_waterwall_vmess_interop(tamper_does_not_fallback --scenario tamper)
  add_waterwall_vmess_interop(split --scenario split --workers 2)
  add_waterwall_vmess_interop(fallback --scenario fallback --workers 2)
  if("database" IN_LIST vmess_auth_modes)
    add_waterwall_vmess_interop(connection_limit --auth database --scenario connection_limit --workers 2)
  endif()
  if(TARGET TlsServer)
    add_waterwall_vmess_interop(tls --transport tls --cipher zero)
  endif()
  if(TARGET HttpServer)
    add_waterwall_vmess_interop(websocket --transport ws --cipher none)
    if(TARGET TlsServer)
      add_waterwall_vmess_interop(websocket_tls --transport wss)
    endif()
  endif()
endif()
