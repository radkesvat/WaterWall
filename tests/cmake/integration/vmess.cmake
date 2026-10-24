# Independent V2Ray peer, provisioned explicitly before the loopback-only tests.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   (TARGET VmessServer OR TARGET VmessClient))
  set(vmess_reference_cache "${CMAKE_SOURCE_DIR}/build/test-tools/v2ray-5.53.0")
  set(WATERWALL_VMESS_REFERENCE "${vmess_reference_cache}/v2ray" CACHE FILEPATH
      "Pinned V2Ray 5.53.0 executable used by VMess interoperability tests")
  add_custom_target(waterwall_vmess_reference
    COMMAND "${PYTHON3_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/provision_vmess_reference.py"
      --cache-dir "${vmess_reference_cache}"
    COMMENT "Provisioning the pinned V2Ray 5.53.0 interoperability reference"
    VERBATIM)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   TARGET VmessServer AND TARGET TcpListener AND TARGET TcpConnector)
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
      if(TARGET UdpConnector AND NOT cipher STREQUAL "zero")
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

# Outbound interoperability owns its application sockets, peer and local echo
# destinations. It uses the same provisioned binary and namespace isolation.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING AND
   TARGET VmessClient AND TARGET TcpListener AND TARGET TcpConnector)
  function(add_waterwall_vmess_client_interop suffix)
    set(test_name "waterwall.vmess_client_${suffix}")
    add_waterwall_isolated_test(${test_name}
      "${PYTHON3_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/vmess_client_interop.py"
      "$<TARGET_FILE:${WATERWALL_TEST_TARGET}>" "${WATERWALL_VMESS_REFERENCE}" ${ARGN})
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 75)
    add_waterwall_test_labels(${test_name} "integration" "tunnels" "vmess" "client" "interoperability")
    if(NOT WATERWALL_ENABLE_INTEGRATION_TEST_NETNS)
      set_tests_properties(${test_name} PROPERTIES RESOURCE_LOCK waterwall_vmess_client_ports)
    endif()
  endfunction()

  set(vmess_client_peers reference)
  if(TARGET VmessServer)
    list(APPEND vmess_client_peers local)
    if(TARGET AuthenticationClient AND TARGET AuthenticationServer AND TARGET UserController)
      list(APPEND vmess_client_peers database)
    endif()
  endif()
  foreach(peer IN LISTS vmess_client_peers)
    if(peer STREQUAL "reference")
      set(peer_args --peer reference)
    else()
      set(peer_args --peer waterwall --auth "${peer}")
    endif()
    foreach(cipher IN ITEMS aes-128-gcm chacha20-poly1305 none zero)
      string(REPLACE "-" "_" cipher_label "${cipher}")
      add_waterwall_vmess_client_interop("${peer}_${cipher_label}_tcp"
        ${peer_args} --cipher "${cipher}")
      if(TARGET UdpListener AND NOT cipher STREQUAL "zero" AND
         (peer STREQUAL "reference" OR TARGET UdpConnector))
        add_waterwall_vmess_client_interop("${peer}_${cipher_label}_udp"
          ${peer_args} --cipher "${cipher}" --protocol udp)
      endif()
    endforeach()
  endforeach()

  # Every supported encrypted framing profile and NONE's ordinary/masked
  # lengths are exercised against the independent server, including auth length.
  foreach(cipher IN ITEMS aes-128-gcm chacha20-poly1305)
    string(REPLACE "-" "_" cipher_label "${cipher}")
    foreach(options IN ITEMS 1 5 13 17 21 29)
      add_waterwall_vmess_client_interop("reference_${cipher_label}_options_${options}_tcp"
        --cipher "${cipher}" --options "${options}")
      if(TARGET UdpListener)
        add_waterwall_vmess_client_interop("reference_${cipher_label}_options_${options}_udp"
          --cipher "${cipher}" --options "${options}" --protocol udp)
      endif()
    endforeach()
  endforeach()
  add_waterwall_vmess_client_interop(reference_none_options_1_tcp --cipher none --options 1)
  if(TARGET UdpListener)
    foreach(options IN ITEMS 1 5 13)
      add_waterwall_vmess_client_interop("reference_none_options_${options}_udp"
        --cipher none --options "${options}" --protocol udp)
    endforeach()
  endif()
  foreach(scenario IN ITEMS wrong_uuid split tamper early_close silent)
    add_waterwall_vmess_client_interop("reference_${scenario}" --scenario "${scenario}" --workers 2)
  endforeach()

  foreach(peer IN LISTS vmess_client_peers)
    if(peer STREQUAL "reference")
      set(peer_args --peer reference)
    else()
      set(peer_args --peer waterwall --auth "${peer}")
    endif()
    foreach(target IN ITEMS ipv6 domain)
      add_waterwall_vmess_client_interop("${peer}_${target}" ${peer_args} --target "${target}")
    endforeach()
    if(TARGET Socks5Server)
      add_waterwall_vmess_client_interop("${peer}_context_tcp" ${peer_args} --destination context --target domain)
      if(TARGET TcpUdpListener AND TARGET UdpListener AND
         (peer STREQUAL "reference" OR TARGET UdpConnector))
        add_waterwall_vmess_client_interop("${peer}_context_udp"
          ${peer_args} --destination context --protocol udp)
      endif()
    endif()
    if(TARGET TlsClient AND (peer STREQUAL "reference" OR TARGET TlsServer))
      add_waterwall_vmess_client_interop("${peer}_tls" ${peer_args} --transport tls --cipher zero)
    endif()
    if(TARGET HttpClient AND (peer STREQUAL "reference" OR TARGET HttpServer))
      add_waterwall_vmess_client_interop("${peer}_websocket" ${peer_args} --transport ws --cipher none)
      if(TARGET TlsClient AND (peer STREQUAL "reference" OR TARGET TlsServer))
        add_waterwall_vmess_client_interop("${peer}_websocket_tls" ${peer_args} --transport wss)
      endif()
    endif()
  endforeach()
  if("local" IN_LIST vmess_client_peers)
    foreach(strategy IN ITEMS resolve-domains-and-accept-dns-returned-order
        resolve-domains-and-prefer-ipv4 resolve-domains-and-prefer-ipv6
        resolve-domains-and-use-only-ipv4 resolve-domains-and-use-only-ipv6
        resolve-domains-with-core-settings)
      string(REPLACE "-" "_" strategy_label "${strategy}")
      add_waterwall_vmess_client_interop("local_${strategy_label}"
        --peer waterwall --target domain --destination fixed --dns "${strategy}")
    endforeach()
    foreach(scenario IN ITEMS wrong_uuid split tamper early_close silent)
      add_waterwall_vmess_client_interop("local_${scenario}"
        --peer waterwall --scenario "${scenario}" --workers 2)
    endforeach()
  endif()
  if("database" IN_LIST vmess_client_peers)
    foreach(scenario IN ITEMS disabled expired quota)
      add_waterwall_vmess_client_interop("database_${scenario}"
        --peer waterwall --auth database --scenario "${scenario}" --workers 2)
    endforeach()
    if(TARGET APIServer)
      add_waterwall_vmess_client_interop(database_rotation
        --peer waterwall --auth database --scenario rotation --workers 2)
    endif()
  endif()
endif()
