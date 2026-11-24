# Explicit native registrations.
if(TARGET WireGuardCommon)
  waterwall_add_native_executable(wireguard_transport_buffer_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguard_transport_buffer_test.c)
  target_link_libraries(wireguard_transport_buffer_test PRIVATE WireGuardCommon ww)
  add_dependencies(waterwall_unit_tests wireguard_transport_buffer_test)
  add_waterwall_unit_test(waterwall.wireguard_transport_buffer_unit wireguard_transport_buffer_test "unit;tunnels;wireguard;transport;buffer;security")
endif()

if(LINUX AND TARGET WireGuardServer)
  waterwall_add_native_executable(wireguard_server_endpoint_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguard_server_endpoint_test.c)
  target_link_libraries(wireguard_server_endpoint_test PRIVATE ww_test_support WireGuardCommon AuthenticationClient UserController PacketsToConnection)
  target_include_directories(wireguard_server_endpoint_test PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/WireGuardServer/include)
  target_link_options(wireguard_server_endpoint_test PRIVATE
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  add_dependencies(waterwall_unit_tests wireguard_server_endpoint_test)
  add_waterwall_unit_test(waterwall.wireguard_server_endpoint_unit wireguard_server_endpoint_test
    "unit;tunnels;wireguard;endpoint;security")
endif()
if(LINUX AND TARGET WireGuardCommon)
  waterwall_add_native_executable(wireguard_crypto_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/wireguard_crypto_failure_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/src/wireguard.c)
  target_link_libraries(wireguard_crypto_failure_test PRIVATE ww_test_support WireGuardCommon)
  target_include_directories(wireguard_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/include
  )
  target_link_libraries(wireguard_crypto_failure_test PRIVATE ww)
  target_link_options(wireguard_crypto_failure_test PRIVATE
    "-Wl,-u,wCryptoBlake2sInit"
    "-Wl,-u,wCryptoBlake2s"
    "-Wl,-u,wCryptoX25519"
    "-Wl,-u,wCryptoChaCha20Poly1305Encrypt"
    "-Wl,--wrap=wCryptoBlake2sInit"
    "-Wl,--wrap=wCryptoBlake2s"
    "-Wl,--wrap=wCryptoX25519"
    "-Wl,--wrap=wCryptoChaCha20Poly1305Encrypt"
    "-Wl,--wrap=wwBase64Decode"
  )
  add_dependencies(waterwall_unit_tests wireguard_crypto_failure_test)

  add_waterwall_unit_test(
    waterwall.wireguard_crypto_failure_unit
    wireguard_crypto_failure_test
    "unit;tunnels;wireguard;crypto;failure"
  )
endif()

if(LINUX AND TARGET EncryptionClient)
  waterwall_add_native_executable(encryptionclient_crypto_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/encryption_crypto_failure_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/EncryptionCommon/src/record.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/common/line_state.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/downstream/payload.c)
  target_link_libraries(encryptionclient_crypto_failure_test PRIVATE ww_test_support)
  target_compile_definitions(encryptionclient_crypto_failure_test PRIVATE TEST_ENCRYPTION_CLIENT=1)
  target_include_directories(encryptionclient_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/include
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/include/EncryptionClient
  )
  target_link_libraries(encryptionclient_crypto_failure_test PRIVATE EncryptionCommon ww)
  target_link_options(encryptionclient_crypto_failure_test PRIVATE
    "-Wl,--wrap=wCryptoChaCha20Poly1305Decrypt"
  )
  add_dependencies(waterwall_unit_tests encryptionclient_crypto_failure_test)

  add_waterwall_unit_test(
    waterwall.encryptionclient_crypto_failure_unit
    encryptionclient_crypto_failure_test
    "unit;tunnels;encryptionclient;crypto;failure"
  )
endif()

if(LINUX AND TARGET EncryptionServer)
  waterwall_add_native_executable(encryptionserver_crypto_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/encryption_crypto_failure_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/EncryptionCommon/src/record.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/common/line_state.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/upstream/payload.c)
  target_link_libraries(encryptionserver_crypto_failure_test PRIVATE ww_test_support)
  target_compile_definitions(encryptionserver_crypto_failure_test PRIVATE TEST_ENCRYPTION_SERVER=1)
  target_include_directories(encryptionserver_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/include/EncryptionServer
  )
  target_link_libraries(encryptionserver_crypto_failure_test PRIVATE EncryptionCommon ww)
  target_link_options(encryptionserver_crypto_failure_test PRIVATE
    "-Wl,--wrap=wCryptoChaCha20Poly1305Decrypt"
  )
  add_dependencies(waterwall_unit_tests encryptionserver_crypto_failure_test)

  add_waterwall_unit_test(
    waterwall.encryptionserver_crypto_failure_unit
    encryptionserver_crypto_failure_test
    "unit;tunnels;encryptionserver;crypto;failure"
  )
endif()

if(LINUX AND TARGET EncryptionCommon)
  waterwall_add_native_executable(encryption_packet_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/encryption_packet_test.c
    LIBRARIES EncryptionCommon ww)
  add_dependencies(waterwall_unit_tests encryption_packet_test)
  add_waterwall_unit_test(waterwall.encryption_packet_unit encryption_packet_test
    "unit;tunnels;encryption;crypto;packet")

  if(TARGET EncryptionClient AND TARGET EncryptionServer)
    waterwall_add_native_executable(encryption_packet_nodes_test SUPPORT
      SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/encryption_packet_nodes_test.c
      LIBRARIES EncryptionClient EncryptionServer EncryptionCommon ww)
    target_link_options(encryption_packet_nodes_test PRIVATE
      "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
      "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetBestFit"
      "-Wl,--wrap=bufferpoolTryGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
      "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
    add_dependencies(waterwall_unit_tests encryption_packet_nodes_test)
    add_waterwall_unit_test(waterwall.encryption_packet_nodes_unit encryption_packet_nodes_test
      "unit;tunnels;encryption;crypto;packet")
  endif()

  # Compile the wrapped callers outside ww/EncryptionCommon's Release IPO units,
  # so the existing pool ledger sees both record and BufferStream ownership.
  set(encryption_test_sources
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/EncryptionCommon/src/record.c
    ${CMAKE_SOURCE_DIR}/ww/bufio/buffer_stream.c)
  set(encryption_test_wraps
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetBestFit"
    "-Wl,--wrap=bufferpoolTryGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  waterwall_add_native_executable(encryption_record_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/encryption_record_test.c ${encryption_test_sources}
    LIBRARIES EncryptionCommon ww)
  target_link_options(encryption_record_test PRIVATE ${encryption_test_wraps} "-Wl,--wrap=sbufAppendMerge")
  add_dependencies(waterwall_unit_tests encryption_record_test)
  add_waterwall_unit_test(waterwall.encryption_record_unit encryption_record_test
    "unit;tunnels;encryption;crypto;framing")

  foreach(encryption_role Client Server)
    if(TARGET Encryption${encryption_role})
      string(TOLOWER "${encryption_role}" encryption_role_lower)
      string(TOUPPER "${encryption_role}" encryption_role_upper)
      set(encryption_test "encryption${encryption_role_lower}_reentrant_output_test")
      set(encryption_dir "${CMAKE_SOURCE_DIR}/tunnels/Encryption${encryption_role}")
      waterwall_add_native_executable(${encryption_test} SUPPORT
        SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/encryption_reentrant_output_test.c
          ${encryption_test_sources}
          ${encryption_dir}/common/helpers.c ${encryption_dir}/common/line_state.c
          ${encryption_dir}/upstream/init.c
          ${encryption_dir}/upstream/payload.c ${encryption_dir}/downstream/payload.c
          ${encryption_dir}/upstream/fin.c ${encryption_dir}/downstream/fin.c
        LIBRARIES EncryptionCommon ww)
      target_compile_definitions(${encryption_test} PRIVATE TEST_ENCRYPTION_${encryption_role_upper}=1)
      target_include_directories(${encryption_test} PRIVATE
        ${encryption_dir}/include ${encryption_dir}/include/Encryption${encryption_role})
      target_link_options(${encryption_test} PRIVATE ${encryption_test_wraps})
      add_dependencies(waterwall_unit_tests ${encryption_test})
      add_waterwall_unit_test(waterwall.encryption${encryption_role_lower}_reentrant_output_unit ${encryption_test}
        "unit;tunnels;encryption;crypto;lifetime;reentrant")
    endif()
  endforeach()
endif()


if(LINUX AND TARGET WireGuardClient)
  waterwall_add_native_executable(wireguard_client_carrier_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguard_client_carrier_test.c)
  target_link_libraries(wireguard_client_carrier_test PRIVATE ww_test_support WireGuardClient)
  target_link_options(wireguard_client_carrier_test PRIVATE
    "-Wl,--wrap=getTickMS" "-Wl,--wrap=wireguardCommonReceiveOnCarrier"
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  add_dependencies(waterwall_unit_tests wireguard_client_carrier_test)
  add_waterwall_unit_test(waterwall.wireguard_client_carrier_unit wireguard_client_carrier_test
    "unit;tunnels;wireguard;carrier;lifetime")
endif()

if(LINUX AND TARGET WireGuardCommon)
  # Keep the controlled-clock call sites outside the production Release IPO
  # archive, so --wrap=getTickMS observes the real protocol implementation.
  waterwall_add_native_executable(wireguard_protocol_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguard_protocol_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/src/wireguard.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/src/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/src/device_loop.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/src/input.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/src/output.c
    ${CMAKE_SOURCE_DIR}/tunnels/Internals/WireGuardCommon/src/settings.c)
  target_link_libraries(wireguard_protocol_test PRIVATE ww_test_support WireGuardCommon)
  set_target_properties(wireguard_protocol_test PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF
    INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF)
  target_link_options(wireguard_protocol_test PRIVATE
    "-Wl,--wrap=getTickMS" "-Wl,--wrap=isSystemUnderLoad"
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  add_dependencies(waterwall_unit_tests wireguard_protocol_test)
  add_waterwall_unit_test(waterwall.wireguard_protocol_unit wireguard_protocol_test "unit;tunnels;wireguard;protocol;security")
endif()

if(LINUX AND TARGET WireGuardServer)
  waterwall_add_native_executable(wireguard_user_binding_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguard_user_binding_test.c)
  target_link_libraries(wireguard_user_binding_test PRIVATE ww_test_support WireGuardCommon AuthenticationClient UserController PacketsToConnection)
  target_include_directories(wireguard_user_binding_test PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/WireGuardServer/include)
  target_link_options(wireguard_user_binding_test PRIVATE
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  target_link_options(wireguard_user_binding_test PRIVATE "-Wl,--wrap=getTickMS" "-Wl,--wrap=nodemanagerGetConfigNodeByName"
    "-Wl,--wrap=authenticationclientRecoverControlLine" "-Wl,--wrap=authenticationclientResumeSync")
  add_dependencies(waterwall_unit_tests wireguard_user_binding_test)
  add_waterwall_unit_test(waterwall.wireguard_user_binding_unit wireguard_user_binding_test
    "unit;tunnels;wireguard;authentication;usercontroller;ip;identity")

  waterwall_add_native_executable(wireguard_server_lifecycle_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguard_server_lifecycle_test.c
    ${CMAKE_SOURCE_DIR}/ww/lwip/engine_runtime.c)
  target_link_libraries(wireguard_server_lifecycle_test PRIVATE ptc_engine_test ww_lwip_engine_test WireGuardCommon AuthenticationClient UserController)
  target_include_directories(wireguard_server_lifecycle_test PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/WireGuardServer/include)
  target_link_options(wireguard_server_lifecycle_test PRIVATE
    "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
    "-Wl,--wrap=tunnelDestroy"
    "-Wl,--wrap=tunnelOwnedChildDestroy"
    "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
    "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
    "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
    "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
    "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  add_dependencies(waterwall_unit_tests wireguard_server_lifecycle_test)
  add_waterwall_unit_test(waterwall.wireguard_server_lifecycle_unit wireguard_server_lifecycle_test
    "unit;tunnels;wireguard;lifecycle;shutdown;failure;workers")
endif()

if(LINUX AND TARGET WireGuardServer)
  foreach(suite retirement capacity)
    set(target wireguard_server_${suite}_test)
    waterwall_add_native_executable(${target} SUPPORT SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/${target}.c)
    target_link_libraries(${target} PRIVATE ww_test_support ptc_engine_test ww_lwip_engine_test WireGuardCommon AuthenticationClient UserController)
    target_include_directories(${target} PRIVATE ${CMAKE_SOURCE_DIR}/tunnels/WireGuardServer/include)
    target_link_options(${target} PRIVATE
      "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup" "-Wl,--wrap=tunnelDestroy" "-Wl,--wrap=tunnelOwnedChildDestroy"
      "-Wl,--wrap=abortProgramNow" "-Wl,--wrap=requestProgramShutdown"
      "-Wl,--wrap=bufferpoolGetLargeBuffer" "-Wl,--wrap=bufferpoolTryGetBestFit"
      "-Wl,--wrap=bufferpoolGetBestFit" "-Wl,--wrap=bufferpoolGetSpliceBuffer"
      "-Wl,--wrap=bufferpoolGetMediumBuffer" "-Wl,--wrap=bufferpoolGetSmallBuffer"
      "-Wl,--wrap=bufferpoolReuseBuffer" "-Wl,--wrap=sbufDestroy")
  endforeach()
  target_link_options(wireguard_server_retirement_test PRIVATE "-Wl,--wrap=ptcRetireSourceRange")
  target_link_options(wireguard_server_capacity_test PRIVATE "-Wl,--wrap=getTickMS" "-Wl,--wrap=getHRTimeUs")
  add_waterwall_unit_test(waterwall.wireguard_server_retirement_unit wireguard_server_retirement_test
    "unit;tunnels;wireguard;retirement;workers;authentication")
  # The portable software crypto backend also completes all 5,000 handshakes under sanitizers.
  add_waterwall_unit_test(waterwall.wireguard_server_capacity_unit wireguard_server_capacity_test
    "unit;tunnels;wireguard;capacity;workers;authentication" 300)
endif()
