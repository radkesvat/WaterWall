# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET WireGuardDevice)
  waterwall_add_native_executable(wireguarddevice_layer_resolution_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguarddevice_layer_resolution_test.c)
  target_include_directories(wireguarddevice_layer_resolution_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice
  )
  target_link_libraries(wireguarddevice_layer_resolution_test PRIVATE WireGuardDevice ww)
  add_dependencies(waterwall_unit_tests wireguarddevice_layer_resolution_test)

  add_waterwall_unit_test(
    waterwall.wireguarddevice_layer_resolution_unit
    wireguarddevice_layer_resolution_test
    "unit;tunnels;wireguard;layer;topology"
  )

  waterwall_add_native_executable(wireguarddevice_transport_buffer_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguarddevice_transport_buffer_test.c)
  target_include_directories(wireguarddevice_transport_buffer_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice/include/WireGuardDevice
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice
  )
  target_link_libraries(wireguarddevice_transport_buffer_test PRIVATE WireGuardDevice ww)
  add_dependencies(waterwall_unit_tests wireguarddevice_transport_buffer_test)

  add_waterwall_unit_test(
    waterwall.wireguarddevice_transport_buffer_unit
    wireguarddevice_transport_buffer_test
    "unit;tunnels;wireguard;transport;buffer;security"
  )
endif()

if(LINUX AND TARGET WireGuardDevice)
  waterwall_add_native_executable(wireguarddevice_controller_mode_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/wireguard/wireguarddevice_controller_mode_test.c)
  target_include_directories(wireguarddevice_controller_mode_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice)
  target_link_libraries(wireguarddevice_controller_mode_test PRIVATE WireGuardDevice UserController AuthenticationClient ww)
  target_link_options(wireguarddevice_controller_mode_test PRIVATE
    "-Wl,--wrap=nodemanagerGetConfigNodeByName")
  add_dependencies(waterwall_unit_tests wireguarddevice_controller_mode_test)
  add_waterwall_unit_test(waterwall.wireguarddevice_controller_mode_unit wireguarddevice_controller_mode_test
    "unit;tunnels;wireguard;usercontroller;framing;line")

  waterwall_add_native_executable(wireguard_crypto_failure_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/crypto/wireguard_crypto_failure_test.c
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice/common/wireguard.c)
  target_link_libraries(wireguard_crypto_failure_test PRIVATE ww_test_support)
  target_include_directories(wireguard_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice/include/WireGuardDevice
    ${CMAKE_SOURCE_DIR}/tunnels/WireGuardDevice
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

