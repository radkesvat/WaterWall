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
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/common/line_state.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/downstream/payload.c)
  target_link_libraries(encryptionclient_crypto_failure_test PRIVATE ww_test_support)
  target_compile_definitions(encryptionclient_crypto_failure_test PRIVATE TEST_ENCRYPTION_CLIENT=1)
  target_include_directories(encryptionclient_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/include
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionClient/include/EncryptionClient
  )
  target_link_libraries(encryptionclient_crypto_failure_test PRIVATE ww)
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
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/common/helpers.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/common/line_state.c
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/upstream/payload.c)
  target_link_libraries(encryptionserver_crypto_failure_test PRIVATE ww_test_support)
  target_compile_definitions(encryptionserver_crypto_failure_test PRIVATE TEST_ENCRYPTION_SERVER=1)
  target_include_directories(encryptionserver_crypto_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/include
    ${CMAKE_SOURCE_DIR}/tunnels/EncryptionServer/include/EncryptionServer
  )
  target_link_libraries(encryptionserver_crypto_failure_test PRIVATE ww)
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

