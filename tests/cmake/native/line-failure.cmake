# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET ww)
  waterwall_add_native_executable(capture_windows_checksum_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_windows_checksum_test.c)
  target_link_libraries(capture_windows_checksum_test PRIVATE ww_test_support)
  target_link_libraries(capture_windows_checksum_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests capture_windows_checksum_test)
  add_waterwall_unit_test(
    waterwall.capture_windows_checksum_unit
    capture_windows_checksum_test
    "unit;net;capture;checksum"
  )

  waterwall_add_native_executable(device_checksum_validity_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/device_checksum_validity_test.c)
  target_link_libraries(device_checksum_validity_test PRIVATE ww_test_support)
  target_link_libraries(device_checksum_validity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests device_checksum_validity_test)
  add_waterwall_unit_test(
    waterwall.device_checksum_validity_unit
    device_checksum_validity_test
    "unit;net;devices;checksum"
  )

  waterwall_add_native_executable(device_frag_affinity_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/device_frag_affinity_test.c)
  target_link_libraries(device_frag_affinity_test PRIVATE ww_test_support)
  target_link_libraries(device_frag_affinity_test PRIVATE ww)
  add_dependencies(waterwall_unit_tests device_frag_affinity_test)
  add_waterwall_unit_test(
    waterwall.device_frag_affinity_unit
    device_frag_affinity_test
    "unit;net;devices;fragment;affinity;lifetime"
  )
endif()

