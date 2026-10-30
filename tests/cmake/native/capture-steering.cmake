if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
  waterwall_add_native_executable(capture_linux_steering_test SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/devices/capture_linux_steering_test.c
    ${CMAKE_SOURCE_DIR}/ww/devices/capture/capture_linux_steering.c
    ${CMAKE_SOURCE_DIR}/ww/devices/device_flow_hash.c)
  target_link_libraries(capture_linux_steering_test PRIVATE waterwall_runtime_options)
  add_dependencies(waterwall_unit_tests capture_linux_steering_test)
  add_waterwall_unit_test(waterwall.capture_linux_steering_unit capture_linux_steering_test
    "unit;net;device;capture;multiqueue")
endif()
