if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
  waterwall_add_native_executable(device_kernel_queue_tuning_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/devices/device_kernel_queue_tuning_test.c)
  target_link_libraries(device_kernel_queue_tuning_test PRIVATE waterwall_runtime_options)
  add_dependencies(waterwall_unit_tests device_kernel_queue_tuning_test)
  add_waterwall_unit_test(waterwall.device_kernel_queue_tuning_unit device_kernel_queue_tuning_test
    "unit;net;device;configuration")

  waterwall_add_native_executable(tun_linux_queues_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/devices/tun_linux_queues_test.c
    ${CMAKE_SOURCE_DIR}/ww/devices/device_flow_hash.c
    ${CMAKE_SOURCE_DIR}/ww/devices/tun/tun_linux_queues.c)
  target_link_libraries(tun_linux_queues_test PRIVATE waterwall_runtime_options)
  target_link_options(tun_linux_queues_test PRIVATE
    "-Wl,--wrap=open" "-Wl,--wrap=close" "-Wl,--wrap=ioctl" "-Wl,--wrap=syscall")
  add_dependencies(waterwall_unit_tests tun_linux_queues_test)
  add_waterwall_unit_test(waterwall.tun_linux_queues_unit tun_linux_queues_test
    "unit;net;device;tun;multiqueue")
  add_test(NAME waterwall.tun_linux_steering_kernel
    COMMAND tun_linux_queues_test --kernel)
  set_tests_properties(waterwall.tun_linux_steering_kernel PROPERTIES
    TIMEOUT 20 SKIP_RETURN_CODE 77 LABELS "unit;net;device;tun;multiqueue;privileged")
endif()
