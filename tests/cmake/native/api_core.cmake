# Core API remains independent of the optional APIServer and authentication provider.
waterwall_add_native_executable(api_registry_resolver_test SUPPORT SOURCES
  ${WATERWALL_UNIT_SOURCE_ROOT}/core/api_registry_resolver_test.c)
target_link_libraries(api_registry_resolver_test PRIVATE ww_test_support ww)
add_dependencies(waterwall_unit_tests api_registry_resolver_test)
add_waterwall_unit_test(waterwall.api_registry_resolver_unit api_registry_resolver_test
  "unit;api;node-manager;startup")

waterwall_add_native_executable(api_dispatcher_test SUPPORT SOURCES
  ${WATERWALL_UNIT_SOURCE_ROOT}/core/api_dispatcher_test.c)
target_link_libraries(api_dispatcher_test PRIVATE ww_test_support ww)
target_link_options(api_dispatcher_test PRIVATE "-Wl,--wrap=sendWorkerMessageForceQueueWithCleanup"
  "-Wl,--wrap=memoryAllocate" "-Wl,--wrap=memoryFree")
add_dependencies(waterwall_unit_tests api_dispatcher_test)
add_waterwall_unit_test(waterwall.api_dispatcher_unit api_dispatcher_test
  "unit;api;worker-message;ownership;shutdown;tsan")

waterwall_add_native_executable(api_config_strings_test SUPPORT SOURCES
  ${WATERWALL_UNIT_SOURCE_ROOT}/core/api_config_strings_test.c)
target_link_libraries(api_config_strings_test PRIVATE ww_test_support ww)
add_dependencies(waterwall_unit_tests api_config_strings_test)
add_waterwall_unit_test(waterwall.api_config_strings_unit api_config_strings_test
  "unit;api;configuration;security")

waterwall_add_native_executable(api_json_threads_test SUPPORT SOURCES
  ${WATERWALL_UNIT_SOURCE_ROOT}/core/api_json_threads_test.c)
target_link_libraries(api_json_threads_test PRIVATE ww_test_support ww)
add_dependencies(waterwall_unit_tests api_json_threads_test)
add_waterwall_unit_test(waterwall.api_json_threads_unit api_json_threads_test
  "unit;api;json;concurrency;tsan")
