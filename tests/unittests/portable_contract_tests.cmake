include_guard(GLOBAL)

if(NOT WW_BUILD_UNIT_TESTS OR NOT BUILD_TESTING)
  return()
endif()

set(_waterwall_portable_unit_dir "${CMAKE_CURRENT_LIST_DIR}")
set(_waterwall_portable_unit_runner "${CMAKE_CURRENT_LIST_DIR}/run_unit_test.cmake")

# ww's PCH is reused by tunnel targets. Every native-unit consumer must see the
# same unit-only seams before any portable target compiles.
target_compile_definitions(ww PUBLIC WW_IDLE_TABLE_TEST_SEAM=1 WW_SYSINFO_TEST_SEAM=1)

function(_waterwall_register_portable_contract test_name target_name labels)
  add_test(
    NAME ${test_name}
    COMMAND
      "${CMAKE_COMMAND}"
      "-DUNIT_TEST_TARGET=${target_name}"
      "-DUNIT_TEST_CONFIG=$<CONFIG>"
      "-DUNIT_TEST_EXECUTABLE=$<TARGET_FILE:${target_name}>"
      "-DUNIT_TEST_BUILD_DIR=${CMAKE_BINARY_DIR}"
      -P "${_waterwall_portable_unit_runner}"
  )
  set_tests_properties(${test_name} PROPERTIES
    TIMEOUT 120
    LABELS "${labels}"
    RESOURCE_LOCK waterwall_unit_test_build
  )

  if(TARGET waterwall_unit_tests)
    add_dependencies(waterwall_unit_tests ${target_name})
  else()
    waterwall_register_platform_native_unit(${test_name} ${target_name} "${labels}")
  endif()
endfunction()

add_executable(idle_table_contract_test EXCLUDE_FROM_ALL
  "${_waterwall_portable_unit_dir}/idle_table_contract_test.c")
target_link_libraries(idle_table_contract_test PRIVATE ww)
_waterwall_register_portable_contract(
  waterwall.idle_table_contract_unit
  idle_table_contract_test
  "unit;idle-table;local-idle;contract;lifetime;tsan"
)

add_executable(system_memory_snapshot_test EXCLUDE_FROM_ALL
  "${_waterwall_portable_unit_dir}/system_memory_snapshot_test.c")
target_link_libraries(system_memory_snapshot_test PRIVATE ww)
_waterwall_register_portable_contract(
  waterwall.system_memory_snapshot_unit
  system_memory_snapshot_test
  "unit;base;system-memory;sampler;concurrency;tsan"
)

if(TARGET MuxServer AND TARGET MuxClient)
  add_executable(muxserver_admission_limit_test EXCLUDE_FROM_ALL
    "${_waterwall_portable_unit_dir}/muxserver_admission_limit_test.c")
  target_include_directories(muxserver_admission_limit_test PRIVATE
    "${CMAKE_SOURCE_DIR}/tunnels/MuxServer/include"
    "${CMAKE_SOURCE_DIR}/tunnels/MuxClient/include"
    "${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include"
  )
  target_link_libraries(muxserver_admission_limit_test PRIVATE MuxServer MuxClient ww)
  _waterwall_register_portable_contract(
    waterwall.muxserver_admission_limit_unit
    muxserver_admission_limit_test
    "unit;tunnels;muxserver;muxclient;admission;cid;concurrency;tsan"
  )
endif()

if(TARGET MuxClient)
  add_executable(muxclient_cid_index_test EXCLUDE_FROM_ALL
    "${_waterwall_portable_unit_dir}/muxclient_cid_index_test.c")
  target_include_directories(muxclient_cid_index_test PRIVATE
    "${CMAKE_SOURCE_DIR}/tunnels/MuxClient/include"
    "${CMAKE_SOURCE_DIR}/tunnels/Internals/MuxCommon/include"
  )
  target_link_libraries(muxclient_cid_index_test PRIVATE MuxClient ww)
  _waterwall_register_portable_contract(
    waterwall.muxclient_cid_index_unit
    muxclient_cid_index_test
    "unit;tunnels;muxclient;cid;scalability"
  )
endif()
