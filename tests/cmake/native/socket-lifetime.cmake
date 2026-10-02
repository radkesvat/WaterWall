# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
waterwall_add_native_executable(socket_manager_lifetime_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/devices/socket_manager/socket_manager_lifetime_test.c
  ${CMAKE_SOURCE_DIR}/ww/managers/socket_manager.c)
  target_link_libraries(socket_manager_lifetime_test PRIVATE ww_test_support)
set_target_properties(socket_manager_lifetime_test PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
target_compile_definitions(socket_manager_lifetime_test PRIVATE
  WW_SYNC_INIT_TEST_SEAM=1
  WW_SOCKET_MANAGER_CONSTRUCTOR_TEST_SEAM=1
  WW_SOCKET_MANAGER_REGISTRATION_TEST_SEAM=1
)
target_include_directories(socket_manager_lifetime_test PRIVATE
  ${CMAKE_SOURCE_DIR}/ww/managers
)
target_link_libraries(socket_manager_lifetime_test PRIVATE ww)
add_dependencies(waterwall_unit_tests socket_manager_lifetime_test)
add_waterwall_unit_test(
  waterwall.socket_manager_lifetime_unit
  socket_manager_lifetime_test
  "unit;socket-manager;synchronization;lifecycle;failure;linux"
)

# Category-B orderly-shutdown failure injection. One executable per tunnel so
# that only one tunnel's structure.h is ever visible in a translation unit.
# Direct public-wtimer callers wrap wtimerAdd. Scheduler-backed delayed callers
# exercise admission closure; timer allocation failure is fatal.
