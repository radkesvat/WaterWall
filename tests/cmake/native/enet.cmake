# ENet units are pure C: no socket, worker runtime or wall clock. The driver
# tests run over the in-memory link in tests/unittests/tunnels/enet/enet_sim.h.
if(TARGET EnetCommon)
  waterwall_add_native_executable(enet_platform_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/enet/enet_platform_test.c
    INCLUDES ${CMAKE_SOURCE_DIR}/tunnels/Internals/EnetCommon/src
    LIBRARIES EnetCommon ww)
  set_target_properties(enet_platform_test PROPERTIES DISABLE_PRECOMPILE_HEADERS ON UNITY_BUILD OFF)
  add_waterwall_unit_test(waterwall.enet_platform_unit enet_platform_test "unit;tunnels;enet;platform")
endif()
