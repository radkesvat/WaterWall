# Direct component coverage uses the same deterministic delayed-task and buffer
# ownership fixtures as the server-level fallback suites.
if(LINUX AND TARGET FallbackReplay)
  waterwall_add_native_executable(fallback_replay_test SUPPORT
    SOURCES
      ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/fallback/fallback_replay_test.c
      ${WATERWALL_LINE_FAILURE_WW_SOURCES}
    LIBRARIES FallbackReplay ww)
  target_link_options(fallback_replay_test PRIVATE
    ${WATERWALL_LINE_FAILURE_WRAPS}
    "-Wl,--wrap=lineScheduleDelayedTask")
  add_dependencies(waterwall_unit_tests fallback_replay_test)
  add_waterwall_unit_test(
    waterwall.fallback_replay_unit
    fallback_replay_test
    "unit;tunnels;fallback;reentrant;scheduling;lifetime;ownership;splice")
endif()
