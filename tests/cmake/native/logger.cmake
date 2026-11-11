# File diagnostics use native Linux filesystem failures without network access.
if(LINUX AND TARGET LoggerTunnel)
  waterwall_add_native_executable(logger_file_diagnostics_test SUPPORT
    SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/logger/logger_file_diagnostics_test.c
    LIBRARIES LoggerTunnel ww)
  add_waterwall_unit_test(waterwall.logger_file_diagnostics_unit logger_file_diagnostics_test
    "unit;tunnels;logger;diagnostics")
endif()
