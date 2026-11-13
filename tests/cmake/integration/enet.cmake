add_test(
  NAME waterwall.enet_vendor_source_policy
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/enet_vendor_source_policy_test.py"
)
set_tests_properties(waterwall.enet_vendor_source_policy PROPERTIES
  TIMEOUT 30 LABELS "unit;policy;source-policy;tunnels;enet;vendor")

# Both peers run in one WaterWall process and are joined directly, so no socket is bound.
if(TARGET EnetClient AND TARGET EnetServer AND
   CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(enet_case IN ITEMS enet_roundtrip enet_disturber_roundtrip)
    add_waterwall_integration_test(waterwall.${enet_case} ${enet_case})
    add_waterwall_test_labels(waterwall.${enet_case} "enet")
  endforeach()
endif()
