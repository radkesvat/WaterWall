add_test(
  NAME waterwall.enet_vendor_source_policy
  COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/enet_vendor_source_policy_test.py"
)
set_tests_properties(waterwall.enet_vendor_source_policy PROPERTIES
  TIMEOUT 30 LABELS "unit;policy;source-policy;tunnels;enet;vendor")
