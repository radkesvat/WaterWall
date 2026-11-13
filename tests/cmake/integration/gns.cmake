# Both peers run in one WaterWall process and are joined directly, so no socket is bound.
if(TARGET GnsClient AND TARGET GnsServer AND
   CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(gns_case IN ITEMS gns_roundtrip gns_disturber_roundtrip)
    add_waterwall_integration_test(waterwall.${gns_case} ${gns_case})
    add_waterwall_test_labels(waterwall.${gns_case} "gns")
  endforeach()
endif()
