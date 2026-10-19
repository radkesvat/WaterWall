# UserController framing uses real construction, Init and late promotion paths.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET UserController AND TARGET AuthenticationClient)
  waterwall_add_native_executable(usercontroller_payload_mode_test SUPPORT SOURCES
    ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/usercontroller/usercontroller_payload_mode_test.c)
  target_link_libraries(usercontroller_payload_mode_test PRIVATE UserController AuthenticationClient ww)
  target_link_options(usercontroller_payload_mode_test PRIVATE
    "-Wl,--wrap=nodemanagerGetConfigNodeByName"
    "-Wl,--wrap=authenticationclientUserTryAdmitConnection"
    "-Wl,--wrap=authenticationclientUserReleaseConnection")
  add_waterwall_unit_test(waterwall.usercontroller_payload_mode_unit usercontroller_payload_mode_test
    "unit;tunnels;usercontroller;framing;configuration;line")
endif()
