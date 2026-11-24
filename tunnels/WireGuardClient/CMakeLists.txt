add_library(WireGuardClient STATIC
  instance/create.c
  instance/node.c
  instance/start.c
  instance/stop.c
  instance/destroy.c
  common/carrier.c
  common/output.c
  common/pending.c
  upstream/payload.c
  upstream/fin.c
  downstream/payload.c
  downstream/fin.c
  downstream/pause.c
  downstream/resume.c
)
target_include_directories(WireGuardClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(WireGuardClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/WireGuardClient)
target_link_libraries(WireGuardClient PUBLIC WireGuardCommon)
if(NOT APPLE)
  target_precompile_headers(WireGuardClient REUSE_FROM ww)
endif()
