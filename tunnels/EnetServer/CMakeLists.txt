add_library(EnetServer STATIC
  instance/create.c
  instance/node.c
  common/output.c
  upstream/init.c
  upstream/est.c
  upstream/payload.c
  upstream/pause.c
  upstream/resume.c
  upstream/fin.c
  downstream/est.c
  downstream/payload.c
  downstream/pause.c
  downstream/resume.c
  downstream/fin.c
)
target_include_directories(EnetServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(EnetServer PRIVATE ww EnetTunnelCommon)
if(NOT APPLE)
  target_precompile_headers(EnetServer REUSE_FROM ww)
endif()
