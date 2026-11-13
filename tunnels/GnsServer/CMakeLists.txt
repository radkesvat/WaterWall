add_library(GnsServer STATIC
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
target_include_directories(GnsServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(GnsServer PRIVATE ww GnsCommon)
if(NOT APPLE)
  target_precompile_headers(GnsServer REUSE_FROM ww)
endif()
