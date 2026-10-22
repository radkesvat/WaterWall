add_library(QuicClient STATIC
  instance/create.c
  instance/node.c
  instance/api.c
  instance/stop.c
  instance/destroy.c
  common/output.c
  upstream/init.c
  upstream/payload.c
  upstream/fin.c
  upstream/pause.c
  upstream/resume.c
  downstream/est.c
  downstream/payload.c
  downstream/fin.c
  downstream/pause.c
  downstream/resume.c
)
target_include_directories(QuicClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(QuicClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/QuicClient)
target_link_libraries(QuicClient PRIVATE ww QuicCommon)
if(NOT APPLE)
  target_precompile_headers(QuicClient REUSE_FROM ww)
endif()
