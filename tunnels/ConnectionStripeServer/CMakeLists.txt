add_library(ConnectionStripeServer STATIC
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
target_include_directories(ConnectionStripeServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(ConnectionStripeServer PRIVATE ww ConnectionStripeCommon)
if(NOT APPLE)
  target_precompile_headers(ConnectionStripeServer REUSE_FROM ww)
endif()
