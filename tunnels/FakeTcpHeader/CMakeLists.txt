add_library(FakeTcpHeader STATIC
  instance/create.c
  instance/destroy.c
  instance/node.c
  common/wire.c
  common/payload.c
  upstream/payload.c
  downstream/payload.c
)
target_include_directories(FakeTcpHeader PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(FakeTcpHeader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/FakeTcpHeader)
target_link_libraries(FakeTcpHeader PRIVATE ww)
if(NOT APPLE)
  target_precompile_headers(FakeTcpHeader REUSE_FROM ww)
endif()
