add_library(TlsRecordShapingCommon STATIC
  src/config.c
  src/sampler.c
  src/output_queue.c
)

target_include_directories(TlsRecordShapingCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(TlsRecordShapingCommon PUBLIC ww)

if(NOT APPLE)
  target_precompile_headers(TlsRecordShapingCommon REUSE_FROM ww)
endif()
