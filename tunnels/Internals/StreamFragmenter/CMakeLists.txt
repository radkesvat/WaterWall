add_library(StreamFragmenter STATIC
    instance/create.c
    instance/node.c
    instance/api.c
    common/config.c
    common/line_state.c
    common/flow.c
    common/tls_hello.c
    upstream/init.c
    upstream/payload.c
    upstream/fin.c
    downstream/fin.c
    downstream/est.c
    downstream/pause.c
    downstream/resume.c
)
target_include_directories(StreamFragmenter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(StreamFragmenter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/StreamFragmenter)
target_link_libraries(StreamFragmenter PRIVATE ww)
if(NOT APPLE)
    target_precompile_headers(StreamFragmenter REUSE_FROM ww)
endif()
