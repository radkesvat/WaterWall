add_library(SniffRouter STATIC
    common/classifier.c
    common/line_state.c
    downstream/est.c
    downstream/fin.c
    downstream/init.c
    downstream/pause.c
    downstream/payload.c
    downstream/resume.c
    instance/api.c
    instance/chain.c
    instance/create.c
    instance/destroy.c
    instance/index.c
    instance/node.c
    instance/prepair.c
    instance/start.c
    upstream/est.c
    upstream/fin.c
    upstream/init.c
    upstream/pause.c
    upstream/payload.c
    upstream/resume.c
)

target_include_directories(SniffRouter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(SniffRouter ww)
if(NOT APPLE)
    target_precompile_headers(SniffRouter REUSE_FROM ww)
endif()
