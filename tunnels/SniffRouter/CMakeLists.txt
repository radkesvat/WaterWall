add_library(SniffRouter STATIC
    common/classifier.c
    common/line_state.c
    common/routes.c
    downstream/fin.c
    instance/api.c
    instance/chain.c
    instance/create.c
    instance/destroy.c
    instance/node.c
    upstream/est.c
    upstream/fin.c
    upstream/init.c
    upstream/pause.c
    upstream/payload.c
    upstream/resume.c
)

target_include_directories(SniffRouter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../ReverseClient/include
)

target_include_directories(SniffRouter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(SniffRouter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/SniffRouter)

target_link_libraries(SniffRouter PRIVATE ww ReverseClient)
if(NOT APPLE)
    target_precompile_headers(SniffRouter REUSE_FROM ww)
endif()
