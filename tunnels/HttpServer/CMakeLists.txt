add_library(HttpServer STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    common/transport.c
                    common/split.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
  
)

target_include_directories(HttpServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(HttpServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpServer)

target_link_libraries(HttpServer ww)

if(NOT TARGET http_def)
    add_library(http_def OBJECT
        common/http_def.c
    )
    target_include_directories(http_def PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_include_directories(http_def PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpServer)
endif()

target_link_libraries(HttpServer http_def)

if(NOT TARGET nghttp2_static)
    message(FATAL_ERROR "HttpServer requires nghttp2_static, but it was not created")
endif()

target_link_libraries(HttpServer nghttp2_static)

if(NOT APPLE)
    target_precompile_headers(HttpServer REUSE_FROM ww)
endif()
