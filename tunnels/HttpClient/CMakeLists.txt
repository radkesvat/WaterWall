
add_library(HttpClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/stop.c
                    instance/chain.c
                    instance/index.c
                    common/transport.c
                    common/split.c
                    common/line_state.c
                    common/helpers.c
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

target_include_directories(HttpClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(HttpClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpClient)

target_link_libraries(HttpClient ww)

if(NOT TARGET http_def)
    add_library(http_def OBJECT
        common/http_def.c
    )
    target_include_directories(http_def PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_include_directories(http_def PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpClient)
endif()

target_link_libraries(HttpClient http_def)

if(NOT TARGET nghttp2_static)
    message(FATAL_ERROR "HttpClient requires nghttp2_static, but it was not created")
endif()

target_link_libraries(HttpClient nghttp2_static)

if(NOT APPLE)
    target_precompile_headers(HttpClient REUSE_FROM ww)
endif()
