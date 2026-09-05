add_library(HttpServer STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    common/helpers.c
                    common/http_base64.c
                    common/line_state.c
                    common/transport.c
                    common/split.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
  
)

target_include_directories(HttpServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(HttpServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpServer)

target_link_libraries(HttpServer ww)

add_library(http_server_def OBJECT
    common/http_def.c
)
target_include_directories(http_server_def PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(http_server_def PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/HttpServer)
target_link_libraries(http_server_def PRIVATE ww nghttp2_static)

target_link_libraries(HttpServer http_server_def)

if(NOT TARGET nghttp2_static)
    message(FATAL_ERROR "HttpServer requires nghttp2_static, but it was not created")
endif()

target_link_libraries(HttpServer nghttp2_static)

if(NOT APPLE)
    target_precompile_headers(HttpServer REUSE_FROM ww)
endif()
