add_library(HttpServer STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/h2_helpers.c
                    common/line_state.c


                    http2/upstream/init.c
                    http2/upstream/est.c
                    http2/upstream/fin.c
                    http2/upstream/payload.c
                    http2/upstream/pause.c
                    http2/upstream/resume.c
                    http2/upstream/est.c
                    http2/downstream/init.c
                    http2/downstream/est.c
                    http2/downstream/fin.c
                    http2/downstream/payload.c
                    http2/downstream/pause.c
                    http2/downstream/resume.c
                    http2/downstream/est.c
  
)

target_include_directories(HttpServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(HttpServer ww)

if(NOT TUNNELS_HTTP_DEF_SET)
    set(TUNNELS_HTTP_DEF_SET TRUE CACHE INTERNAL "")
    add_library(http_def OBJECT
        common/http_def.c
    )
    target_include_directories(http_def PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
endif()

target_link_libraries(HttpServer http_def)

CPMAddPackage(
    NAME nghttp2
    GIT_TAG v1.66.0
    GITHUB_REPOSITORY nghttp2/nghttp2
    OPTIONS 
    "ENABLE_APP OFF"
    "ENABLE_HPACK_TOOLS OFF"
    "BUILD_SHARED_LIBS OFF"
    "BUILD_STATIC_LIBS ON"
    "ENABLE_STATIC_CRT ON" 
    "ENABLE_HTTP3 OFF"     
    "WITH_JEMALLOC OFF"
    "WITH_LIBXML2 OFF"
    "ENABLE_EXAMPLES OFF"
    "ENABLE_DOC OFF"
    "ENABLE_LIB_ONLY ON"
    # "ENABLE_DEBUG ON"
)

if(WW_HAVE_SSE3)
    if(MSVC)
        target_compile_options(nghttp2_static PRIVATE /arch:SSE2)   # SSE3 is included in SSE2 support on MSVC
    else()
        target_compile_options(nghttp2_static PRIVATE -msse3)
    endif()
endif()

if(WW_HAVE_AVX2)
    if(MSVC)
        target_compile_options(nghttp2_static PRIVATE /arch:AVX2)
    else()
        target_compile_options(nghttp2_static PRIVATE -mavx2)
    endif()
endif()

target_link_libraries(HttpServer nghttp2_static)

set_target_properties(nghttp2_static PROPERTIES UNITY_BUILD_BATCH_SIZE 18)

if(NOT APPLE)
    target_precompile_headers(HttpServer REUSE_FROM ww)
endif()
