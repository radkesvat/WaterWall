
add_library(HttpClient STATIC
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
                    common/http_def.c


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

target_include_directories(HttpClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(HttpClient ww)

CPMAddPackage(
    NAME nghttp2
    GIT_TAG v1.66.0
    GITHUB_REPOSITORY nghttp2/nghttp2
    OPTIONS 
    "ENABLE_APP OFF"
    "ENABLE_HPACK_TOOLS OFF"
    # nghttp2-specific toggles — BUILD_SHARED_LIBS is not used by nghttp2
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


# target_sources(nghttp2_static PRIVATE
#     $<TARGET_PROPERTY:nghttp2,SOURCES>
# )

# set_source_files_properties(
#     ${nghttp2_SOURCE_DIR}/lib/nghttp2_http.c
#     ${nghttp2_SOURCE_DIR}/lib/nghttp2_helper.c
#     PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON
# )

target_link_libraries(HttpClient nghttp2_static)


set_target_properties(nghttp2_static PROPERTIES UNITY_BUILD_BATCH_SIZE 18)

if(NOT APPLE)
    target_precompile_headers(HttpClient REUSE_FROM ww)
endif()
