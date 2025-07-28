
add_library(TlsClient STATIC
                    instance/create.c
                    instance/destroy.c
                    instance/api.c
                    instance/node.c
                    instance/prepair.c
                    instance/start.c
                    instance/chain.c
                    instance/index.c
                    common/helpers.c
                    common/line_state.c
                    upstream/init.c
                    upstream/est.c
                    upstream/fin.c
                    upstream/payload.c
                    upstream/pause.c
                    upstream/resume.c
                    upstream/est.c
                    downstream/init.c
                    downstream/est.c
                    downstream/fin.c
                    downstream/payload.c
                    downstream/pause.c
                    downstream/resume.c
                    downstream/est.c
  
)

target_include_directories(TlsClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)


target_link_libraries(TlsClient PRIVATE ww)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

CPMAddPackage(
    NAME BoringSSL
    GIT_REPOSITORY https://boringssl.googlesource.com/boringssl
    GIT_TAG main
    OPTIONS
    "BUILD_SHARED_LIBS OFF"
)

target_include_directories(TlsClient PRIVATE
    ${boringssl_SOURCE_DIR}/include
)

enable_language(CXX)

# Static link standard libraries for C++ code in BoringSSL
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(APPLE)
        target_link_libraries(TlsClient PRIVATE c++)
    else()
        target_link_libraries(TlsClient PRIVATE stdc++)
    endif()
endif()

target_link_libraries(TlsClient PRIVATE crypto ssl)
