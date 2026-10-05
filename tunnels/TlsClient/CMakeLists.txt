# BoringSSL is pinned to Chromium 154.0.8037.97's revision:
# ac39ea6853833c1f18fd23614091d11855e71752
# Local patches live in RadkesvatPatches. Port record padding before direct
# record output, then apply the public prefix patch after all custom SSL APIs
# are present. Upstream supplies internal and assembly prefix
# headers for each architecture. See `my notes.txt` for the porting contract and
# validation checklist. Normal builds consume these headers without a generator.

#==============================================================================
# Build Configuration
#==============================================================================

# set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS OFF)
set(INSTALL_ENABLED OFF)
set(BUILD_TOOL OFF)
set(BUILD_TESTING OFF)





#==============================================================================
# Brotli Decompression Library
#==============================================================================

add_library(BrotliDec OBJECT
    brotli/dec/bit_reader.c
    brotli/dec/decode.c
    brotli/dec/huffman.c
    brotli/dec/state.c
    brotli/common/constants.c
    brotli/common/platform.c
    brotli/common/context.c
    brotli/common/transform.c
    brotli/common/dictionary.c
)

target_include_directories(BrotliDec PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/brotli/include
)

# Decompress_brotli library depends on BoringSSL (to decompress certificates)
add_library(DecompressBrotli OBJECT
    common/decompress_brotli.cc
)

target_compile_features(DecompressBrotli PRIVATE cxx_std_17)
target_link_libraries(DecompressBrotli PRIVATE waterwall_runtime_options)
target_include_directories(DecompressBrotli PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/brotli/include
)

#==============================================================================
# TLS Client Library
#==============================================================================

add_library(TlsClient STATIC
    ../Internals/TlsBufferBio/buffer_bio.c
    instance/chain.c
    instance/create.c
    instance/destroy.c
    instance/api.c
    instance/node.c
    common/helpers.c
    common/line_state.c
    common/trust_anchors.c
    upstream/init.c
    upstream/fin.c
    upstream/payload.c
    downstream/est.c
    downstream/fin.c
    downstream/payload.c
    downstream/pause.c
    downstream/resume.c
    downstream/est.c
)

# Keep the public API entry point in its own archive object. Some unit tests
# provide a purpose-built tlsclientTunnelApi() stub; folding api.c into the
# unity object would force both definitions into the link when another
# TlsClient symbol is needed.
set_source_files_properties(instance/api.c PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)

target_include_directories(TlsClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(TlsClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../Internals/TlsBufferBio/include)
target_include_directories(TlsClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/TlsClient)




#==============================================================================
# BoringSSL Configuration
#==============================================================================

set(WW_BORINGSSL_PREFIX WW_BSSL)
set(BORINGSSL_PREFIX ${WW_BORINGSSL_PREFIX})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/boringssl boringssl)

foreach(runtime_dependency IN ITEMS BrotliDec fipsmodule crypto ssl decrepit pki)
    if(TARGET ${runtime_dependency})
        waterwall_configure_runtime_dependency(${runtime_dependency})
    endif()
endforeach()

target_include_directories(DecompressBrotli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include
)
target_compile_definitions(DecompressBrotli PRIVATE BORINGSSL_PREFIX=${WW_BORINGSSL_PREFIX})

target_link_libraries(DecompressBrotli PRIVATE crypto ssl)

target_include_directories(TlsClient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include
)
target_compile_definitions(TlsClient PRIVATE BORINGSSL_PREFIX=${WW_BORINGSSL_PREFIX})

#==============================================================================
# Platform-specific Configurations
#==============================================================================

if(APPLE)
    target_compile_options(ssl PRIVATE -Wno-shorten-64-to-32)
    target_compile_options(crypto PRIVATE -Wno-shorten-64-to-32)
    target_compile_options(pki PRIVATE -Wno-shorten-64-to-32)
    target_compile_options(fipsmodule PRIVATE -Wno-shorten-64-to-32)
    target_compile_options(decrepit PRIVATE -Wno-shorten-64-to-32)
endif()

# Fix for MinGW64 format string warnings
if(TARGET bssl AND WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(bssl PRIVATE -Wno-format)
endif()

# GCC (notably 15.x on MinGW/UCRT64) emits false-positive -Warray-bounds /
# -Wstringop-overflow when it inlines the AVX2 _mm256_store path of
# memoryZeroAligned32 (ww/libc/wlibc.h) over small fixed-size line-state buffers
# in helpers.c / line_state.c. The stores are in-bounds; keep the warnings
# visible but don't let ww's inherited -Werror fail the build. -Wno-error=
# overrides a later blanket -Werror regardless of command-line order.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(TlsClient PRIVATE -Wno-error=array-bounds -Wno-error=stringop-overflow)
endif()

if(NOT MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wno-free-nonheap-object" CACHE STRING "Linker flags" FORCE)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wno-free-nonheap-object" CACHE STRING "Linker flags" FORCE)
endif()

set_target_properties(crypto PROPERTIES UNITY_BUILD OFF)
set_target_properties(ssl PROPERTIES UNITY_BUILD OFF)
set_target_properties(pki PROPERTIES UNITY_BUILD OFF)
set_target_properties(fipsmodule PROPERTIES UNITY_BUILD OFF)
set_target_properties(decrepit PROPERTIES UNITY_BUILD OFF)

if(TARGET bssl AND NOT APPLE)
    set_target_properties(bssl PROPERTIES UNITY_BUILD OFF)
endif()


#==============================================================================
# Final Library Linkage
#==============================================================================

target_link_libraries(TlsClient PUBLIC TlsRecordShapingCommon)
target_link_libraries(TlsClient PRIVATE StreamFragmenter ww BrotliDec DecompressBrotli crypto ssl)
if(NOT APPLE)
    target_precompile_headers(TlsClient REUSE_FROM ww)
endif()
