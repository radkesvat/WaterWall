########## NOTES
# The Downloaded BoringSSL source code was the HEAD of the repository at the time of writing this.
# The commit hash is 4b3285002397da82681bebaacea9b4f231c9dbfc
# Currently only removed git folder to be able to push it

# All my patches (diffs) are saved in RadkesvatPatches folder

# I saved original cmake file as CMakeLists.txt.original
# and the diff of changes that I made to CMakeLists.txt is CMakeLists.txt.patch
   
# Description:
    # Line 44 of bssl cmake: set INSTALL_ENABLED to zero
    # At around line 720 of bssl cmake: add_executable(bssl ${BSSL_SOURCES}) is excluded if APPLE

# I saved the original p256_64.h file as p256_64.h.original
# and the diff of changes that I made to p256_64.h is p256_64.h.patch

# Description:
    # There was a problem on Windows with assembly optimizations in BoringSSL, so we disable the buggy part
    # by defining WW_BSSL_WIN_FIAT_NO_ASM, which is used in p256_64.h to conditionally switch to C code.
    # This is done to avoid issues with assembly code that is not added to NASM build list by BoringSSL CMakeLists.txt
    # The assembly code is only compiled on Linux, so we can safely disable it on Windows.
    # windows still uses assmembly code main parts of boring ssl, only 2 functions are now using c code instead of assembly
    # they are not also important functions in tls as far as i know (only used for elliptic curve operations)
    # they are : fiat_p256_adx_sqr, fiat_p256_adx_mul

# I added brotli library to the project, because it is used to decompress certificates and Chrome uses it too.

# I patched the handshake_client.cc file to add TLS 1.3 ciphers like Chrome does. patch file is 
# also saved as handshake_client.cc.patch

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
target_include_directories(DecompressBrotli PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/brotli/include
)

#==============================================================================
# TLS Client Library
#==============================================================================

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

target_include_directories(TlsClient PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)




#==============================================================================
# BoringSSL Configuration
#==============================================================================

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/boringssl boringssl)

target_include_directories(DecompressBrotli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include
)

target_link_libraries(DecompressBrotli PRIVATE crypto ssl)

target_include_directories(TlsClient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include
)

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
if(WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(bssl PRIVATE -Wno-format)
endif()

if(WIN32)
    # BoringSSL on Windows points to some functions in assembly that their assembly files are only compiled on Linux
    # Adding this to switch to C version on Windows
    # More notes are above
    target_compile_definitions(bssl       PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(ssl        PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(crypto     PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(pki        PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(fipsmodule PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(decrepit   PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
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

if(NOT APPLE)
    set_target_properties(bssl PROPERTIES UNITY_BUILD OFF)
endif()


#==============================================================================
# Final Library Linkage
#==============================================================================

target_link_libraries(TlsClient PRIVATE ww BrotliDec DecompressBrotli crypto ssl)
if(NOT APPLE)
    target_precompile_headers(TlsClient REUSE_FROM ww)
endif()
