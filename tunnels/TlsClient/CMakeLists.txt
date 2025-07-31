
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

# set(CMAKE_POSITION_INDEPENDENT_CODE ON)


# Configure BoringSSL options
set(BUILD_SHARED_LIBS OFF)
set(INSTALL_ENABLED OFF)
set(BUILD_TOOL OFF)
set(BUILD_TESTING OFF)



########## NOTES
# The Downnloaded BoringSSL source code was the HEAD of the repository at the time of writing this.
# the commit hash is 4b3285002397da82681bebaacea9b4f231c9dbfc
# currently only removed git folder to be able to push it

# All my patches are saveid in RadkesvatPatches folder

# i saved original cmake file as CMakeLists.txt.original
# and the diff of changes that i made to CMakeLists.tx is CMakeLists.txt.patch
   
# description:
    # line 44 of bssl cmake: set INSTALL_ENABLED to zero
    # at around line 720 of bssl cmake:  add_executable(bssl ${BSSL_SOURCES}) is excluded if APPLE

# i saved the original p256_64.h file as p256_64.h.original
# and the diff of changes that i made to p256_64.h is p256_64.h.patch

# description:
    # There was a problem on windows with assembly optimizations in BoringSSL, so we disable them
    # by defining WW_BSSL_WIN_FIAT_NO_ASM, which is used in p256_64.h to conditionally switch to c code.
    # This is done to avoid issues with assembly code that is not added to NASM build list by boringssl CMakeLists.txt
    # The assembly code is only compiled on Linux, so we can safely disable it on Windows.


add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/boringssl boringssl)



# Include BoringSSL headers
target_include_directories(TlsClient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include
)


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
    # boring ssl on windows points to some functions in assembly that their assembly files are only compiled on linux
    # adding this to switch to c version on windows
    # more notes are above
    target_compile_definitions(bssl       PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(ssl        PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(crypto     PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(pki        PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(fipsmodule PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
    target_compile_definitions(decrepit   PRIVATE WW_BSSL_WIN_FIAT_NO_ASM=1)
endif()

target_link_libraries(TlsClient PRIVATE crypto ssl)
