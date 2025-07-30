
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
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)


# Configure BoringSSL options
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build BoringSSL as static library" FORCE)
set(INSTALL_ENABLED OFF CACHE BOOL "Disable BoringSSL installation" FORCE)
set(BUILD_TOOL OFF CACHE BOOL "Disable BoringSSL tools" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Disable BoringSSL tests" FORCE)

if(APPLE)
    set(CMAKE_MACOSX_BUNDLE OFF CACHE BOOL "Disable macOS bundle creation for BoringSSL" FORCE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(CMAKE_OSX_ARCHITECTURES "arm64")
    set(CMAKE_OSX_SYSROOT "iphoneos")
endif()

# For Windows ARM64 builds, disable assembly to avoid x86/x64 assembly conflicts
if(WIN32 AND (CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64"))
    message(STATUS "Configuring BoringSSL for Windows ARM64 - disabling assembly to avoid x86/x64 conflicts")
    set(OPENSSL_NO_ASM ON CACHE BOOL "Disable BoringSSL assembly for Windows ARM64" FORCE)
endif()

CPMAddPackage(
    NAME BoringSSL
    GIT_REPOSITORY https://boringssl.googlesource.com/boringssl
    GIT_TAG 0.20250701.0
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
