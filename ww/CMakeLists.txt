################################################################################
# WaterWall Runtime Library CMake Configuration
################################################################################

################################################################################
# Version Settings
################################################################################
set(WW_VERSION_MAJOR 1)
set(WW_VERSION_MINOR 1)
set(WW_VERSION_PATCH 0)

################################################################################
# Global Options & Build Configuration
################################################################################
option(WW_STATICLIB "Build as static library" ON)
option(ASMLIB_OVERRIDE "Try to link against asm lib and override standard functions" OFF)

# Crypto backend options (only one can be enabled)
option(WCRYPTO_BACKEND_SODIUM "Enable Sodium backend" ON)
option(WCRYPTO_BACKEND_OPENSSL "Enable OpenSSL backend" OFF)
option(WCRYPTO_BACKEND_SOFTWARE "Enable Software backend" OFF)

# Windows-specific options
if(WIN32)
    option(WITH_WEPOLL "Use wepoll (IOCP wrapper)" ON)
    option(ENABLE_WINDUMP "Enable Windows MiniDumpWriteDump" OFF)
endif()

# Validate required variables
if(NOT DEFINED FINAL_EXECUTABLE_NAME OR FINAL_EXECUTABLE_NAME STREQUAL "")
    message(FATAL_ERROR "FINAL_EXECUTABLE_NAME is not set! Please define it before configuring.")
endif()

################################################################################
# Library Build Configuration
################################################################################
add_library(ww STATIC
    # Core libraries
    libc/wlibc.c
    libc/wtime.c
    libc/werr.c
    libc/wfrand.c
    
    # Base functionality
    base/wchan.c
    base/widle_table.c
    base/wlog.c
    base/wlsem.c
    base/wsocket.c
    base/wsysinfo.c
    base/wproc.c
    
    # Buffer I/O
    bufio/buffer_pool.c
    bufio/buffer_stream.c
    bufio/context_queue.c
    bufio/buffer_queue.c
    bufio/generic_pool.c
    bufio/master_pool.c
    bufio/shiftbuffer.c
    
    # Utilities
    utils/base64.c
    utils/cacert.c
    utils/md5.c
    utils/sha1.c
    
    # Event handling
    event/wevent.c
    event/wloop.c
    event/nio.c
    event/ev_memory.c
    event/epoll.c
    event/evport.c
    event/iocp.c
    event/kqueue.c
    event/noevent.c
    event/overlapio.c
    event/poll.c
    event/select.c
    
    # Instance management
    instance/global_state.c
    instance/worker.c
    instance/wversion.c
    
    # Networking
    net/http_def.c
    net/packet_tunnel.c
    net/pipe_tunnel.c
    net/sync_dns.c
    net/adapter.c
    net/tunnel.c
    net/chain.c
    net/context.c
    net/socket_filter_option.c
    net/wchecksum.c
    net/wchecksum_default.c
    
    # LWIP integration
    lwip/ww_lwip.c
    
    # Node builder
    node_builder/config_file.c
    node_builder/node_library.c
    
    # Managers
    managers/signal_manager.c
    managers/socket_manager.c
    managers/node_manager.c
    managers/memory_manager.c

    # Data of SocketManager
    managers/data/iprange_mci.c
    managers/data/iprange_irancell.c
    managers/data/iprange_mokhaberat.c
    managers/data/iprange_rightel.c
    managers/data/iprange_iran.c
    
    # Loggers
    loggers/core_logger.c
    loggers/network_logger.c
    loggers/dns_logger.c
    loggers/internal_logger.c
)

set_source_files_properties(
    devices/capture/capture_linux.c
    devices/raw/raw_linux.c
    devices/raw/raw_windows.c
    devices/capture/capture_windows.c
    base/wlsem.c
    PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON
)

################################################################################
# Target Properties
################################################################################
target_compile_features(ww PUBLIC c_std_11)
set_target_properties(ww PROPERTIES LANGUAGES C)

################################################################################
# Include Directories
################################################################################
target_include_directories(ww PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/base
    ${CMAKE_CURRENT_SOURCE_DIR}/node_builder
    ${CMAKE_CURRENT_SOURCE_DIR}/bufio
    ${CMAKE_CURRENT_SOURCE_DIR}/event
    ${CMAKE_CURRENT_SOURCE_DIR}/net
    ${CMAKE_CURRENT_SOURCE_DIR}/instance
    ${CMAKE_CURRENT_SOURCE_DIR}/libc
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib
    ${CMAKE_CURRENT_SOURCE_DIR}/base/internal_types
)

################################################################################
# Platform-specific Configuration
################################################################################
if(WIN32)
    target_compile_definitions(ww PUBLIC 
        FINAL_EXECUTABLE_NAME="${FINAL_EXECUTABLE_NAME}.exe"
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS 
        _WIN32_WINNT=0x0600
    )
else()
    target_compile_definitions(ww PUBLIC FINAL_EXECUTABLE_NAME="${FINAL_EXECUTABLE_NAME}")
endif()

################################################################################
# CMake Module Setup
################################################################################
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")
include(utils)
include(vars)
include(CheckCCompilerFlag)

################################################################################
# Header and Function Checks
################################################################################
check_header("stdbool.h")
check_header("stdint.h")
check_header("stdatomic.h")
check_header("sys/types.h")
check_header("sys/stat.h")
check_header("sys/time.h")
check_header("fcntl.h")
check_header("pthread.h")
check_header("endian.h")
check_header("errno.h")
check_header("sys/endian.h")
check_header("x86intrin.h")
check_header("immintrin.h")

check_function("gettid" "unistd.h")
check_function("strlcpy" "string.h")
check_function("strlcat" "string.h")
check_function("clock_gettime" "time.h")
check_function("gettimeofday" "sys/time.h")
check_function("pthread_spin_lock" "pthread.h")
check_function("pthread_mutex_timedlock" "pthread.h")
check_function("sem_timedwait" "semaphore.h")
check_function("pipe" "unistd.h")
check_function("socketpair" "sys/socket.h")
check_function("eventfd" "sys/eventfd.h")
check_function("setproctitle" "unistd.h")

################################################################################
# Advanced CPU Instructions Configuration
################################################################################
set(WW_HAVE_ADVANCED_CPU_INSTRUCTIONS 0 CACHE INTERNAL "Using advanced CPU instructions" FORCE)
set(WW_HAVE_AVX2 0 CACHE INTERNAL "AVX2 available" FORCE)
set(WW_HAVE_SSE3 0 CACHE INTERNAL "SSE3 available" FORCE)
set(WW_SUPPORTED_MEMCOPY_AVX2 0 CACHE INTERNAL "Enable MemoryCopyLarge() to use AVX2" FORCE)
set(WW_SUPPORTED_MEMCOPY_AVX512F 0 CACHE INTERNAL "Enable MemoryCopyLarge() to use AVX512F" FORCE)
set(WW_CHECKSUM_AVX2 0 CACHE INTERNAL "Enable Checksum() to use AVX2" FORCE)
set(WW_CHECKSUM_SSE3 0 CACHE INTERNAL "Enable Checksum() to use SSE3" FORCE)

if(HAVE_X86INTRIN_H OR HAVE_IMMINTRIN_H AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT WW_DISABLE_ADVANCED_CPU_INSTRUCTIONS
    AND CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

    message(STATUS "Using advanced CPU instructions")
    set(WW_HAVE_ADVANCED_CPU_INSTRUCTIONS 1)

    if (MSVC)
        # MSVC: enable Haswell's AVX2
        # target_compile_options(ww PUBLIC /arch:AVX2)
    else()
        # GCC/Clang: target Haswell microarchitecture
        target_compile_options(ww PUBLIC -march=haswell)
    endif()
    
    # Check compiler support for instruction sets
    if(MSVC)
        # For MSVC x64: SSE/SSE2/SSE3 are enabled by default, no /arch flag needed
        # x64 build - SSE3 is always available
        set(COMPILER_SUPPORTS_SSE3 TRUE)
        check_c_compiler_flag("/arch:AVX2" COMPILER_SUPPORTS_AVX2)
        check_c_compiler_flag("/arch:AVX512" COMPILER_SUPPORTS_AVX512F)
    else()
        check_c_compiler_flag("-msse3" COMPILER_SUPPORTS_SSE3)
        check_c_compiler_flag("-mavx2" COMPILER_SUPPORTS_AVX2)
        check_c_compiler_flag("-mavx512f" COMPILER_SUPPORTS_AVX512F)
    endif()

    # SSE3 Configuration
    if(COMPILER_SUPPORTS_SSE3)
        message(STATUS "Using SSE3")
        if(MSVC)
            target_compile_options(ww PUBLIC /arch:SSE2)   # SSE3 is included in SSE2 support on MSVC
        else()
            target_compile_options(ww PUBLIC -msse3)
        endif()
        set(WW_HAVE_SSE3 1)
        set(WW_CHECKSUM_SSE3 1)
        target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/net/wchecksum_sse3.c")
    else()
        message(FATAL_ERROR "SSE3 not supported by compiler")
    endif()

    # AVX2 Configuration
    if(COMPILER_SUPPORTS_AVX2)
        message(STATUS "Using AVX2")
        if(MSVC)
            target_compile_options(ww PUBLIC /arch:AVX2)
        else()
            target_compile_options(ww PUBLIC -mavx2)
        endif()
        set(WW_HAVE_AVX2 1)
        set(WW_SUPPORTED_MEMCOPY_AVX2 1)
        set(WW_CHECKSUM_AVX2 1)
        target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/net/wchecksum_avx2.c")
    else()
        message(STATUS "AVX2 not supported by compiler")
    endif()

    # AVX512F Configuration
    if(COMPILER_SUPPORTS_AVX512F)
        if(WW_ENABLE_AVX_512)
            message(STATUS "Using AVX512F")
            if(MSVC)
                target_compile_options(ww PUBLIC /arch:AVX512)
            else()
                target_compile_options(ww PUBLIC -mavx512f)
            endif()
            set(WW_HAVE_AVX512F 1)
            set(WW_SUPPORTED_MEMCOPY_AVX512F 1)
        else()
            message(STATUS "AVX512F is power consuming and disabled by default")
        endif()
    else()
        message(STATUS "AVX512F not supported by compiler")
    endif()

else()
    message(STATUS "Advanced CPU instructions will not be used")
endif()

# Update cache variables
set(WW_HAVE_ADVANCED_CPU_INSTRUCTIONS ${WW_HAVE_ADVANCED_CPU_INSTRUCTIONS} CACHE INTERNAL "Using advanced CPU instructions" FORCE)
set(WW_HAVE_AVX2 ${WW_HAVE_AVX2} CACHE INTERNAL "AVX2 available" FORCE)
set(WW_HAVE_SSE3 ${WW_HAVE_SSE3} CACHE INTERNAL "SSE3 available" FORCE)
set(WW_SUPPORTED_MEMCOPY_AVX2 ${WW_SUPPORTED_MEMCOPY_AVX2} CACHE INTERNAL "Enable MemoryCopyLarge() to use AVX2" FORCE)
set(WW_SUPPORTED_MEMCOPY_AVX512F ${WW_SUPPORTED_MEMCOPY_AVX512F} CACHE INTERNAL "Enable MemoryCopyLarge() to use AVX512F" FORCE)
set(WW_CHECKSUM_AVX2 ${WW_CHECKSUM_AVX2} CACHE INTERNAL "Enable Checksum() to use AVX2" FORCE)
set(WW_CHECKSUM_SSE3 ${WW_CHECKSUM_SSE3} CACHE INTERNAL "Enable Checksum() to use SSE3" FORCE)


################################################################################
# Crypto Backend Source Selection
################################################################################
if(WCRYPTO_BACKEND_SODIUM)
    set(WCRYPTO_BACKEND_OPENSSL OFF CACHE BOOL "Enable OpenSSL backend" FORCE)
    set(WCRYPTO_BACKEND_SOFTWARE OFF CACHE BOOL "Enable Software backend" FORCE)
    
    target_sources(ww PRIVATE 
        crypto/sodium_instance.c
        crypto/impl_sodium/chacha20poly1305.c
        crypto/impl_sodium/xchacha20poly1305.c
        crypto/impl_sodium/x25519.c
        crypto/impl_software/blake2s.c
    )
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_SODIUM=1)
    
elseif(WCRYPTO_BACKEND_OPENSSL)
    set(WCRYPTO_BACKEND_SODIUM OFF CACHE BOOL "Enable Sodium backend" FORCE)
    set(WCRYPTO_BACKEND_SOFTWARE OFF CACHE BOOL "Enable Software backend" FORCE)
    
    target_sources(ww PRIVATE 
        crypto/openssl_instance.c
        crypto/impl_openssl/blake2s.c
        crypto/impl_openssl/chacha20poly1305.c
        crypto/impl_openssl/x25519.c
    )
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_OPENSSL=1)
    
elseif(WCRYPTO_BACKEND_SOFTWARE)
    set(WCRYPTO_BACKEND_SODIUM OFF CACHE BOOL "Enable Sodium backend" FORCE)
    set(WCRYPTO_BACKEND_OPENSSL OFF CACHE BOOL "Enable OpenSSL backend" FORCE)
    
    target_sources(ww PRIVATE 
        crypto/impl_software/blake2s.c
        crypto/impl_software/chacha20.c
        crypto/impl_software/chacha20poly1305.c
        crypto/impl_software/poly1305.c
        crypto/impl_software/poly1305-donna.c
        crypto/impl_software/x25519.c
    )
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_SOFTWARE=1)
endif()

################################################################################
# Platform-specific Device Sources
################################################################################
if(APPLE)
    message(STATUS "No Tun device support for macOS yet")
    
elseif(UNIX AND NOT ANDROID)
    target_sources(ww PRIVATE devices/tun/tun_linux.c)
    if(LINUX)
        target_sources(ww PRIVATE 
            devices/capture/capture_linux.c
            devices/raw/raw_linux.c
        )
    endif()
    
elseif(WIN32)
    # WinDivert for x64 systems
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        message(STATUS "Including WinDivert for amd64")
        target_sources(ww PRIVATE 
            vendor/windivert/x64/windivert.dll.x64.bytes.c
            vendor/windivert/x64/windivert.sys.x64.bytes.c
            devices/raw/raw_windows.c
            devices/capture/capture_windows.c
        )
    endif()

    # WinTun configuration
    target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/wintun/)
    
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        message(STATUS "Including WinTun for amd64")
        target_sources(ww PRIVATE vendor/wintun/amd64/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i386")
        message(STATUS "Including WinTun for x86")
        target_sources(ww PRIVATE vendor/wintun/x86/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM")
        message(STATUS "Including WinTun for ARM")
        target_sources(ww PRIVATE vendor/wintun/arm/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        message(STATUS "Including WinTun for ARM64")
        target_sources(ww PRIVATE vendor/wintun/arm64/wintun_bytes.c)
    else()
        message(FATAL_ERROR "Cannot bind WinTun - Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    
    target_sources(ww PRIVATE devices/tun/tun_windows.c)

    # WEPoll configuration
    set(WITH_WEPOLL 1)
    if(WITH_WEPOLL)
        target_include_directories(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/event/wepoll)
        target_sources(ww PRIVATE event/wepoll/wepoll.c)
        set_source_files_properties(
            event/wepoll/wepoll.c
            PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON
        )
    endif()
endif()

################################################################################
# External Dependencies
################################################################################
include(cmake/CPM.cmake)
set(BUILD_SHARED_LIBS OFF)

# KomiHash library
CPMAddPackage(
    NAME komihash
    GIT_REPOSITORY https://github.com/avaneev/komihash.git
    GIT_TAG 5.10
    DOWNLOAD_ONLY True
)
if(komihash_ADDED)
    target_include_directories(ww PUBLIC ${komihash_SOURCE_DIR})
endif()

# STC library
CPMAddPackage(
    NAME stc
    GIT_REPOSITORY https://github.com/radkesvat/STC
    GIT_TAG c23acadfc85a12adc2ae7c56d1fb12ccb1455b41
    DOWNLOAD_ONLY True
)
if(stc_ADDED)
    target_compile_definitions(ww PUBLIC STC_STATIC=1 STC_ALLOCATOR=c)
    target_include_directories(ww PUBLIC ${stc_SOURCE_DIR}/include)
    if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_compile_options(ww PUBLIC /wd4310)
    endif()
endif()

# cJSON library
CPMAddPackage(
    NAME cjson
    VERSION 1.7.17
    GITHUB_REPOSITORY DaveGamble/cJSON
    DOWNLOAD_ONLY True
)
if(cjson_ADDED)
    target_include_directories(ww PUBLIC ${cjson_SOURCE_DIR})
    target_sources(ww PRIVATE ${cjson_SOURCE_DIR}/cJSON.c)
    target_compile_definitions(ww PUBLIC CJSON_HIDE_SYMBOLS)
endif()
target_compile_definitions(ww PUBLIC ENABLE_TARGET_EXPORT=OFF)

# LibSodium library
CPMAddPackage(
    NAME libsodium
    GITHUB_REPOSITORY robinlinden/libsodium-cmake
    GIT_TAG 24f829c6d1bf88adb05ff3ee594abc367ffc0590
    OPTIONS
        "SODIUM_MINIMAL ON"
        "SODIUM_DISABLE_TESTS ON"
        "BUILD_SHARED_LIBS OFF"
        "SODIUM_BUILD_TESTS OFF"
        "SODIUM_BUILD_EXAMPLES OFF"
        "SODIUM_BUILD_SHARED OFF"
        "SODIUM_STATIC ON"
)

if(NOT MSVC)        
    target_compile_options(sodium PRIVATE -Wno-attributes)
endif()


set(LIBS ${LIBS} sodium)

################################################################################
# LWIP Library Configuration
################################################################################
CPMAddPackage(
    NAME lwip
    GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
    GIT_TAG STABLE-2_2_1_RELEASE
    DOWNLOAD_ONLY True
)
if(NOT lwip_ADDED)
    message(FATAL_ERROR "LWIP library could not be downloaded")
endif()

set(LWIP_DIR ${lwip_SOURCE_DIR})
set(WPDPACK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/)
set(LWIPOPTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)
set(LWIP_CONTRIB_DIR ${LWIPOPTS_DIR}/contrib)
set(LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib"
    "${LWIPOPTS_DIR}"
)
set(LWIP_DEFINITIONS ${LWIP_DEFINITIONS} WW_LWIP_HAVE_ERRNO_H=$<IF:${HAVE_ERRNO_H},1,0>)

if(NOT APPLE)
    set(LWIP_DEFINITIONS ${LWIP_DEFINITIONS} LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS=1)
endif()
if(ANDROID)
    set(LWIP_DEFINITIONS ${LWIP_DEFINITIONS} SOCKLEN_T_DEFINED=1)
endif()
if(WIN32)
    set(LWIP_INCLUDE_DIRS ${LWIP_INCLUDE_DIRS} "${LWIP_CONTRIB_DIR}/ports/win32/include")
    target_compile_definitions(ww PUBLIC LWIP_NO_UNISTD_H=1)
else()
    set(LWIP_INCLUDE_DIRS ${LWIP_INCLUDE_DIRS} "${LWIP_CONTRIB_DIR}/ports/unix/port/include")
endif()

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_CONTRIB_DIR}/Filelists.cmake)

add_library(ww_lwip STATIC ${lwipnoapps_SRCS})

target_compile_definitions(ww_lwip PUBLIC $<$<CONFIG:Debug>:LWIP_DEBUG=1>)
target_include_directories(ww_lwip PUBLIC ${LWIP_INCLUDE_DIRS})
target_compile_definitions(ww_lwip PUBLIC ${LWIP_DEFINITIONS})

# Set the platform-specific sys_arch.c property explicitly.
if(UNIX)
    set_source_files_properties(
        ${LWIP_CONTRIB_DIR}/ports/unix/port/sys_arch.c
        PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON
    )
elseif(WIN32)
    set_source_files_properties(
        ${LWIP_CONTRIB_DIR}/ports/win32/sys_arch.c
        PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON
    )
endif()

set_source_files_properties(
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/altcp_tcp.c
    ${LWIP_DIR}/src/core/altcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    ${LWIP_DIR}/src/core/ipv6/ip6_frag.c
    ${LWIP_DIR}/src/core/udp.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/netif/ppp/ppp.c
    ${LWIP_DIR}/src/api/netdb.c
    ${LWIP_DIR}/src/api/sockets.c
    PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON
)

if(UNIX)
    target_sources(ww_lwip PRIVATE ${LWIP_CONTRIB_DIR}/ports/unix/port/sys_arch.c)
else()
    target_sources(ww_lwip PRIVATE ${LWIP_CONTRIB_DIR}/ports/win32/sys_arch.c)
endif()

if(NOT MSVC AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang" AND NOT CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS} -Wno-stringop-overread -Wno-stringop-overflow)
endif()

# Windows-specific LWIP compiler flags for Clang
if(WIN32)
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS} -Wno-pragma-pack)
        set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS} -fno-ms-compatibility)
        # set_target_properties(ww_lwip PROPERTIES UNITY_BUILD OFF)
    endif()
endif()


target_compile_options(ww_lwip PRIVATE ${LWIP_COMPILER_FLAGS})
set(LIBS ${LIBS} ww_lwip)

################################################################################
# Mimalloc Configuration
################################################################################
set(MI_USE_CXX OFF) 
set(MI_NO_USE_CXX ON)
set(MI_OVERRIDE OFF)
set(MI_XMALLOC ON)
set(MI_OPT_ARCH ${WW_HAVE_ADVANCED_CPU_INSTRUCTIONS})
set(MI_OPT_SIMD ${WW_HAVE_ADVANCED_CPU_INSTRUCTIONS})
set(MI_BUILD_SHARED OFF)
set(MI_BUILD_OBJECT OFF)
set(MI_BUILD_TESTS OFF)
set(MI_SKIP_COLLECT_ON_EXIT ON)
set(MI_DEBUG OFF)
set(MI_SECURE OFF)


add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/mimalloc)

if(NOT MSVC)        
    target_compile_options(mimalloc-static PRIVATE -Wno-attributes -Wno-array-bounds)
    if(MI_USE_CXX)
        target_compile_options(mimalloc-static PRIVATE -Wno-missing-field-initializers)
    endif()
endif()

set(LIBS ${LIBS} mimalloc-static)

################################################################################
# Final Configuration and Linking
################################################################################
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h)
message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

# ASM library configuration for Linux x86_64
if(LINUX AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)
    if(CMAKE_BUILD_TYPE STREQUAL "Release" AND ASMLIB_OVERRIDE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-builtin-function")  
        set(CMAKE_EXE_LINKER_FLAGS "-L${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib -laelf64o" CACHE INTERNAL "calculated linker flags, the order is important")
    else()
        target_link_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)
    endif()
endif()

# Architecture definitions
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(ww PUBLIC WW_COMPILE_FOR_64BIT=1 WW_COMPILE_FOR_32BIT=0)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_compile_definitions(ww PUBLIC WW_COMPILE_FOR_64BIT=0 WW_COMPILE_FOR_32BIT=1)
else()
    message(FATAL_ERROR "Unknown pointer size")
endif()

# Build type definitions
target_compile_definitions(ww PUBLIC 
    $<$<CONFIG:Debug>:DEBUG=1>
    $<$<CONFIG:RelWithDebInfo>:NDEBUG=1;RELEASEWITHDEBUGINFO=1>
    $<$<CONFIG:Release>:NDEBUG=1;RELEASE=1>
)

# Optional features
if(ENABLE_UDS)
    target_compile_definitions(ww PUBLIC ENABLE_UDS)
endif()

if(WW_STATICLIB)
    target_compile_definitions(ww PUBLIC WW_STATICLIB)
else()
    target_compile_definitions(ww PUBLIC WW_DYNAMICLIB)
endif()

# Platform-specific libraries
if(WIN32)
    set(LIBS ${LIBS} secur32 crypt32 winmm ntdll iphlpapi ws2_32 pdh)
    if(ENABLE_WINDUMP)
        target_compile_definitions(ww PUBLIC ENABLE_WINDUMP)
        set(LIBS ${LIBS} dbghelp)
    endif()
elseif(ANDROID)
    set(LIBS ${LIBS} log)
elseif(UNIX)
    set(LIBS ${LIBS} pthread m)
    if(NOT CMAKE_SYSTEM_NAME MATCHES "BSD")
        set(LIBS ${LIBS} dl)
    endif()
    if(CMAKE_COMPILER_IS_GNUCC)
        set(LIBS ${LIBS} rt)
    endif()
endif()

if(APPLE)
    set(LIBS ${LIBS} "-framework CoreFoundation" "-framework Security")
endif()

# GNU C++ exception handler cleanup (development/debugging)
if(NOT MSVC)
    set(FREERES_TEST_FILE "${CMAKE_CURRENT_BINARY_DIR}/test_freeres_wrap.cc")
    file(WRITE ${FREERES_TEST_FILE} "
#define WW_FREERES_TEST_MODE 1

extern \"C\" void call_freeres(); 

namespace __gnu_cxx {
  void __freeres() noexcept;
}

extern \"C\" void call_freeres() {
    __gnu_cxx::__freeres();   
}

#ifdef WW_FREERES_TEST_MODE
int main() {
    call_freeres();
    return 0;
}
#endif
")
    
    try_compile(FREERES_WRAP_COMPILES
        ${CMAKE_CURRENT_BINARY_DIR}/test_freeres_wrap
        ${FREERES_TEST_FILE}
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        OUTPUT_VARIABLE FREERES_WRAP_OUTPUT
    )
    
    if(FREERES_WRAP_COMPILES)
        # message(STATUS "Including FREERS_EH library for cleaner valgrind output")
        add_library(FREERS_EH OBJECT utils/freeres_wrap.cc)
        target_compile_definitions(ww PUBLIC WW_CALL_GNU_FREES)
        set(LIBS ${LIBS} "FREERS_EH")
    else()
        message(STATUS "__gnu_cxx::__freeres not available - skipping FREERS_EH")
    endif()
endif()

target_link_libraries(ww PUBLIC ${LIBS})

# Symbol stripping for release builds
if(MSVC)
    # For MSVC: disable debug info generation and strip symbols in release
    target_link_options(ww PUBLIC 
        $<$<CONFIG:Release>:/DEBUG:NONE>
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
    )
else()
    # For GCC/Clang: use -s flag to strip symbols
    target_link_options(ww PUBLIC $<$<CONFIG:Release>:-s>)
endif()

# Disable Unity Build for targets that cannot use it
set_target_properties(sodium PROPERTIES UNITY_BUILD OFF)
# set_target_properties(ww_lwip PROPERTIES UNITY_BUILD_BATCH_SIZE 16)
set_target_properties(ww PROPERTIES UNITY_BUILD_BATCH_SIZE 500)



################################################################################
# Sanitizer Options (Debug builds only)
################################################################################
if(ENABLE_ASAN)
    target_compile_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=address>)
    target_link_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=address>)
endif()
if(ENABLE_TSAN)
    target_compile_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=thread>)
    target_link_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=thread>)
endif()
if(ENABLE_LSAN)
    target_compile_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=leak>)
    target_link_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=leak>)
endif()
if(ENABLE_USAN)
    target_compile_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=undefined>)
    target_link_options(ww PUBLIC $<$<CONFIG:Debug>:-fsanitize=undefined>)
endif()

################################################################################
# Compiler-specific Options
################################################################################
if(NOT MSVC)
    target_compile_options(ww PUBLIC 
        -Wall 
        -Wextra 
        -Werror 
        -pedantic 
        -pedantic-errors
        -Wparentheses
        -Wsequence-point
        -Wpointer-arith
        -Wlogical-not-parentheses
        -Wshadow
        -Wmissing-prototypes
        -Wnested-externs
        -Wuninitialized
        -Wwrite-strings
        -Wunused-parameter
        -Wstrict-prototypes
        # disable warnings for unused functions and unkown pragmas
        -Wno-unused-function
        -Wno-unknown-pragmas 
        -Wno-error=pragmas
        -Wno-unknown-warning-option
        -Wno-pragmas
        # disable warnings for int to pointer conversion
        # -Wno-int-to-pointer-cast
        # -Wno-pointer-to-int-cast
    )

    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        # Suppress unused command-line argument warnings for ASM compilation on Clang
        # This prevents -D flags and -pedantic from causing errors when assembling .s files
        target_compile_options(ww PRIVATE $<$<AND:$<COMPILE_LANGUAGE:ASM>,$<C_COMPILER_ID:Clang>>:-Wno-unused-command-line-argument>)
        # prevent defining _MSC_VER
        target_compile_options(ww PUBLIC -fno-ms-compatibility)
    endif()
endif()

if(APPLE)
    target_compile_options(ww PRIVATE -Wno-shorten-64-to-32 -Wno-unused-command-line-argument)
    # Disable precompiled headers on Apple platforms due to clang issues with C/C++ mixed compilation
    set_target_properties(ww PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
endif()

if(MSVC)
    target_compile_options(ww PUBLIC /W4 /WX 
    /wd4505 # unreferenced local function has been removed (unused function warning)
    )
endif()

# Precompiled headers (except on Apple)
if(NOT APPLE)
    target_precompile_headers(ww PUBLIC "wwapi.h")
endif()

# Final definitions
target_compile_definitions(ww PUBLIC 
    WW_VERSION=${WW_VERSION_MAJOR}.${WW_VERSION_MINOR}.${WW_VERSION_PATCH}
)
