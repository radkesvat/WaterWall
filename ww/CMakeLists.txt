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

# Crypto backend options. These compose as a priority stack:
# OpenSSL > libsodium > software fallback. The software fallback is always
# compiled, while the external backends are configurable.
set(WCRYPTO_OPENSSL_DEFAULT OFF)
if(PROJECT_REQUIRES_OPENSSL)
    set(WCRYPTO_OPENSSL_DEFAULT ON)
endif()
option(WCRYPTO_BACKEND_SODIUM "Enable libsodium crypto backend" ON)
option(WCRYPTO_BACKEND_OPENSSL "Enable OpenSSL crypto backend" ${WCRYPTO_OPENSSL_DEFAULT})
set(WCRYPTO_BACKEND_SOFTWARE ON CACHE BOOL "Always enable software crypto fallback" FORCE)
mark_as_advanced(WCRYPTO_BACKEND_SOFTWARE)

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
    base/local_widle_table.c
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
    bufio/threadsafe_generic_pool.c
    bufio/master_pool.c
    bufio/shiftbuffer.c
    
    # Utilities
    utils/base64.c
    utils/cacert.c
    utils/md5.c
    utils/sha1.c
    objects/user_handle.c
    objects/user.c
    objects/users.c
    
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
    instance/worker_messages.c
    instance/wversion.c
    
    # Networking
    net/packet_tunnel.c
    net/pipe_tunnel.c
    net/sync_dns.c
    net/async_dns.c
    net/dns_strategy.c
    net/adapter.c
    net/tunnel.c
    net/line.c
    net/chain.c
    net/context.c
    net/generic_sniffer.c
    net/egress_pin.c
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

    
    # Loggers
    loggers/core_logger.c
    loggers/network_logger.c
    loggers/dns_logger.c
    loggers/internal_logger.c
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
check_header("inttypes.h")
check_header("limits.h")
check_header("netinet/in.h")
check_header("pthread.h")
check_header("stdlib.h")
check_header("string.h")
check_header("endian.h")
check_header("errno.h")
check_header("sys/endian.h")
check_header("sys/file.h")
check_header("sys/ioctl.h")
check_header("sys/socket.h")
check_header("unistd.h")
check_header("x86intrin.h")
check_header("immintrin.h")

check_function("ftruncate" "unistd.h")
check_function("gettid" "unistd.h")
check_function("memset" "string.h")
check_function("memset_explicit" "string.h")
check_function("explicit_bzero" "string.h")
check_function("timingsafe_bcmp" "string.h")
check_function("socket" "sys/socket.h")
check_function("strlcpy" "string.h")
check_function("strlcat" "string.h")
check_function("strtoul" "stdlib.h")
check_function("usleep" "unistd.h")
check_function("srandom" "stdlib.h")
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
option(WW_DISABLE_ADVANCED_CPU_INSTRUCTIONS "Disable all architecture-specific CPU instruction paths" OFF)
option(WW_DISABLE_AVX "Disable all AVX instruction paths (AVX/AVX2/AVX512) while keeping SSE3 available" OFF)
option(WW_DISABLE_AVX2 "Disable AVX2-specific instruction paths while keeping lower x86 features available" OFF)
option(DEV_DISABLE_AVX2 "Developer switch: disable AVX2-specific instruction paths" OFF)
option(WW_ENABLE_AVX_512 "Enable AVX512F instruction paths" OFF)

set(WW_ADVANCED_CPU_BASELINE "haswell" CACHE STRING "Non-MSVC -march value used for advanced x86_64 builds")
set(WW_ADVANCED_CPU_EXTRA_FLAGS "" CACHE STRING "Additional non-MSVC CPU flags for advanced x86_64 builds")

set(WW_HAVE_ADVANCED_CPU_INSTRUCTIONS 0)
set(WW_HAVE_SSE3 0)
set(WW_HAVE_AVX 0)
set(WW_HAVE_AVX2 0)
set(WW_HAVE_AVX512F 0)
set(WW_SUPPORTED_MEMCOPY_AVX2 0)
set(WW_SUPPORTED_MEMCOPY_AVX512F 0)
set(WW_CHECKSUM_AVX2 0)
set(WW_CHECKSUM_SSE3 0)

set(WW_TARGET_X86_64 FALSE)
if(CMAKE_SIZEOF_VOID_P EQUAL 8 AND (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"))
    set(WW_TARGET_X86_64 TRUE)
endif()

set(WW_HAS_X86_INTRINSICS FALSE)
if(HAVE_X86INTRIN_H OR HAVE_IMMINTRIN_H)
    set(WW_HAS_X86_INTRINSICS TRUE)
endif()

set(WW_AVX_DISABLED FALSE)
if(WW_DISABLE_AVX)
    set(WW_AVX_DISABLED TRUE)
endif()

# AVX2 (and AVX512) build on top of AVX, so disabling AVX cascades into disabling them.
set(WW_AVX2_DISABLED FALSE)
if(WW_DISABLE_AVX2 OR DEV_DISABLE_AVX2 OR WW_AVX_DISABLED)
    set(WW_AVX2_DISABLED TRUE)
endif()

if(WW_ENABLE_AVX_512 AND WW_AVX2_DISABLED)
    message(FATAL_ERROR "WW_ENABLE_AVX_512 requires AVX2 (and therefore AVX) to remain enabled")
endif()

function(ww_add_cpu_compile_option target msvc_option non_msvc_option)
    if(MSVC)
        if(NOT "${msvc_option}" STREQUAL "")
            target_compile_options(${target} PUBLIC "${msvc_option}")
        endif()
    elseif(NOT "${non_msvc_option}" STREQUAL "")
        target_compile_options(${target} PUBLIC "${non_msvc_option}")
    endif()
endfunction()

function(ww_add_private_cpu_compile_option target msvc_option non_msvc_option)
    if(MSVC)
        if(NOT "${msvc_option}" STREQUAL "")
            target_compile_options(${target} PRIVATE "${msvc_option}")
        endif()
    elseif(NOT "${non_msvc_option}" STREQUAL "")
        target_compile_options(${target} PRIVATE "${non_msvc_option}")
    endif()
endfunction()

if(WW_TARGET_X86_64 AND WW_HAS_X86_INTRINSICS AND NOT WW_DISABLE_ADVANCED_CPU_INSTRUCTIONS)

    message(STATUS "Using advanced CPU instructions")
    set(WW_HAVE_ADVANCED_CPU_INSTRUCTIONS 1)

    if(MSVC)
        # MSVC dosent have a specific flag for haswell, but we can enable AVX2 which includes all the instructions we need,
        # and MSVC will automatically enable the necessary instruction sets for AVX2
        # target_compile_options(ww PUBLIC /arch:AVX2)
    else()
        if(NOT WW_ADVANCED_CPU_BASELINE STREQUAL "")
            target_compile_options(ww PUBLIC "-march=${WW_ADVANCED_CPU_BASELINE}")
        endif()
        if(NOT WW_ADVANCED_CPU_EXTRA_FLAGS STREQUAL "")
            separate_arguments(WW_ADVANCED_CPU_EXTRA_FLAGS_LIST NATIVE_COMMAND "${WW_ADVANCED_CPU_EXTRA_FLAGS}")
            target_compile_options(ww PUBLIC ${WW_ADVANCED_CPU_EXTRA_FLAGS_LIST})
        endif()
        if(WW_AVX_DISABLED)
            target_compile_options(ww PUBLIC -mno-avx)
        endif()
        if(WW_AVX2_DISABLED)
            target_compile_options(ww PUBLIC -mno-avx2)
        endif()
    endif()
    
    if(MSVC)
        # For MSVC x64: SSE/SSE2/SSE3 are enabled by default, no /arch flag needed
        # x64 build - SSE3 is always available
        set(COMPILER_SUPPORTS_SSE3 TRUE)
        check_c_compiler_flag("/arch:AVX" COMPILER_SUPPORTS_AVX)
        check_c_compiler_flag("/arch:AVX2" COMPILER_SUPPORTS_AVX2)
        check_c_compiler_flag("/arch:AVX512" COMPILER_SUPPORTS_AVX512F)
    else()
        check_c_compiler_flag("-msse3" COMPILER_SUPPORTS_SSE3)
        check_c_compiler_flag("-mavx" COMPILER_SUPPORTS_AVX)
        check_c_compiler_flag("-mavx2" COMPILER_SUPPORTS_AVX2)
        check_c_compiler_flag("-mavx512f" COMPILER_SUPPORTS_AVX512F)
    endif()


    # SSE3 Configuration
    if(COMPILER_SUPPORTS_SSE3)
        message(STATUS "Using SSE3")
        ww_add_cpu_compile_option(ww "/arch:SSE2" "-msse3")
        set(WW_HAVE_SSE3 1)
        set(WW_CHECKSUM_SSE3 1)
        target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/net/wchecksum_sse3.c")
    else()
        message(FATAL_ERROR "SSE3 not supported by compiler")
    endif()

    # AVX Configuration
    # Plain AVX is enabled for the default (haswell) baseline. The x64 old-cpu build disables it
    # (and therefore AVX2/AVX512) via WW_DISABLE_AVX while still keeping SSE3 available.
    if(COMPILER_SUPPORTS_AVX)
        if(NOT WW_AVX_DISABLED)
            message(STATUS "Using AVX")
            ww_add_cpu_compile_option(ww "/arch:AVX" "-mavx")
            set(WW_HAVE_AVX 1)
        else()
            message(STATUS "AVX is disabled by configuration")
            # For MSVC, avoiding /arch:AVX is the available AVX codegen disable.
        endif()
    else()
        message(STATUS "AVX not supported by compiler")
    endif()

    # AVX2 Configuration
    if(COMPILER_SUPPORTS_AVX2)
        if(NOT WW_AVX2_DISABLED)
            message(STATUS "Using AVX2")
            ww_add_cpu_compile_option(ww "/arch:AVX2" "-mavx2")
            set(WW_HAVE_AVX2 1)
            set(WW_SUPPORTED_MEMCOPY_AVX2 1)
            set(WW_CHECKSUM_AVX2 1)
            target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/net/wchecksum_avx2.c")
        elseif(WW_AVX_DISABLED)
            message(STATUS "AVX2 is disabled because AVX is disabled")
        elseif(WW_DISABLE_AVX2)
            message(STATUS "AVX2 is disabled by configuration")
        else()
            message(STATUS "AVX2 is disabled by a dev flag")
            # For MSVC, avoiding /arch:AVX2 is the available AVX2 codegen disable.
        endif()

    else()
        message(STATUS "AVX2 not supported by compiler")
    endif()

    # AVX512F Configuration
    if(COMPILER_SUPPORTS_AVX512F)
        if(WW_ENABLE_AVX_512)
            message(STATUS "Using AVX512F")
            ww_add_cpu_compile_option(ww "/arch:AVX512" "-mavx512f")
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
set(WW_HAVE_AVX ${WW_HAVE_AVX} CACHE INTERNAL "AVX available" FORCE)
set(WW_HAVE_AVX2 ${WW_HAVE_AVX2} CACHE INTERNAL "AVX2 available" FORCE)
set(WW_HAVE_AVX512F ${WW_HAVE_AVX512F} CACHE INTERNAL "AVX512F available" FORCE)
set(WW_HAVE_SSE3 ${WW_HAVE_SSE3} CACHE INTERNAL "SSE3 available" FORCE)
set(WW_SUPPORTED_MEMCOPY_AVX2 ${WW_SUPPORTED_MEMCOPY_AVX2} CACHE INTERNAL "Enable MemoryCopyLarge() to use AVX2" FORCE)
set(WW_SUPPORTED_MEMCOPY_AVX512F ${WW_SUPPORTED_MEMCOPY_AVX512F} CACHE INTERNAL "Enable MemoryCopyLarge() to use AVX512F" FORCE)
set(WW_CHECKSUM_AVX2 ${WW_CHECKSUM_AVX2} CACHE INTERNAL "Enable Checksum() to use AVX2" FORCE)
set(WW_CHECKSUM_SSE3 ${WW_CHECKSUM_SSE3} CACHE INTERNAL "Enable Checksum() to use SSE3" FORCE)


################################################################################
# Crypto Backend Source Selection
################################################################################
if(WCRYPTO_BACKEND_OPENSSL)
    set(PROJECT_REQUIRES_OPENSSL TRUE CACHE INTERNAL "if any of the tunnels that require openssl is included, this will be set to true" FORCE)
endif()

set(WCRYPTO_OPENSSL_RUNTIME_REQUIRED ${PROJECT_REQUIRES_OPENSSL})

configure_file(
    crypto/private/crypto_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/private/crypto_config.h
)
target_include_directories(ww PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)

target_sources(ww PRIVATE
    crypto/aes256gcm.c
    crypto/blake2s.c
    crypto/chacha20poly1305.c
    crypto/compare.c
    crypto/crypto_validation.c
    crypto/global.c
    crypto/hash.c
    crypto/status.c
    crypto/x25519.c
    crypto/xchacha20poly1305.c
    crypto/impl_software/aes256gcm.c
    crypto/impl_software/blake2s.c
    crypto/impl_software/chacha20.c
    crypto/impl_software/chacha20poly1305.c
    crypto/impl_software/hash_md5_sha1.c
    crypto/impl_software/hash_sha2.c
    crypto/impl_software/poly1305.c
    crypto/impl_software/poly1305-donna.c
    crypto/impl_software/sha2.c
    crypto/impl_software/x25519.c
)
if(WCRYPTO_BACKEND_SODIUM)
    target_sources(ww PRIVATE
        crypto/sodium_instance.c
        crypto/impl_sodium/aes256gcm.c
        crypto/impl_sodium/chacha20poly1305.c
        crypto/impl_sodium/hash.c
        crypto/impl_sodium/xchacha20poly1305.c
        crypto/impl_sodium/x25519.c
    )
endif()

if(WCRYPTO_BACKEND_OPENSSL)
    target_sources(ww PRIVATE
        crypto/impl_openssl/aes256gcm.c
        crypto/impl_openssl/blake2s.c
        crypto/impl_openssl/chacha20poly1305.c
        crypto/impl_openssl/hash.c
        crypto/impl_openssl/xchacha20poly1305.c
        crypto/impl_openssl/x25519.c
    )
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set_source_files_properties(
        crypto/aes256gcm.c
        crypto/blake2s.c
        crypto/chacha20poly1305.c
        crypto/compare.c
        crypto/crypto_validation.c
        crypto/global.c
        crypto/hash.c
        crypto/status.c
        crypto/x25519.c
        crypto/xchacha20poly1305.c
        crypto/impl_software/aes256gcm.c
        crypto/impl_software/blake2s.c
        crypto/impl_software/chacha20.c
        crypto/impl_software/chacha20poly1305.c
        crypto/impl_software/hash_md5_sha1.c
        crypto/impl_software/hash_sha2.c
        crypto/impl_software/poly1305.c
        crypto/impl_software/poly1305-donna.c
        crypto/impl_software/sha2.c
        crypto/impl_software/x25519.c
        crypto/sodium_instance.c
        crypto/impl_sodium/aes256gcm.c
        crypto/impl_sodium/chacha20poly1305.c
        crypto/impl_sodium/hash.c
        crypto/impl_sodium/xchacha20poly1305.c
        crypto/impl_sodium/x25519.c
        crypto/openssl_instance.c
        crypto/impl_openssl/aes256gcm.c
        crypto/impl_openssl/blake2s.c
        crypto/impl_openssl/chacha20poly1305.c
        crypto/impl_openssl/hash.c
        crypto/impl_openssl/xchacha20poly1305.c
        crypto/impl_openssl/x25519.c
        PROPERTIES COMPILE_OPTIONS "-Wconversion;-Wsign-conversion"
    )
endif()

################################################################################
# Platform-specific Device Sources
################################################################################
if(APPLE)
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_sources(ww PRIVATE
            devices/tun/tun_darwin.c
            devices/tun/tun_loopguard_stub.c
        )
    else()
        message(STATUS "No Tun device support for this Apple platform")
    endif()

elseif(UNIX AND NOT ANDROID)
    target_sources(ww PRIVATE
        devices/tun/tun_linux.c
        devices/tun/tun_loopguard_stub.c
    )
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
            managers/windivert_manager.c
            devices/raw/raw_windows.c
            devices/capture/capture_windows.c
            devices/tun/tun_loopguard_windows.c
        )
    else()
        # No WinDivert on this Windows arch -> TUN loop-guard is a no-op.
        target_sources(ww PRIVATE devices/tun/tun_loopguard_stub.c)
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

        add_library(ww_wepoll OBJECT event/wepoll/wepoll.c)
        target_compile_features(ww_wepoll PRIVATE c_std_11)
        target_include_directories(ww_wepoll PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/libc
        )
        set_target_properties(ww_wepoll PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
        target_sources(ww PRIVATE $<TARGET_OBJECTS:ww_wepoll>)
        set_source_files_properties(
            event/wepoll/wepoll.c
            PROPERTIES
                SKIP_PRECOMPILE_HEADERS ON
                SKIP_UNITY_BUILD_INCLUSION ON
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
    GIT_TAG bf1d20e3dd903cde66c301587e017c4dd234a620
    DOWNLOAD_ONLY True
)
if(stc_ADDED)
    target_compile_definitions(ww PUBLIC STC_STATIC=1 STC_ALLOCATOR=c)
    target_include_directories(ww PUBLIC ${stc_SOURCE_DIR}/include)
    if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_compile_options(ww PUBLIC /wd4310)
    endif()
endif()

# Vendored iperf3 cJSON fork: cJSON::valueint is int64_t, unlike upstream cJSON.
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/cjson)
target_sources(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/vendor/cjson/cJSON.c)
target_compile_definitions(ww PUBLIC CJSON_HIDE_SYMBOLS)
target_compile_definitions(ww PUBLIC ENABLE_TARGET_EXPORT=OFF)

# C-Ares library
CPMAddPackage(
    NAME cares
    GIT_REPOSITORY https://github.com/c-ares/c-ares
    GIT_TAG v1.34.6
    OPTIONS
        "CARES_INSTALL OFF"
        "CARES_BUILD_TESTS OFF"
        "CARES_BUILD_TOOLS OFF"
        "CARES_SHARED OFF"
        "CARES_THREADS ON"
        "CARES_STATIC ON"
)

if(cares_ADDED)

    set(CARES_NO_UNUSED_RESULT_SOURCES
        src/lib/event/ares_event_wake_pipe.c
    )

    foreach(CARES_TARGET IN ITEMS c-ares c-ares_static)
        if(TARGET ${CARES_TARGET})
            set_target_properties(${CARES_TARGET} PROPERTIES UNITY_BUILD OFF)

            foreach(CARES_SOURCE IN LISTS CARES_NO_UNUSED_RESULT_SOURCES)
                set_source_files_properties(
                    "${cares_SOURCE_DIR}/${CARES_SOURCE}"
                    TARGET_DIRECTORY ${CARES_TARGET}
                    PROPERTIES
                        COMPILE_OPTIONS "$<$<COMPILE_LANG_AND_ID:C,GNU,Clang,AppleClang>:-Wno-unused-result>"
                )
            endforeach()
        endif()
    endforeach()

    set(LIBS ${LIBS} c-ares::cares_static)
else()
    message(FATAL_ERROR "c-ares was added by CPM, but no c-ares CMake target was created")
endif()

# nghttp2 library
if(PROJECT_REQUIRES_NGHTTP2)
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
    )

    if(NOT TARGET nghttp2_static)
        message(FATAL_ERROR "nghttp2 is required, but nghttp2_static was not created")
    endif()

    if(WW_HAVE_SSE3)
        ww_add_private_cpu_compile_option(nghttp2_static "/arch:SSE2" "-msse3")
    endif()

    if(WW_HAVE_AVX2)
        ww_add_private_cpu_compile_option(nghttp2_static "/arch:AVX2" "-mavx2")
    endif()

    set_target_properties(nghttp2_static PROPERTIES UNITY_BUILD_BATCH_SIZE 18)
endif()


# libmaxminddb library
CPMAddPackage(
    NAME maxminddb
    GITHUB_REPOSITORY maxmind/libmaxminddb
    GIT_TAG 1.13.3
    OPTIONS
        "BUILD_SHARED_LIBS OFF"
        "BUILD_TESTING OFF"
        "MAXMINDDB_BUILD_BINARIES OFF"
        "MAXMINDDB_INSTALL OFF"
)

if(TARGET maxminddb::maxminddb)
    list(APPEND LIBS maxminddb::maxminddb)
elseif(TARGET maxminddb)
    list(APPEND LIBS maxminddb)
else()
    message(FATAL_ERROR "libmaxminddb was added by CPM, but no maxminddb CMake target was created")
endif()


# LibSodium library
if(WCRYPTO_BACKEND_SODIUM)
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

    if(NOT TARGET sodium)
        message(FATAL_ERROR "libsodium backend is enabled, but the sodium target was not created")
    endif()

    if(NOT MSVC)
        target_compile_options(sodium PRIVATE -Wno-attributes)
    endif()

    list(APPEND LIBS sodium)
endif()



# Openssl Library
if(PROJECT_REQUIRES_OPENSSL)
    if(NOT TARGET OpenSSL::SSL OR NOT TARGET OpenSSL::Crypto)
        set(WW_OPENSSL_CONFIGURE_OPTIONS ${OPENSSL_CONFIGURE_OPTIONS})
        if(WW_OPENSSL_CONFIGURE_OPTIONS)
            list(REMOVE_DUPLICATES WW_OPENSSL_CONFIGURE_OPTIONS)
        endif()
        set(OPENSSL_CONFIGURE_OPTIONS ${WW_OPENSSL_CONFIGURE_OPTIONS})

        set(WW_OPENSSL_CPM_OPTIONS
            "BUILD_SHARED_LIBS OFF"
            "OPENSSL_TEST OFF"
            "OPENSSL_CONFIGURE_VERBOSE OFF"
            "OPENSSL_BUILD_VERBOSE TRUE"
            "OPENSSL_ENABLE_PARALLEL TRUE"
            "OPENSSL_CONFIGURE_VERBOSE TRUE"
        )

        if(MSVC)
            set(WW_WINDOWS_TARGET_PLATFORM "")

            if(CMAKE_VS_PLATFORM_NAME)
                set(WW_WINDOWS_TARGET_PLATFORM "${CMAKE_VS_PLATFORM_NAME}")
            elseif(CMAKE_GENERATOR_PLATFORM)
                set(WW_WINDOWS_TARGET_PLATFORM "${CMAKE_GENERATOR_PLATFORM}")
            elseif(CMAKE_SYSTEM_PROCESSOR)
                set(WW_WINDOWS_TARGET_PLATFORM "${CMAKE_SYSTEM_PROCESSOR}")
            endif()

            if(WW_WINDOWS_TARGET_PLATFORM STREQUAL "Win32"
               OR WW_WINDOWS_TARGET_PLATFORM STREQUAL "x86"
               OR WW_WINDOWS_TARGET_PLATFORM STREQUAL "i386")
                set(WW_OPENSSL_TARGET_PLATFORM VC-WIN32)
            elseif(WW_WINDOWS_TARGET_PLATFORM STREQUAL "x64"
                   OR WW_WINDOWS_TARGET_PLATFORM STREQUAL "AMD64"
                   OR WW_WINDOWS_TARGET_PLATFORM STREQUAL "x86_64")
                set(WW_OPENSSL_TARGET_PLATFORM VC-WIN64A)
            elseif(WW_WINDOWS_TARGET_PLATFORM STREQUAL "ARM")
                set(WW_OPENSSL_TARGET_PLATFORM VC-WIN32-ARM)
            elseif(WW_WINDOWS_TARGET_PLATFORM STREQUAL "ARM64"
                   OR WW_WINDOWS_TARGET_PLATFORM STREQUAL "aarch64")
                set(WW_OPENSSL_TARGET_PLATFORM VC-WIN64-ARM)
            endif()
        elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
            string(TOLOWER "${CMAKE_OSX_SYSROOT}" WW_IOS_SYSROOT_LOWER)

            if(WW_IOS_SYSROOT_LOWER MATCHES "iphonesimulator")
                set(WW_IOS_SIM_ARCHS "${CMAKE_OSX_ARCHITECTURES}")
                if(NOT WW_IOS_SIM_ARCHS)
                    set(WW_IOS_SIM_ARCHS "${CMAKE_HOST_SYSTEM_PROCESSOR}")
                endif()

                list(LENGTH WW_IOS_SIM_ARCHS WW_IOS_SIM_ARCH_COUNT)
                if(WW_IOS_SIM_ARCH_COUNT GREATER 1)
                    message(FATAL_ERROR
                        "The in-tree OpenSSL simulator build must use a single architecture. "
                        "Set CMAKE_OSX_ARCHITECTURES to either arm64 or x86_64 for ios_sim.")
                endif()

                list(GET WW_IOS_SIM_ARCHS 0 WW_IOS_SIM_ARCH)
                if(WW_IOS_SIM_ARCH STREQUAL "arm64" OR WW_IOS_SIM_ARCH STREQUAL "aarch64")
                    set(WW_OPENSSL_TARGET_PLATFORM iossimulator-arm64-xcrun)
                elseif(WW_IOS_SIM_ARCH STREQUAL "x86_64" OR WW_IOS_SIM_ARCH STREQUAL "AMD64")
                    set(WW_OPENSSL_TARGET_PLATFORM iossimulator-x86_64-xcrun)
                else()
                    message(FATAL_ERROR
                        "Unsupported iOS simulator architecture for OpenSSL: ${WW_IOS_SIM_ARCH}")
                endif()
            elseif(WW_IOS_SYSROOT_LOWER MATCHES "iphoneos")
                set(WW_OPENSSL_TARGET_PLATFORM ios64-xcrun)
            else()
                message(FATAL_ERROR
                    "Unsupported iOS SDK for OpenSSL: ${CMAKE_OSX_SYSROOT}. "
                    "Expected iphoneos or iphonesimulator.")
            endif()
        elseif(ANDROID)
            if(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
                set(WW_OPENSSL_TARGET_PLATFORM android-arm)
            elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
                set(WW_OPENSSL_TARGET_PLATFORM android-arm64)
            elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
                set(WW_OPENSSL_TARGET_PLATFORM android-x86)
            elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
                set(WW_OPENSSL_TARGET_PLATFORM android-x86_64)
            endif()
        elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
                set(WW_OPENSSL_TARGET_PLATFORM linux-aarch64)
            endif()
        endif()

        if(DEFINED WW_OPENSSL_TARGET_PLATFORM)
            set(OPENSSL_TARGET_PLATFORM "${WW_OPENSSL_TARGET_PLATFORM}")
            message(STATUS "OpenSSL target platform: ${WW_OPENSSL_TARGET_PLATFORM}")
            list(APPEND WW_OPENSSL_CPM_OPTIONS
                "OPENSSL_TARGET_PLATFORM ${WW_OPENSSL_TARGET_PLATFORM}"
            )
        endif()

        # openssl-cmake chooses the OpenSSL Configure target, but it does not
        # automatically inherit CMake's cross-compiler/binutils selection.
        # Export the active toolchain for cross-builds, except for iOS xcrun
        # targets where OpenSSL's target already selects the correct SDK.
        set(WW_OPENSSL_PREV_ENV_CC "$ENV{CC}")
        set(WW_OPENSSL_PREV_ENV_CXX "$ENV{CXX}")
        set(WW_OPENSSL_PREV_ENV_AR "$ENV{AR}")
        set(WW_OPENSSL_PREV_ENV_RANLIB "$ENV{RANLIB}")

        set(WW_OPENSSL_USE_CMAKE_TOOLCHAIN_ENV TRUE)
        if(CMAKE_SYSTEM_NAME STREQUAL "iOS" AND WW_OPENSSL_TARGET_PLATFORM MATCHES "-xcrun$")
            set(WW_OPENSSL_USE_CMAKE_TOOLCHAIN_ENV FALSE)
            unset(ENV{CC})
            unset(ENV{CXX})
        endif()

        if(WW_OPENSSL_USE_CMAKE_TOOLCHAIN_ENV AND CMAKE_C_COMPILER)
            set(ENV{CC} "${CMAKE_C_COMPILER}")
        endif()
        if(WW_OPENSSL_USE_CMAKE_TOOLCHAIN_ENV AND CMAKE_CXX_COMPILER)
            set(ENV{CXX} "${CMAKE_CXX_COMPILER}")
        endif()
        if(WW_OPENSSL_USE_CMAKE_TOOLCHAIN_ENV AND CMAKE_AR)
            set(ENV{AR} "${CMAKE_AR}")
        endif()
        if(WW_OPENSSL_USE_CMAKE_TOOLCHAIN_ENV AND CMAKE_RANLIB)
            set(ENV{RANLIB} "${CMAKE_RANLIB}")
        endif()

        # add openssl (default version is latest 3.3.0 +)
        CPMAddPackage(
            NAME openssl-cmake
            URL https://github.com/jimmy-park/openssl-cmake/archive/main.tar.gz
            OPTIONS
            ${WW_OPENSSL_CPM_OPTIONS}
        )

        set(ENV{CC} "${WW_OPENSSL_PREV_ENV_CC}")
        set(ENV{CXX} "${WW_OPENSSL_PREV_ENV_CXX}")
        set(ENV{AR} "${WW_OPENSSL_PREV_ENV_AR}")
        set(ENV{RANLIB} "${WW_OPENSSL_PREV_ENV_RANLIB}")
    endif()

    if(NOT TARGET OpenSSL::SSL OR NOT TARGET OpenSSL::Crypto)
        message(FATAL_ERROR "OpenSSL backend is enabled, but OpenSSL::SSL/OpenSSL::Crypto were not created")
    endif()

    # openssl-cmake's Makefile parser in some rolling `main` revisions loses
    # both archive paths when it is embedded as a subproject.  Keep fresh
    # backend-matrix build trees usable while the dependency remains unpinned.
    get_target_property(WW_OPENSSL_SSL_LOCATION OpenSSL::SSL IMPORTED_LOCATION)
    if(UNIX AND (NOT WW_OPENSSL_SSL_LOCATION OR
                 WW_OPENSSL_SSL_LOCATION MATCHES "-NOTFOUND$"))
        set(WW_OPENSSL_BUILD_DIR "${CMAKE_BINARY_DIR}/_deps/openssl-source-build")
        set(OPENSSL_CRYPTO_LIBRARY
            "${WW_OPENSSL_BUILD_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}crypto${CMAKE_STATIC_LIBRARY_SUFFIX}"
            CACHE STRING "Override FindOpenSSL variables" FORCE)
        set(OPENSSL_SSL_LIBRARY
            "${WW_OPENSSL_BUILD_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}ssl${CMAKE_STATIC_LIBRARY_SUFFIX}"
            CACHE STRING "Override FindOpenSSL variables" FORCE)
        set_target_properties(OpenSSL::Crypto PROPERTIES
            IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
        )
        set_target_properties(OpenSSL::SSL PROPERTIES
            IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
        )

        find_program(WW_OPENSSL_MAKE_EXECUTABLE NAMES gmake make REQUIRED)
        add_custom_command(
            OUTPUT "${OPENSSL_CRYPTO_LIBRARY}"
            COMMAND "${WW_OPENSSL_MAKE_EXECUTABLE}" -j4 build_libs
            WORKING_DIRECTORY "${WW_OPENSSL_BUILD_DIR}"
            VERBATIM
        )
        add_custom_target(ww-openssl-build-workaround
            DEPENDS "${OPENSSL_CRYPTO_LIBRARY}"
        )
        add_dependencies(ww-openssl-build-workaround openssl-build)
        add_dependencies(OpenSSL::Crypto ww-openssl-build-workaround)
        add_dependencies(OpenSSL::SSL ww-openssl-build-workaround)
    endif()

    list(APPEND LIBS OpenSSL::SSL OpenSSL::Crypto)
    if(TARGET OpenSSL::applink)
        list(APPEND LIBS OpenSSL::applink)
    endif()

    target_sources(ww PRIVATE 
        crypto/openssl_instance.c
    )
endif()

# libuuid library
set(LIBUUID_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libuuid)

set(LIBUUID_SOURCES
    ${LIBUUID_DIR}/unparse.c
    ${LIBUUID_DIR}/unpack.c
    ${LIBUUID_DIR}/pack.c
    ${LIBUUID_DIR}/parse.c
    ${LIBUUID_DIR}/isnull.c
    ${LIBUUID_DIR}/copy.c
    ${LIBUUID_DIR}/clear.c
    ${LIBUUID_DIR}/compare.c
)

if(WIN32)
    list(APPEND LIBUUID_SOURCES
        ${LIBUUID_DIR}/windows_uuid.c
    )
else()
    list(APPEND LIBUUID_SOURCES
        ${LIBUUID_DIR}/gen_uuid.c
        ${LIBUUID_DIR}/randutils.c
        ${LIBUUID_DIR}/uuid_time.c
    )
endif()

add_library(libuuid OBJECT
    ${LIBUUID_SOURCES}
)

target_include_directories(libuuid
    PRIVATE
        ${LIBUUID_DIR}
    PUBLIC
        ${LIBUUID_DIR}/include
)

target_compile_definitions(libuuid
    PRIVATE
        $<$<BOOL:${HAVE_FCNTL_H}>:HAVE_FCNTL_H=1>
        $<$<BOOL:${HAVE_FTRUNCATE}>:HAVE_FTRUNCATE=1>
        $<$<BOOL:${HAVE_GETTIMEOFDAY}>:HAVE_GETTIMEOFDAY=1>
        $<$<BOOL:${HAVE_INTTYPES_H}>:HAVE_INTTYPES_H=1>
        $<$<BOOL:${HAVE_LIMITS_H}>:HAVE_LIMITS_H=1>
        $<$<BOOL:${HAVE_MEMSET}>:HAVE_MEMSET=1>
        $<$<BOOL:${HAVE_NETINET_IN_H}>:HAVE_NETINET_IN_H=1>
        $<$<BOOL:${HAVE_SOCKET}>:HAVE_SOCKET=1>
        $<$<BOOL:${HAVE_SRANDOM}>:HAVE_SRANDOM=1>
        $<$<BOOL:${HAVE_STDINT_H}>:HAVE_STDINT_H=1>
        $<$<BOOL:${HAVE_STDLIB_H}>:HAVE_STDLIB_H=1>
        $<$<BOOL:${HAVE_STRING_H}>:HAVE_STRING_H=1>
        $<$<BOOL:${HAVE_STRTOUL}>:HAVE_STRTOUL=1>
        $<$<BOOL:${HAVE_SYS_FILE_H}>:HAVE_SYS_FILE_H=1>
        $<$<BOOL:${HAVE_SYS_IOCTL_H}>:HAVE_SYS_IOCTL_H=1>
        $<$<BOOL:${HAVE_SYS_SOCKET_H}>:HAVE_SYS_SOCKET_H=1>
        $<$<BOOL:${HAVE_SYS_STAT_H}>:HAVE_SYS_STAT_H=1>
        $<$<BOOL:${HAVE_SYS_TIME_H}>:HAVE_SYS_TIME_H=1>
        $<$<BOOL:${HAVE_SYS_TYPES_H}>:HAVE_SYS_TYPES_H=1>
        $<$<BOOL:${HAVE_UNISTD_H}>:HAVE_UNISTD_H=1>
        $<$<BOOL:${HAVE_USLEEP}>:HAVE_USLEEP=1>
)

if(WIN32)
    target_compile_definitions(libuuid PRIVATE
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0600
    )
    target_link_libraries(libuuid PUBLIC rpcrt4 bcrypt)
elseif(UNIX)
    target_compile_definitions(libuuid PRIVATE _DEFAULT_SOURCE)
endif()

set_target_properties(libuuid PROPERTIES UNITY_BUILD OFF)

set(LIBS ${LIBS} libuuid)


################################################################################
# LWIP Library Configuration
################################################################################
# updating lwip may cause our patching to fail or be incorrect. check with
# https://github.com/heiher/lwip
CPMAddPackage(
    NAME lwip
    GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
    GIT_TAG STABLE-2_2_1_RELEASE
    DOWNLOAD_ONLY True
)
if(NOT lwip_ADDED)
    message(FATAL_ERROR "LWIP library could not be downloaded")
endif()

set(LWIP_ORIGINAL_DIR ${lwip_SOURCE_DIR})
set(LWIP_DIR ${CMAKE_BINARY_DIR}/patched-deps/lwip)
set(LWIP_PATCH_STAMP ${LWIP_DIR}/.waterwall-pretend-patch)
if(NOT EXISTS ${LWIP_PATCH_STAMP} OR ${CMAKE_CURRENT_SOURCE_DIR}/lwip/pretend_patch.cmake IS_NEWER_THAN ${LWIP_PATCH_STAMP})
    file(REMOVE_RECURSE ${LWIP_DIR})
    file(MAKE_DIRECTORY ${LWIP_DIR})
    file(COPY ${LWIP_ORIGINAL_DIR}/ DESTINATION ${LWIP_DIR} PATTERN ".git" EXCLUDE)
    include(${CMAKE_CURRENT_SOURCE_DIR}/lwip/pretend_patch.cmake)
    ww_apply_lwip_pretend_patch(${LWIP_DIR})
    file(WRITE ${LWIP_PATCH_STAMP} "patched\n")
endif()

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
if(WW_HAVE_ADVANCED_CPU_INSTRUCTIONS AND WW_HAVE_AVX2)
    set(MI_OPT_ARCH 1)
    set(MI_OPT_SIMD 1)
else()
    set(MI_OPT_ARCH 0)
    set(MI_OPT_SIMD 0)
endif()
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

# Architecture definitions
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WW_IS_64_BIT 1)
    target_compile_definitions(ww PUBLIC WW_COMPILE_FOR_64BIT=1 WW_COMPILE_FOR_32BIT=0)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(WW_IS_64_BIT 0)
    target_compile_definitions(ww PUBLIC WW_COMPILE_FOR_64BIT=0 WW_COMPILE_FOR_32BIT=1)
else()
    message(FATAL_ERROR "Unknown pointer size")
endif()

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


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h)
message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

# Build type definitions
target_compile_definitions(ww PUBLIC 
    $<$<CONFIG:Debug>:DEBUG=1>
    $<$<CONFIG:RelWithDebInfo>:RELEASEWITHDEBUGINFO=1>
    $<$<CONFIG:Release>:NDEBUG=1;RELEASE=1>
)

# CMake's default RelWithDebInfo flags define NDEBUG. Undefine it after those
# flags so assert() remains active in release-with-debug builds.
if(MSVC)
    target_compile_options(ww PUBLIC $<$<CONFIG:RelWithDebInfo>:/UNDEBUG>)
else()
    target_compile_options(ww PUBLIC $<$<CONFIG:RelWithDebInfo>:-UNDEBUG>)
endif()

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
if(TARGET sodium)
    set_target_properties(sodium PROPERTIES UNITY_BUILD OFF)
endif()
# set_target_properties(ww_lwip PROPERTIES UNITY_BUILD_BATCH_SIZE 16)
set_target_properties(ww PROPERTIES UNITY_BUILD_BATCH_SIZE 500)

set_source_files_properties(
    devices/capture/capture_linux.c
    devices/raw/raw_linux.c
    devices/raw/raw_windows.c
    devices/capture/capture_windows.c
    base/wlsem.c
    # Failure-injection tests compile these sources directly. Keep their
    # production objects separate so extracting ww's Unity object does not
    # define the same symbols a second time.
    instance/global_state.c
    objects/user.c
    PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON
)

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
        target_compile_options(ww PUBLIC -fno-ms-compatibility -Wno-shorten-64-to-32)
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
