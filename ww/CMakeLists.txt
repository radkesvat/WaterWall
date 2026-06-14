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
    net/adapter.c
    net/tunnel.c
    net/line.c
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
        # MSVC dosent have a specific flag for haswell, but we can enable AVX2 which includes all the instructions we need,
        # and MSVC will automatically enable the necessary instruction sets for AVX2
        # target_compile_options(ww PUBLIC /arch:AVX2)
    else()
        # GCC/Clang: target Haswell microarchitecture
        target_compile_options(ww PUBLIC -march=haswell)
    endif()
    # with "haswell" target, we already have AVX
    

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
        if(NOT DEV_DISABLE_AVX)
            message(STATUS "Using AVX2")
            if(MSVC)
                #/arch:AVX2    # enables AVX2 (+ AVX)
                target_compile_options(ww PUBLIC /arch:AVX2)
            else()
                target_compile_options(ww PUBLIC -mavx2)
            endif()
            set(WW_HAVE_AVX2 1)
            set(WW_SUPPORTED_MEMCOPY_AVX2 1)
            set(WW_CHECKSUM_AVX2 1)
            target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/net/wchecksum_avx2.c")
        else()
            message(STATUS "AVX is disabled by a dev flag")
            if(NOT MSVC)
                target_compile_options(ww PUBLIC -mno-avx2 -mno-avx -mno-fma)
            endif()
            # for MSVC, there's no specific flag to disable AVX2, when we dont specify /arch:AVX2,
            # it will not use AVX2 and AVX instructions, so we can just avoid adding that flag
        endif()

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
        crypto/impl_sodium/aes256gcm.c
        crypto/impl_sodium/chacha20poly1305.c
        crypto/impl_sodium/hash.c
        crypto/impl_sodium/xchacha20poly1305.c
        crypto/impl_sodium/x25519.c
        crypto/impl_software/blake2s.c
        crypto/impl_software/hash_md5_sha1.c
    )
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_SODIUM=1)
    
elseif(WCRYPTO_BACKEND_OPENSSL)
    set(WCRYPTO_BACKEND_SODIUM OFF CACHE BOOL "Enable Sodium backend" FORCE)
    set(WCRYPTO_BACKEND_SOFTWARE OFF CACHE BOOL "Enable Software backend" FORCE)
    
    set(PROJECT_REQUIRERS_OPENSSL TRUE CACHE INTERNAL "if any of the tunnels that require openssl is included, this will be set to true" FORCE)


    target_sources(ww PRIVATE 
        crypto/imp_openssl/aes256gcm.c
        crypto/imp_openssl/blake2s.c
        crypto/imp_openssl/chacha20poly1305.c
        crypto/imp_openssl/hash.c
        crypto/imp_openssl/xchacha20poly1305.c
        crypto/imp_openssl/x25519.c
        crypto/impl_software/chacha20.c
    )
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_OPENSSL=1)
    
elseif(WCRYPTO_BACKEND_SOFTWARE)
    set(WCRYPTO_BACKEND_SODIUM OFF CACHE BOOL "Enable Sodium backend" FORCE)
    set(WCRYPTO_BACKEND_OPENSSL OFF CACHE BOOL "Enable OpenSSL backend" FORCE)
    
    target_sources(ww PRIVATE 
        crypto/impl_software/aes256gcm.c
        crypto/impl_software/blake2s.c
        crypto/impl_software/chacha20.c
        crypto/impl_software/chacha20poly1305.c
        crypto/impl_software/hash_md5_sha1.c
        crypto/impl_software/hash_unsupported.c
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
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_sources(ww PRIVATE devices/tun/tun_darwin.c)
    else()
        message(STATUS "No Tun device support for this Apple platform")
    endif()
    
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



# Openssl Library
if(PROJECT_REQUIRERS_OPENSSL)
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

    list(APPEND LIBS OpenSSL::SSL OpenSSL::Crypto)
    if(TARGET OpenSSL::applink)
        list(APPEND LIBS OpenSSL::applink)
    endif()

    target_sources(ww PRIVATE 
        crypto/openssl_instance.c
    )
    target_compile_definitions(ww PUBLIC WCRYPTO_USING_OPENSSL=1)
    
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
set_target_properties(sodium PROPERTIES UNITY_BUILD OFF)
# set_target_properties(ww_lwip PROPERTIES UNITY_BUILD_BATCH_SIZE 16)
set_target_properties(ww PROPERTIES UNITY_BUILD_BATCH_SIZE 500)

set_source_files_properties(
    devices/capture/capture_linux.c
    devices/raw/raw_linux.c
    devices/raw/raw_windows.c
    devices/capture/capture_windows.c
    base/wlsem.c
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
