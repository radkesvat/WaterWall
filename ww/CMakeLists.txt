################################################################################
# Version Settings
################################################################################
set(WW_VERSION_MAJOR 1)
set(WW_VERSION_MINOR 1)
set(WW_VERSION_PATCH 0)


################################################################################
# Library Build Configuration
################################################################################
add_library(ww STATIC
    libc/wlibc.c
    libc/wtime.c
    libc/werr.c
    libc/wfrand.c
    base/wchan.c
    base/widle_table.c
    base/wlog.c
    base/wlsem.c
    base/wsocket.c
    base/wsysinfo.c
    base/wproc.c
    bufio/buffer_pool.c
    bufio/buffer_stream.c
    bufio/context_queue.c
    bufio/buffer_queue.c
    bufio/generic_pool.c
    bufio/master_pool.c
    bufio/shiftbuffer.c
    utils/base64.c
    utils/cacert.c
    utils/md5.c
    utils/sha1.c
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
    instance/global_state.c
    instance/worker.c
    instance/wversion.c
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
    lwip/ww_lwip.c
    node_builder/config_file.c
    node_builder/node_library.c
    managers/signal_manager.c
    managers/socket_manager.c
    managers/node_manager.c
    managers/memory_manager.c
    managers/data/iprange_mci.c
    managers/data/iprange_irancell.c
    managers/data/iprange_mokhaberat.c
    managers/data/iprange_rightel.c
    managers/data/iprange_iran.c
    loggers/core_logger.c
    loggers/network_logger.c
    loggers/dns_logger.c
    loggers/internal_logger.c
)

################################################################################
# Target Properties & Platform-specific Sources
################################################################################
# Enforce C11 for this specific target
set_target_properties(ww 
    PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)



################################################################################
# Global Options & Definitions
################################################################################
option(WW_STATICLIB "ON -> static library ; OFF-> dynamic" ON)

option(ASMLIB_OVERRIDE "try to link against asm lib and override standard functions" OFF)


# Crypto backend options
option(WCRYPTO_BACKEND_SODIUM "Enable Sodium backend" ON)
option(WCRYPTO_BACKEND_OPENSSL "Enable OpenSSL backend" OFF)
option(WCRYPTO_BACKEND_SOFTWARE "Enable Software backend" OFF)

if(NOT DEFINED FINAL_EXECUTABLE_NAME OR MY_VARIABLE STREQUAL "")
    message(FATAL_ERROR "Error: FINAL_EXECUTABLE_NAME is not set! Please define FINAL_EXECUTABLE_NAME before configuring.")
endif()

if(WIN32)
    option(WITH_WEPOLL "compile event/wepoll -> use iocp" ON)
    option(ENABLE_WINDUMP "Windows MiniDumpWriteDump" OFF)
    target_compile_definitions(ww PUBLIC FINAL_EXECUTABLE_NAME="${FINAL_EXECUTABLE_NAME}.exe")
else()
    target_compile_definitions(ww PUBLIC FINAL_EXECUTABLE_NAME="${FINAL_EXECUTABLE_NAME}")
endif()



################################################################################
# Crypto Backend Source Selection
################################################################################
# Ensure only one backend is selected
if(WCRYPTO_BACKEND_SODIUM)
    set(WCRYPTO_BACKEND_OPENSSL OFF CACHE BOOL "Enable OpenSSL backend" FORCE)
    set(WCRYPTO_BACKEND_SOFTWARE OFF CACHE BOOL "Enable Software backend" FORCE)
    
    target_sources(ww PRIVATE crypto/sodium_instance.c)
    target_sources(ww PRIVATE crypto/impl_sodium/chacha20poly1305.c)
    target_sources(ww PRIVATE crypto/impl_sodium/xchacha20poly1305.c)
    target_sources(ww PRIVATE crypto/impl_sodium/x25519.c)
    target_sources(ww PRIVATE crypto/impl_software/blake2s.c)
    
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_SODIUM=1)
elseif(WCRYPTO_BACKEND_OPENSSL)
    set(WCRYPTO_BACKEND_SODIUM OFF CACHE BOOL "Enable Sodium backend" FORCE)
    set(WCRYPTO_BACKEND_SOFTWARE OFF CACHE BOOL "Enable Software backend" FORCE)
    
    target_sources(ww PRIVATE crypto/openssl_instance.c)
    target_sources(ww PRIVATE crypto/impl_openssl/blake2s.c)
    target_sources(ww PRIVATE crypto/impl_openssl/chacha20poly1305.c)
    target_sources(ww PRIVATE crypto/impl_openssl/x25519.c)
    
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_OPENSSL=1)
elseif(WCRYPTO_BACKEND_SOFTWARE)
    set(WCRYPTO_BACKEND_SODIUM OFF CACHE BOOL "Enable Sodium backend" FORCE)
    set(WCRYPTO_BACKEND_OPENSSL OFF CACHE BOOL "Enable OpenSSL backend" FORCE)
    
    target_sources(ww PRIVATE crypto/impl_software/blake2s.c)
    target_sources(ww PRIVATE crypto/impl_software/chacha20.c)
    target_sources(ww PRIVATE crypto/impl_software/chacha20poly1305.c)
    target_sources(ww PRIVATE crypto/impl_software/poly1305.c)
    target_sources(ww PRIVATE crypto/impl_software/poly1305-donna.c)
    target_sources(ww PRIVATE crypto/impl_software/x25519.c)
    
    target_compile_definitions(ww PUBLIC WCRYPTO_BACKEND_SOFTWARE=1)
endif()



# Platform-specific sources
if(APPLE)
    message(STATUS "No Tun device for This os yet")
elseif(UNIX AND NOT ANDROID)
    target_sources(ww PRIVATE devices/tun/tun_linux.c)
    if(LINUX)
        target_sources(ww PRIVATE devices/capture/capture_linux.c)
        target_sources(ww PRIVATE devices/raw/raw_linux.c)
    endif()
elseif(WIN32)

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        message(STATUS "Including WinDivert Target architecture: amd64")
        target_sources(ww PRIVATE vendor/windivert/x64/windivert.dll.x64.bytes.c)
        target_sources(ww PRIVATE vendor/windivert/x64/windivert.sys.x64.bytes.c)

        target_sources(ww PRIVATE devices/raw/raw_windows.c)
        target_sources(ww PRIVATE devices/capture/capture_windows.c)

    endif()


    target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/wintun/)

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        message(STATUS "Including WinTun Target architecture: amd64")
        target_sources(ww PRIVATE vendor/wintun/amd64/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i386")
        message(STATUS "Including WinTun Target architecture: x86")
        target_sources(ww PRIVATE vendor/wintun/x86/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM")
        message(STATUS "Including WinTun Target architecture: arm")
        target_sources(ww PRIVATE vendor/wintun/arm/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        message(STATUS "Including WinTun Target architecture: arm64")
        target_sources(ww PRIVATE vendor/wintun/arm64/wintun_bytes.c)
    else()
        message(FATAL_ERROR "Cannot Bind WinTun -> Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    
    target_sources(ww PRIVATE devices/tun/tun_windows.c)


endif()

if(WIN32)
    set(WITH_WEPOLL 1)
    if(WITH_WEPOLL)
        target_include_directories(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/event/wepoll)
        target_sources(ww PRIVATE event/wepoll/wepoll.c)
    endif()
endif()


################################################################################
# Include Directories
################################################################################
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/base)
target_include_directories(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/base/internal_types)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/node_builder)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bufio)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/event)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/net)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/instance)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libc)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/crypto)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)


################################################################################
# External Dependencies
################################################################################
# include(cmake/GetCPM.cmake)
include(cmake/CPM.cmake)

set(BUILD_SHARED_LIBS OFF)

# Add komihash library
CPMAddPackage(
    NAME komihash
    GIT_REPOSITORY https://github.com/avaneev/komihash.git
    GIT_TAG 5.10
    DOWNLOAD_ONLY True
)
if(komihash_ADDED)
    target_include_directories(ww PUBLIC ${komihash_SOURCE_DIR})
endif()

# Add STC library
CPMAddPackage(
    NAME stc
    GIT_REPOSITORY https://github.com/radkesvat/STC
    GIT_TAG d367e5403a27cde2dc64fbd34293fcbc60f5669f
    DOWNLOAD_ONLY True
)
if(stc_ADDED)
    target_include_directories(ww PUBLIC ${stc_SOURCE_DIR}/include)
    if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_compile_options(ww PUBLIC /wd4310) # stc bug, hash -> cast truncates constant value
    endif()
endif()

# Add cJSON library
CPMAddPackage(
    NAME cjson
    VERSION 1.7.17
    GITHUB_REPOSITORY DaveGamble/cJSON
    DOWNLOAD_ONLY True
)
if(cjson_ADDED)
    target_include_directories(ww PUBLIC ${cjson_SOURCE_DIR})
    target_sources(ww PRIVATE ${cjson_SOURCE_DIR}/cJSON.c)
endif()
target_compile_definitions(ww PRIVATE ENABLE_TARGET_EXPORT=OFF) # Disable export of cJSON symbols


# add openssl (default version is latest)
# CPMAddPackage(
#     NAME openssl-cmake
#     URL https://github.com/radkesvat/openssl-cmake/archive/main.tar.gz
#     OPTIONS
#     "OPENSSL_CONFIGURE_OPTIONS no-shared\\\\;no-tests"
#     "BUILD_SHARED_LIBS OFF"
#     "OPENSSL_CONFIGURE_VERBOSE OFF"
#     "OPENSSL_BUILD_VERBOSE TRUE"
# )
# set(LIBS ${LIBS} OpenSSL::SSL)
# set(LIBS ${LIBS} OpenSSL::Crypto)
# set(LIBS ${LIBS} OpenSSL::applink)

# Add libsodium as a static library
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
# LWIP Library Settings
################################################################################
CPMAddPackage(
    NAME lwip
    GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
    GIT_TAG STABLE-2_2_1_RELEASE
    DOWNLOAD_ONLY True
)
if(NOT lwip_ADDED)
    message(FATAL_ERROR "Error: LWIP library could not be downloaded")
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
add_library(ww_lwip STATIC 
    ${lwipnoapps_SRCS}
)


target_compile_definitions(ww_lwip PUBLIC $<$<CONFIG:Debug>:LWIP_DEBUG=1>)
target_include_directories(ww_lwip PUBLIC ${LWIP_INCLUDE_DIRS})
target_compile_definitions(ww_lwip PUBLIC ${LWIP_DEFINITIONS})
if(UNIX)
    target_sources(ww_lwip PRIVATE ${LWIP_CONTRIB_DIR}/ports/unix/port/sys_arch.c)
else()
    target_sources(ww_lwip PRIVATE ${LWIP_CONTRIB_DIR}/ports/win32/sys_arch.c)
endif()

if(NOT MSVC AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS} -Wno-stringop-overread -Wno-stringop-overflow)
endif()

target_compile_options(ww_lwip PRIVATE ${LWIP_COMPILER_FLAGS})
set(LIBS ${LIBS} ww_lwip)


################################################################################
# Mimalloc & Platform-specific Options
################################################################################
# Add mimalloc library
# if(ANDROID OR (WIN32 AND MINGW AND CMAKE_SIZEOF_VOID_P EQUAL 4))
    # set(MI_OPT_ARCH OFF)
# endif()

set(MI_USE_CXX ON) # since we enabled c++ for waterwall

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/mimalloc)

if(NOT MSVC)        
    target_compile_options(mimalloc-static PRIVATE -Wno-attributes -Wno-array-bounds)
    if(MI_USE_CXX)
        target_compile_options(mimalloc-static PRIVATE -Wno-missing-field-initializers)
    endif()
endif()

set(LIBS ${LIBS} mimalloc-static)
# Platform-specific options and settings
# message(STATUS "CMAKE_SOURCE_DIR=${CMAKE_SOURCE_DIR}")
# message(STATUS "CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")
include(utils)
include(vars)


################################################################################
# Header and Function Checks
################################################################################
# Header checks
check_header("stdbool.h")
check_header("stdint.h")
check_header("stdatomic.h")
check_header("sys/types.h")
check_header("sys/stat.h")
check_header("sys/time.h")
check_header("fcntl.h")
check_header("pthread.h")
check_header("endian.h")
check_header("sys/endian.h")
check_header("x86intrin.h")

# Function checks
if(NOT MSVC)
    set(CMAKE_REQUIRED_LIBRARIES "-pthread")
endif()
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

include(CheckCCompilerFlag)

check_c_compiler_flag("-msse3" COMPILER_SUPPORTS_SSE3)
check_c_compiler_flag("-mavx2" COMPILER_SUPPORTS_AVX2)
check_c_compiler_flag("-mavx512f" COMPILER_SUPPORTS_AVX512F)

################################################################################
# AVX/SSE3 Checksum and Memory Copy Configuration
################################################################################
set(WW_HAVE_AVX2 0)
set(WW_HAVE_SSE3 0)
set(WW_SUPPORTED_MEMCOPY_AVX2 0)
set(WW_SUPPORTED_MEMCOPY_AVX512F 0)
set(WW_CHECKSUM_AVX2 0)
set(WW_CHECKSUM_SSE3 0)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" 
    AND HAVE_X86INTRIN_H AND NOT DISABLE_AVX AND CMAKE_SIZEOF_VOID_P EQUAL 8)

    
    if(COMPILER_SUPPORTS_SSE3)
        message(STATUS "Compiler supports SSE3")
        target_compile_options(ww PUBLIC -msse3)
        set(WW_HAVE_SSE3 1)
        set(WW_CHECKSUM_SSE3 1)
        target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/net/wchecksum_sse3.c")
    else()
        message(FATAL_ERROR "SSE3 not supported by compiler")
    endif()

    if(COMPILER_SUPPORTS_AVX2)
        message(STATUS "Compiler supports AVX2")
        target_compile_options(ww PUBLIC -mavx2)
        set(WW_HAVE_AVX2 1)
        set(WW_SUPPORTED_MEMCOPY_AVX2 1)
        set(WW_CHECKSUM_AVX2 1)
        target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/net/wchecksum_avx2.c")
    else()
        message(STATUS "AVX2 not supported by compiler")
    endif()

    
    if(COMPILER_SUPPORTS_AVX512F)
        message(STATUS "Compiler supports AVX512F")
        if(WW_ENABLE_AVX_512)
            message(STATUS "Using AVX512F code...")
            target_compile_options(ww PUBLIC -mavx512f)
            set(WW_HAVE_AVX512F 1)
            set(WW_SUPPORTED_MEMCOPY_AVX512F 1)
        else()
            message(STATUS "AVX512F is power consuming and is disabled by default")
            message(STATUS "We are currently not using AVX512F code until the user enables it")
        endif()
        
    else()
        message(STATUS "AVX512F not supported by compiler")
    endif()



    # if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" AND (WIN32 OR LINUX))
    #     MESSAGE(STATUS "Including amd64 checksum assembly code")
    #     target_compile_definitions(ww PUBLIC WW_COMPILE_CHECKSUM_ASSEMBLY=1)
    #     target_sources(ww PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/libc/checksum_amd64.s")
    # else()
    #     MESSAGE(STATUS "using C implementation of checksum")
    #     target_compile_definitions(ww PUBLIC WW_COMPILE_CHECKSUM_ASSEMBLY=0)
    # endif()

else()
    message(STATUS "AVX not supported by compiler")
endif()

################################################################################
# Configuration and Linking
################################################################################
# Configure file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h)
message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

if(LINUX AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)
    if(CMAKE_BUILD_TYPE STREQUAL "Release" AND ASMLIB_OVERRIDE)
        # Disable built-in inline functions for optimal performance
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-builtin-function")  
        set(CMAKE_EXE_LINKER_FLAGS "-L${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib -laelf64o" CACHE INTERNAL "calculated linker flags, the order is important")
    else()
        target_link_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)
    endif()
endif()


target_compile_definitions(ww PUBLIC 
    $<$<CONFIG:Debug>:DEBUG=1>
    $<$<CONFIG:RelWithDebInfo>:NDEBUG=1;RELEASEWITHDEBUGINFO=1>
    $<$<CONFIG:Release>:NDEBUG=1;RELEASE=1>
)

if(ENABLE_UDS)
    target_compile_definitions(ww PUBLIC ENABLE_UDS)
endif()
if(WW_STATICLIB)
    target_compile_definitions(ww PUBLIC WW_STATICLIB)
else()
    target_compile_definitions(ww PUBLIC WW_DYNAMICLIB)
endif()

if(WIN32)
    target_compile_definitions(ww PUBLIC -DWIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0600)
    set(LIBS ${LIBS} secur32 crypt32 winmm ntdll iphlpapi ws2_32 pdh)
    if(ENABLE_WINDUMP)
        target_compile_definitions(ww PUBLIC ENABLE_WINDUMP)
        set(LIBS ${LIBS} dbghelp)
    endif()
endif()

if(ANDROID)
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

# this code will make valgrind output clean, it frees c++ exception handler allocated memory
# only useful for development and debugging
if(NOT MSVC)
    # Try to compile freeres_wrap.cc to check if it's supported on this platform
    # We use CMAKE_TRY_COMPILE_TARGET_TYPE to compile as STATIC_LIBRARY instead of executable
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    try_compile(FREERES_WRAP_COMPILES
        ${CMAKE_CURRENT_BINARY_DIR}/test_freeres_wrap
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/freeres_wrap.cc
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        OUTPUT_VARIABLE FREERES_WRAP_OUTPUT
    )
    # Reset to default behavior for other try_compile calls
    unset(CMAKE_TRY_COMPILE_TARGET_TYPE)
    
    if(FREERES_WRAP_COMPILES)
        message(STATUS "freeres_wrap.cc compilation test passed - including FREERS_EH library")
        add_library(FREERS_EH OBJECT 
            utils/freeres_wrap.cc
        )
        target_compile_definitions(ww PRIVATE WW_CALL_GNU_FREES)
        set(LIBS ${LIBS} "FREERS_EH")
    else()
        # message(STATUS "freeres_wrap.cc compilation test failed - skipping FREERS_EH")
        # message(STATUS "Compilation output: ${FREERES_WRAP_OUTPUT}")
        # Also check the detailed log file
        # if(EXISTS "${CMAKE_BINARY_DIR}/CMakeFiles/CMakeOutput.log")
        #     message(STATUS "Check CMakeFiles/CMakeOutput.log for detailed try_compile logs")
        # endif()
        # if(EXISTS "${CMAKE_BINARY_DIR}/CMakeFiles/CMakeError.log")
        #     message(STATUS "Check CMakeFiles/CMakeError.log for detailed error logs")
        # endif()
    endif()
endif()

target_link_libraries(ww PUBLIC ${LIBS})
target_link_options(ww PUBLIC $<$<CONFIG:Release>:-s>)



# Sanitizer options (using generator expressions for multiconfig)
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
# Final Compiler-specific Options
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

    # prevent defining _MSC_VER
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        target_compile_options(ww PUBLIC -fno-ms-compatibility)
    endif()

    # Suppress unused command-line argument warnings for ASM compilation on Clang
    # This prevents -D flags and -pedantic from causing errors when assembling .s files
    target_compile_options(ww PRIVATE $<$<AND:$<COMPILE_LANGUAGE:ASM>,$<C_COMPILER_ID:Clang>>:-Wno-unused-command-line-argument>)

endif()

if(APPLE)
    target_compile_options(ww PRIVATE -Wno-shorten-64-to-32 -Wno-unused-command-line-argument)
    # Disable precompiled headers on Apple platforms due to clang issues with C/C++ mixed compilation
    set_target_properties(ww PROPERTIES DISABLE_PRECOMPILE_HEADERS ON)
endif()

if(MSVC)
    target_compile_options(ww PUBLIC 
        /W4
        /WX
        /wd4505 # unreferenced local function has been removed (unused function warning)
    )
endif()


if(NOT APPLE)
    target_precompile_headers(ww PUBLIC "wwapi.h")
endif()

target_compile_definitions(ww PUBLIC STC_STATIC=1 WW_VERSION=${WW_VERSION_MAJOR}.${WW_VERSION_MINOR}.${WW_VERSION_PATCH})

