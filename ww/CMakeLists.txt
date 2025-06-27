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
    base/wthread.c
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
    net/line.c
    net/packet_tunnel.c
    net/pipe_tunnel.c
    net/sync_dns.c
    net/adapter.c
    net/tunnel.c
    net/chain.c
    net/context.c
    net/socket_filter_option.c
    lwip/ww_lwip.c
    node_builder/config_file.c
    node_builder/node_loader.c
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
# Global Options & Definitions
################################################################################
option(WW_STATICLIB "ON -> statil library ; OFF-> dynamic" OFF)

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

# Platform-specific sources
if(APPLE)
    message(STATUS "No Tun device for This os yet")
elseif(UNIX AND NOT ANDROID)
    target_sources(ww PRIVATE devices/tun/tun_linux.c)
    if(LINUX)
        target_sources(ww PRIVATE devices/capture/capture_linux.c)
        target_sources(ww PRIVATE devices/raw/raw_linux.c)
    endif()
    # ...existing commented raw/capture devices...
elseif(WIN32)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        message(STATUS "Including WinTun Target architecture: amd64")
        target_sources(ww PRIVATE devices/tun/wintun/amd64/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i386")
        message(STATUS "Including WinTun Target architecture: x86")
        target_sources(ww PRIVATE devices/tun/wintun/x86/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM")
        message(STATUS "Including WinTun Target architecture: arm")
        target_sources(ww PRIVATE devices/tun/wintun/arm/wintun_bytes.c)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        message(STATUS "Including WinTun Target architecture: arm64")
        target_sources(ww PRIVATE devices/tun/wintun/arm64/wintun_bytes.c)
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
    GIT_TAG 45f264db9d282719d192bf4f541bd6ea48142aef
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
    OPTIONS "BUILD_SHARED_LIBS OFF" "BUILD_SHARED_AND_STATIC_LIBS On"
    DOWNLOAD_ONLY True
)
if(cjson_ADDED)
    target_include_directories(ww PUBLIC ${cjson_SOURCE_DIR})
    target_sources(ww PRIVATE ${cjson_SOURCE_DIR}/cJSON.c)
endif()

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
    target_compile_definitions(ww PUBLIC )
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

if(NOT MSVC)        
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
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/mimalloc)

if(NOT MSVC)        
    target_compile_options(mimalloc-static PRIVATE -Wno-attributes -Wno-array-bounds)
endif()

set(LIBS ${LIBS} mimalloc-static)
# Platform-specific options and settings
message(STATUS "CMAKE_SOURCE_DIR=${CMAKE_SOURCE_DIR}")
message(STATUS "CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}")
if(IOS)
    set(BUILD_SHARED OFF)
    set(BUILD_EXAMPLES OFF)
endif()
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


if(HAVE_X86INTRIN_H)
    target_compile_options(ww PUBLIC -mavx)
    set(WW_SUPPORTED_MEM128_OPTIMIZE 1)
else()
    set(WW_SUPPORTED_MEM128_OPTIMIZE 0)
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
        set(LIBS ${LIBS} mimalloc-static)
    endif()
endif()




target_compile_definitions(ww PUBLIC 
    $<$<CONFIG:Debug>:DEBUG=1>
    $<$<CONFIG:RelWithDebInfo>:NDEBUG=1;RELEASEWITHDEBUGINFO=1>
    $<$<CONFIG:Release>:NDEBUG=1;RELEASE=1>
)

if(ENABLE_UDS)
    target_compile_definitions(ww PUBLIC -DENABLE_UDS)
endif()
if(USE_MULTIMAP)
    target_compile_definitions(ww PUBLIC -DUSE_MULTIMAP)
endif()
if(WW_STATICLIB)
    target_compile_definitions(ww PUBLIC -DWW_STATICLIB)
else()
    target_compile_definitions(ww PUBLIC -DWW_DYNAMICLIB)
endif()

if(WIN32)
    target_compile_definitions(ww PUBLIC -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0600)
    set(LIBS ${LIBS} secur32 crypt32 winmm ntdll iphlpapi ws2_32 pdh)
    if(ENABLE_WINDUMP)
        target_compile_definitions(ww PUBLIC -DENABLE_WINDUMP)
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

target_link_libraries(ww PUBLIC ${LIBS})
target_link_options(ww PUBLIC $<$<CONFIG:Release>:-s>)

# Sanitizer options (using generator expressions for multiconfig):
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
# Sanitizer and Compiler-specific Options
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
endif()
if(APPLE)
    target_compile_options(ww PRIVATE -Wno-shorten-64-to-32)
endif()
if(MSVC)
    target_compile_options(ww PUBLIC 
        /W4
        /WX
    )
endif()

target_compile_definitions(ww PUBLIC STC_STATIC=1 WW_VERSION=0.1)





