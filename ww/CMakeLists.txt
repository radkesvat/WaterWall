set(WW_VERSION_MAJOR 1)
set(WW_VERSION_MINOR 1)
set(WW_VERSION_PATCH 0)

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
    crypto/openssl_instance.c
    crypto/chacha20poly1305.c
    crypto/sodium_instance.c
    crypto/blake2s.c
    crypto/x25519.c
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

# Enforce C11 for this specific target
set_target_properties(ww 
    PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)

# Platform-specific sources
if(LINUX OR ANDROID)
    target_sources(ww PRIVATE devices/tun/tun_linux.c)
    # target_sources(ww PRIVATE devices/raw/raw_linux.c)
    # target_sources(ww PRIVATE devices/capture/capture_linux.c)
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
    message(FATAL_ERROR  "Cannot Bind WinTun -> Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

    target_sources(ww PRIVATE devices/tun/tun_windows.c)
    # target_sources(ww PRIVATE devices/raw/raw_windows.c)
    # target_sources(ww PRIVATE devices/capture/capture_windows.c)
elseif(APPLE)
    message(STATUS "No Tun device for MacOS yet")

    # target_sources(ww PRIVATE devices/tun/tun_darwin.c)
    # target_sources(ww PRIVATE devices/raw/raw_darwin.c)
    # target_sources(ww PRIVATE devices/capture/capture_darwin.c)
endif()


if(WIN32)
    set(WITH_WEPOLL 1)
    if(WITH_WEPOLL)
        target_include_directories(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/event/wepoll)
        target_sources(ww PRIVATE event/wepoll/wepoll.c)
    endif()
endif()

# Include directories
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

# Add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

option(ASMLIB_OVERRIDE "try to link against asm lib and override standard functions" OFF)
option(WW_STATICLIB "ON -> statil library ; OFF-> dynamic" OFF)

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
    GIT_TAG HEAD
    DOWNLOAD_ONLY True
)

if(stc_ADDED)
    target_include_directories(ww PUBLIC ${stc_SOURCE_DIR}/include)
    if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_compile_options(ww PUBLIC /wd4310) # stc bug, hash -> cast trucncates constant value TODO fix in stc
    endif()
    # target_sources(ww PRIVATE ${stc_SOURCE_DIR}/src/libstc.c)
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

set(OPENSSL_CONFIGURE_VERBOSE FALSE)

# add openssl (default version is latest 3.3.0 +)
CPMAddPackage(
    NAME openssl-cmake
    URL https://github.com/radkesvat/openssl-cmake/archive/main.tar.gz
    OPTIONS
    "OPENSSL_CONFIGURE_OPTIONS no-shared\\\\;no-tests"
    "BUILD_SHARED_LIBS OFF"
)

set(LIBS ${LIBS} OpenSSL::SSL)
set(LIBS ${LIBS} OpenSSL::Crypto)
set(LIBS ${LIBS} OpenSSL::applink)

# Add libsodium as a static library
CPMAddPackage(
    NAME libsodium
    GITHUB_REPOSITORY robinlinden/libsodium-cmake
    GIT_TAG HEAD
    OPTIONS
        "SODIUM_MINIMAL ON"          # Minimal build
        "SODIUM_DISABLE_TESTS ON"    # Disable tests
        "BUILD_SHARED_LIBS OFF"      # Disable shared library generation
        "SODIUM_BUILD_TESTS OFF"     # Disable tests
        "SODIUM_BUILD_EXAMPLES OFF"  # Disable examples
        "SODIUM_BUILD_SHARED OFF"    # Disable shared library build
        "SODIUM_STATIC ON"           # Enable static library build
)
set(LIBS ${LIBS} sodium)


# Add LWIP library
set(WPDPACK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/lwip/WpdPack)
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/lwip)
set(LWIPOPTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)
set(LWIP_CONTRIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip/contrib)

set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib"
    "${LWIPOPTS_DIR}"
    # lwipopts is located in ww/net
)

if(NOT DARWIN)
    target_compile_definitions(ww PUBLIC LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS=1)
endif()

if(ANDROID)
    set (LWIP_DEFINITIONS SOCKLEN_T_DEFINED=1)
endif()


if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    set (LWIP_DEFINITIONS SOCKLEN_T_DEFINED=1)
endif()

if(WIN32)
    set (LWIP_INCLUDE_DIRS ${LWIP_INCLUDE_DIRS} "${LWIP_CONTRIB_DIR}/ports/win32/include")
    target_compile_definitions(ww PUBLIC LWIP_NO_UNISTD_H=1)
else()
    set (LWIP_INCLUDE_DIRS ${LWIP_INCLUDE_DIRS} "${LWIP_CONTRIB_DIR}/ports/unix/port/include")
endif()


include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_CONTRIB_DIR}/Filelists.cmake)

target_include_directories(ww PUBLIC ${LWIP_INCLUDE_DIRS})

set(LIBS ${LIBS} lwipcore)

# Add mimalloc library

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/mimalloc)

set(LIBS ${LIBS} mimalloc-static)


# Platform-specific options and settings
if(WIN32)
    option(WITH_WEPOLL "compile event/wepoll -> use iocp" ON)
    option(ENABLE_WINDUMP "Windows MiniDumpWriteDump" OFF)
endif()

message(STATUS "CMAKE_SOURCE_DIR=${CMAKE_SOURCE_DIR}")
message(STATUS "CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}")

if(IOS)
    set(BUILD_SHARED OFF)
    set(BUILD_EXAMPLES OFF)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}")
include(utils)
include(vars)

# Checks for header files
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

# Checks for functions
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

# Configure file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h)

message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

if(LINUX AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

    target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)
    if(CMAKE_BUILD_TYPE STREQUAL "Release" AND ASMLIB_OVERRIDE)
        
        # The override method sometimes fails to call the asmlib function because the compiler uses
        # built-in inline codes for some common functions rather than calling a library. The built-in
        # codes are not optimal on modern microprocessors. Use option -fno-builtin 
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-builtin-function")  
        set(CMAKE_EXE_LINKER_FLAGS "-L${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib -laelf64o" CACHE INTERNAL "calculated linker flags, the order is important")
    else()
        target_link_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)
        set(LIBS ${LIBS} mimalloc-static)
    endif()

endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

    target_compile_definitions(ww PUBLIC WW_AVX=1)
    target_compile_options(ww PUBLIC -mavx)

endif()



if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    target_compile_definitions(ww PUBLIC DEBUG=1)
else()
    target_compile_definitions(ww PUBLIC NDEBUG=1)
endif()

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
    set(LIBS ${LIBS} secur32 crypt32 winmm iphlpapi ws2_32)
    if(ENABLE_WINDUMP)
        target_compile_definitions(ww PUBLIC -DENABLE_WINDUMP)
        set(LIBS ${LIBS} dbghelp)
    endif()
endif()

if(ANDROID)
    set(LIBS ${LIBS} log)
elseif(UNIX)
    set(LIBS ${LIBS} pthread m dl)
    if(CMAKE_COMPILER_IS_GNUCC)
        set(LIBS ${LIBS} rt)
    endif()
endif()

if(APPLE)
    set(LIBS ${LIBS} "-framework CoreFoundation" "-framework Security")
endif()

target_link_libraries(ww PUBLIC ${LIBS})

# Link options for Release build
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(ww PUBLIC -s)
endif()

# Link options for Debug build
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(ww PUBLIC DEBUG=1 ALLOCATOR_BYPASS=1 BYPASS_BUFFERPOOL=1 BYPASS_GENERIC_POOL=1)

endif()



# Enable sanitizers for non-Release builds
if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    if(ENABLE_ASAN)
        target_compile_options(ww PUBLIC -fsanitize=address)
        target_link_options(ww PUBLIC -fsanitize=address)
    endif()

    if(ENABLE_TSAN)
        target_compile_options(ww PUBLIC -fsanitize=thread)
        target_link_options(ww PUBLIC -fsanitize=thread)
    endif()

    if(ENABLE_LSAN)
        target_compile_options(ww PUBLIC -fsanitize=leak)
        target_link_options(ww PUBLIC -fsanitize=leak)
    endif()

    if(ENABLE_USAN)
        target_compile_options(ww PUBLIC -fsanitize=undefined)
        target_link_options(ww PUBLIC -fsanitize=undefined)
    endif()
endif()


# clang-tidy dose not like this even if cc = gcc
# if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
# target_compile_options(ww PUBLIC -ftrack-macro-expansion=0)
# endif()





# Compiler-specific options
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
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

        -Wno-unused-function
        -Wno-unknown-pragmas
    )

endif()

if(MSVC)
    target_compile_options(ww PUBLIC 
        /W4
        /WX
    )

endif()

target_compile_definitions(ww PUBLIC STC_STATIC=1 WW_VERSION=0.1)





