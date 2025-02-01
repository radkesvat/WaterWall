

set(WW_VERSION_MAJOR    1)
set(WW_VERSION_MINOR    1)
set(WW_VERSION_PATCH    0)

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

                  bufio/buffer_pool.c
                  bufio/buffer_stream.c
                  bufio/context_queue.c
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
                  net/pipe_tunnel.c
                  net/sync_dns.c
                  net/tunnel.c
                  net/chain.c
                  net/context.c

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

if(LINUX)
  target_sources(ww PRIVATE devices/tun/tun_linux.c)
  target_sources(ww PRIVATE devices/raw/raw_linux.c)
  target_sources(ww PRIVATE devices/capture/capture_linux.c)
endif()


if(WIN32)
    set(WITH_WEPOLL    1)

    if(WITH_WEPOLL)
      target_include_directories(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/event/wepoll)
      target_sources(ww PRIVATE event/wepoll/wepoll.c)
    endif()
    target_link_libraries(ww PUBLIC ws2_32)
endif()


target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/base)
target_include_directories(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/base/internal_types)
target_include_directories(ww PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/node_builder)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bufio)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/event)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/net)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/instance)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libc)
target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/asmlib)



# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

option(ASMLIB_OVERRIDE "try to link against asm lib and override standard functions"  OFF)


CPMAddPackage(
  NAME komihash
  GIT_REPOSITORY https://github.com/avaneev/komihash.git
  GIT_TAG 5.10
  DOWNLOAD_ONLY True
)

if(komihash_ADDED)
  target_include_directories(ww PUBLIC ${komihash_SOURCE_DIR})
endif()

CPMAddPackage(
  NAME stc
  GIT_REPOSITORY https://github.com/radkesvat/STC
  GIT_TAG HEAD
  DOWNLOAD_ONLY True
)

if(stc_ADDED)
  target_include_directories(ww PUBLIC ${stc_SOURCE_DIR}/include)
  # target_sources(ww PRIVATE ${stc_SOURCE_DIR}/src/libstc.c)

endif()

# add cJson
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

set(WPDPACK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/lwip/WpdPack)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/mimalloc)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/vendor/lwip)


target_link_libraries(ww PUBLIC mimalloc-static)


# event



if(WIN32)
    option(WITH_WEPOLL "compile event/wepoll -> use iocp" ON)
    option(ENABLE_WINDUMP "Windows MiniDumpWriteDump" OFF)
    option(BUILD_FOR_MT "build for /MT" OFF)
    if(BUILD_FOR_MT)
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
    endif()
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

# see configure
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


# order is important beacuse  cmakedefine is usedin .in file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/wconfig.h)



message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  target_compile_definitions(ww PUBLIC DDEBUG=1)
else()
  target_compile_definitions(ww PUBLIC DNDEBUG=1)
endif()

if(ENABLE_UDS)
  target_compile_definitions(ww PRIVATE -DENABLE_UDS)
endif()

if(USE_MULTIMAP)
  target_compile_definitions(ww PRIVATE -DUSE_MULTIMAP)
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


# file(INSTALL ${LIBWW_HEADERS} DESTINATION include/hv)
# file(INSTALL ${LIBWW_HEADERS} DESTINATION ${PROJECT_SOURCE_DIR}/include/hv)

# if(BUILD_SHARED)
#     add_library(hv SHARED ${LIBWW_SRCS})
#     target_compile_definitions(hv PRIVATE WW_DYNAMICLIB)
#     target_include_directories(hv PRIVATE ${LIBWW_SRCDIRS}
#         INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
#     target_link_libraries(hv ${LIBS})
#     install(TARGETS hv
#         EXPORT libhvConfig
#         ARCHIVE DESTINATION lib
#         LIBRARY DESTINATION lib
#         RUNTIME DESTINATION bin)
#     add_custom_target(libhv DEPENDS hv)
# endif()

# if(BUILD_STATIC)
#     add_library(hv_static STATIC ${LIBWW_SRCS})
#     target_compile_definitions(hv_static PUBLIC WW_STATICLIB)
#     target_include_directories(hv_static PRIVATE ${LIBWW_SRCDIRS}
#         INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
#     target_link_libraries(hv_static ${LIBS})
#     install(TARGETS hv_static
#         EXPORT libhvConfig
#         ARCHIVE DESTINATION lib)
#     add_custom_target(libhv_static DEPENDS hv_static)
# endif()

# install(FILES ${LIBWW_HEADERS} DESTINATION include/hv)
# install(EXPORT libhvConfig DESTINATION lib/cmake/libhv)

# if(BUILD_SHARED)
#     set(WW_LIBRARIES hv CACHE INTERNAL "link hv libraries")
# else()
#     add_definitions(-DWW_STATICLIB)
#     set(WW_LIBRARIES hv_static ${LIBS} CACHE INTERNAL "link hv libraries")
# endif()

target_compile_definitions(ww PUBLIC WW_STATICLIB)
































# if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
#   message( FATAL_ERROR
#    "MSVC compiler is not supported"
#    "on windows you can still use GCC or CLANG to compile."
#    )
# endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_link_options(ww PUBLIC -s)
  if (WIN32)
    target_link_options(ww PUBLIC -static-libgcc -static)
  endif()
endif()

# target_compile_options(hv_static PRIVATE -fPIC) 
# target_compile_options(ww PUBLIC -fPIC)  
# message( FATAL_ERROR "OEUOUEOU: ${CMAKE_INSTALL_PREFIX}" )

# target_compile_options(ww PUBLIC -pg)
# target_link_options(ww PUBLIC -pg)

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


if(LINUX AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

  target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/asmlib)
  if(CMAKE_BUILD_TYPE STREQUAL "Release" AND ASMLIB_OVERRIDE)
      
    # The override method sometimes fails to call the asmlib function because the compiler uses
    # built-in inline codes for some common functions rather than calling a library. The built-in
    # codes are not optimal on modern microprocessors. Use option -fno-builtin 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-builtin-function")  
    set(CMAKE_EXE_LINKER_FLAGS "-L${CMAKE_CURRENT_SOURCE_DIR}/asmlib -laelf64o" CACHE INTERNAL "calculated linker flags, the order is important")
  
  else()

    target_link_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/asmlib)
    target_link_libraries(ww PUBLIC aelf64)

  endif()

endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")

target_compile_definitions(ww PUBLIC WW_AVX=1)
target_compile_options(ww PUBLIC -mavx)

endif()

if (NOT CMAKE_CXX_COMPILER_ID  STREQUAL "MSVC")


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
                                  # -Wcast-align    todo (fix code to enable this if possible...)

)
target_compile_options(ww PUBLIC -Wno-unused-function)

endif()

# Ensure MSVC uses C11
# if (MSVC)
#     target_compile_options(ww  PUBLIC /std:c11)
# endif()


# disabled warnings: only unused functions

target_compile_definitions(ww PUBLIC STC_STATIC=1 WW_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(ww PUBLIC DEBUG=1 ALLOCATOR_BYPASS=1 BYPASS_BUFFERPOOL=1 BYPASS_GENERIC_POOL=1)
endif()

