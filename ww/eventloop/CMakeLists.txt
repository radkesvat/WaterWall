
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


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/hconfig.h.in ${CMAKE_CURRENT_SOURCE_DIR}/hconfig.h)

# see Makefile.in
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(INCDIR include)
set(SRCDIR src)
set(LIBDIR lib)
set(BINDIR bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${LIBDIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${LIBDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${BINDIR})
message(STATUS "CMAKE_LIBRARY_OUTPUT_DIRECTORY=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

set(INCDIRS . include 3rd/include)
set(LIBDIRS . lib 3rd/lib)
include_directories(${INCDIRS} ${SRCDIR})
link_directories(${LIBDIRS})

message(STATUS "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_definitions(-DDEBUG)
else()
    add_definitions(-DNDEBUG)
endif()

if(ENABLE_UDS)
    add_definitions(-DENABLE_UDS)
endif()

if(USE_MULTIMAP)
    add_definitions(-DUSE_MULTIMAP)
endif()

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0600)
    set(LIBS ${LIBS} secur32 crypt32 winmm iphlpapi ws2_32)
    if(ENABLE_WINDUMP)
        add_definitions(-DENABLE_WINDUMP)
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

# see Makefile
set(ALL_SRCDIRS . base ssl event  util cpputil evpp protocol http http/client http/server mqtt)
set(CORE_SRCDIRS . base ssl event)
if(WIN32)
    if(WITH_WEPOLL)
        set(CORE_SRCDIRS ${CORE_SRCDIRS} event/wepoll)
    endif()
endif()

set(LIBHV_SRCDIRS ${CORE_SRCDIRS} util)
set(LIBHV_HEADERS hv.h hconfig.h hexport.h)
set(LIBHV_HEADERS ${LIBHV_HEADERS} ${BASE_HEADERS} ${SSL_HEADERS} ${EVENT_HEADERS} ${UTIL_HEADERS})

if(WITH_PROTOCOL)
    set(LIBHV_HEADERS ${LIBHV_HEADERS} ${PROTOCOL_HEADERS})
    set(LIBHV_SRCDIRS ${LIBHV_SRCDIRS} protocol)
endif()


if(WITH_MQTT)
    set(LIBHV_HEADERS ${LIBHV_HEADERS} ${MQTT_HEADERS})
    set(LIBHV_SRCDIRS ${LIBHV_SRCDIRS} mqtt)
endif()

list_source_directories(LIBHV_SRCS ${LIBHV_SRCDIRS})

# file(INSTALL ${LIBHV_HEADERS} DESTINATION include/hv)
# file(INSTALL ${LIBHV_HEADERS} DESTINATION ${PROJECT_SOURCE_DIR}/include/hv)

# if(BUILD_SHARED)
#     add_library(hv SHARED ${LIBHV_SRCS})
#     target_compile_definitions(hv PRIVATE HV_DYNAMICLIB)
#     target_include_directories(hv PRIVATE ${LIBHV_SRCDIRS}
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
#     add_library(hv_static STATIC ${LIBHV_SRCS})
#     target_compile_definitions(hv_static PUBLIC HV_STATICLIB)
#     target_include_directories(hv_static PRIVATE ${LIBHV_SRCDIRS}
#         INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
#     target_link_libraries(hv_static ${LIBS})
#     install(TARGETS hv_static
#         EXPORT libhvConfig
#         ARCHIVE DESTINATION lib)
#     add_custom_target(libhv_static DEPENDS hv_static)
# endif()

# install(FILES ${LIBHV_HEADERS} DESTINATION include/hv)
# install(EXPORT libhvConfig DESTINATION lib/cmake/libhv)

# if(BUILD_SHARED)
#     set(HV_LIBRARIES hv CACHE INTERNAL "link hv libraries")
# else()
#     add_definitions(-DHV_STATICLIB)
#     set(HV_LIBRARIES hv_static ${LIBS} CACHE INTERNAL "link hv libraries")
# endif()

target_compile_definitions(ww PUBLIC HV_STATICLIB)
target_include_directories(ww PUBLIC ${LIBHV_SRCDIRS}
        INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(ww PUBLIC ${LIBS})
target_sources(ww PRIVATE ${LIBHV_SRCS})
