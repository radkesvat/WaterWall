

add_library(ww STATIC
                  ww.c
                  tunnel.c
                  shiftbuffer.c
                  library_loader.c
                  context_queue.c
                  buffer_stream.c
                  config_file.c
                  buffer_pool.c
                  generic_pool.c
                  http_def.c
                  cacert.c
                  sync_dns.c
                  idle_table.c
                  frand.c
                  pipe_line.c
                  utils/utils.c
                  utils/btree.c
                  managers/socket_manager.c
                  managers/node_manager.c
                  managers/alloc-engine/wof_allocator.c
                  managers/memory_manager.c
                  managers/data/iprange_mci.c
                  managers/data/iprange_irancell.c
                  managers/data/iprange_mokhaberat.c
                  managers/data/iprange_rightel.c
                  managers/data/iprange_iran.c
                  loggers/core_logger.c
                  loggers/network_logger.c
                  loggers/dns_logger.c

)

target_include_directories(ww PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

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


# add libhv
set(WITH_OPENSSL OFF CACHE BOOL "libhv without openssl binding")
set(WITH_EVPP OFF CACHE BOOL "libhv no c++ eventpool")
set(WITH_HTTP OFF CACHE BOOL "libhv no http")
set(WITH_HTTP_SERVER OFF CACHE BOOL "ibhv no http server")
set(WITH_HTTP_CLIENT OFF CACHE BOOL "lbhv no http client")
set(BUILD_SHARED OFF CACHE BOOL "ibhv no shared lib")
set(BUILD_EXAMPLES OFF CACHE BOOL "ibhv dont build examples")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/eventloop)


# add lwip
set(WPDPACK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip/WpdPack)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lwip)



if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  message( FATAL_ERROR
   "MSVC compiler is not supported, because WW relies on <stdatomic.h>"
   "on windows you can still use GCC or CLANG to compile."
   )
endif()

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

# disabled warnings: only unused functions
target_compile_options(ww PUBLIC -Wno-unused-function)

target_compile_definitions(ww PUBLIC STC_STATIC=1 WW_VERSION=0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(ww PUBLIC DEBUG=1)
endif()

