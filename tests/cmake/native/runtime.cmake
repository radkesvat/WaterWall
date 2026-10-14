# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET ww)
  if(LINUX)
    foreach(backend IN ITEMS mimalloc bypass)
      if(backend STREQUAL "bypass")
        set(memory_test_target memory_allocation_bypass_test)
        set(memory_test_name waterwall.memory_allocation_bypass_unit)
        set(memory_test_bypass 1)
        set(memory_test_wraps malloc calloc realloc free)
      else()
        set(memory_test_target memory_allocation_test)
        set(memory_test_name waterwall.memory_allocation_unit)
        set(memory_test_bypass 0)
        set(memory_test_wraps mi_malloc mi_calloc mi_realloc mi_free)
      endif()
      waterwall_add_native_executable(${memory_test_target} SUPPORT
        SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/base/memory_allocation_test.c
        DEFINITIONS WW_TEST_ALLOCATOR_BYPASS=${memory_test_bypass}
        LIBRARIES ww)
      foreach(symbol IN LISTS memory_test_wraps)
        target_link_options(${memory_test_target} PRIVATE "-Wl,--wrap=${symbol}")
      endforeach()
      add_waterwall_unit_test(${memory_test_name} ${memory_test_target} "unit;memory;allocation;failure")
    endforeach()

    waterwall_add_native_executable(wio_fd_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/event/wio_fd_test.c)
  target_link_libraries(wio_fd_test PRIVATE ww_test_support)
    target_link_libraries(wio_fd_test PRIVATE ww)
    target_link_options(wio_fd_test PRIVATE "-Wl,--wrap=pipe2" "-Wl,--wrap=read" "-Wl,--wrap=send" "-Wl,--wrap=splice"
        "-Wl,--wrap=memoryReAllocate" "-Wl,--wrap=fcntl"
        "-Wl,--wrap=sbufSpliceIsReusable" "-Wl,--wrap=ioctl" "-Wl,--wrap=tcpSocketPeerHasWriteShutdown")
    add_dependencies(waterwall_unit_tests wio_fd_test)
    add_waterwall_unit_test(waterwall.wio_fd_unit wio_fd_test "unit;event;fd;pipe;lifetime")

    waterwall_add_native_executable(wio_fd_no_splice_test SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/net/event/wio_fd_test.c ${CMAKE_SOURCE_DIR}/ww/event/wevent.c
        ${CMAKE_SOURCE_DIR}/ww/event/nio.c ${CMAKE_SOURCE_DIR}/ww/bufio/shiftbuffer.c
        ${CMAKE_SOURCE_DIR}/ww/bufio/splice_buffer.c)
  target_link_libraries(wio_fd_no_splice_test PRIVATE ww_test_support)
    target_compile_definitions(wio_fd_no_splice_test PRIVATE WW_HAVE_SPLICE=0)
    target_link_libraries(wio_fd_no_splice_test PRIVATE ww)
    target_link_options(wio_fd_no_splice_test PRIVATE "-Wl,--wrap=ioctl" "-Wl,--wrap=tcpSocketPeerHasWriteShutdown")
    add_dependencies(waterwall_unit_tests wio_fd_no_splice_test)
    add_waterwall_unit_test(waterwall.wio_fd_no_splice_unit wio_fd_no_splice_test "unit;event;fd;lifetime")
  endif()

  include("${CMAKE_SOURCE_DIR}/tests/cmake/native/runtime-restricted_config.cmake")
  include("${CMAKE_SOURCE_DIR}/tests/cmake/native/runtime-system_load_semantics.cmake")
  include("${CMAKE_SOURCE_DIR}/tests/cmake/native/runtime-address_context.cmake")
endif()

