# Explicit native registrations; included in dependency order by unittests/CMakeLists.txt.
if(TARGET StreamFragmenter AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_CROSSCOMPILING)
  foreach(variant IN ITEMS normal no_splice)
    set(sf_test streamfragmenter_${variant}_test)
    waterwall_add_native_executable(${sf_test} SUPPORT SOURCES ${WATERWALL_UNIT_SOURCE_ROOT}/tunnels/streamfragmenter/streamfragmenter_test.c)
    if(variant STREQUAL "no_splice")
      get_target_property(sf_sources StreamFragmenter SOURCES)
      list(TRANSFORM sf_sources PREPEND "${CMAKE_SOURCE_DIR}/tunnels/Internals/StreamFragmenter/")
      target_sources(${sf_test} PRIVATE ${sf_sources})
      target_include_directories(${sf_test} PRIVATE
        ${CMAKE_SOURCE_DIR}/tunnels/Internals/StreamFragmenter/include
        ${CMAKE_SOURCE_DIR}/tunnels/Internals/StreamFragmenter/include/StreamFragmenter)
      target_compile_definitions(${sf_test} PRIVATE WW_HAVE_SPLICE=0)
    else()
      target_link_libraries(${sf_test} PRIVATE StreamFragmenter)
    endif()
    target_link_options(${sf_test} PRIVATE "-Wl,--wrap=getHRTimeUs" "-Wl,--wrap=wtimerAdd"
      "-Wl,--wrap=bufferpoolGetSpliceBuffer" "-Wl,--wrap=memoryAllocateZero" "-Wl,--wrap=fastRand")
    target_link_libraries(${sf_test} PRIVATE ww)
    add_dependencies(waterwall_unit_tests ${sf_test})
    add_waterwall_unit_test(waterwall.streamfragmenter_${variant}_unit ${sf_test} "unit;tunnels;fragmenter;timers;ownership")
  endforeach()
endif()

