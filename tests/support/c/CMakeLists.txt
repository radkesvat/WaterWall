# Available before Linux and root portable registrations; never linked by ww.
add_library(ww_test_support STATIC test_assert.c test_case.c)
target_include_directories(ww_test_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(ww_test_support PROPERTIES
  DISABLE_PRECOMPILE_HEADERS ON INTERPROCEDURAL_OPTIMIZATION OFF)

# Match the established Debug-only sanitizer policy without inheriting ww.
foreach(sanitizer IN ITEMS ASAN TSAN LSAN USAN)
  if(ENABLE_${sanitizer})
    if(sanitizer STREQUAL "ASAN")
      set(sanitizer_name address)
    elseif(sanitizer STREQUAL "TSAN")
      set(sanitizer_name thread)
    elseif(sanitizer STREQUAL "LSAN")
      set(sanitizer_name leak)
    else()
      set(sanitizer_name undefined)
    endif()
    target_compile_options(ww_test_support PUBLIC "$<$<CONFIG:Debug>:-fsanitize=${sanitizer_name}>")
    target_link_options(ww_test_support PUBLIC "$<$<CONFIG:Debug>:-fsanitize=${sanitizer_name}>")
  endif()
endforeach()

