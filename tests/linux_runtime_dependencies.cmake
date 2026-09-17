# Inspect ELF metadata without executing the binary, including cross-built targets.
foreach(binary IN LISTS WATERWALL_BINARIES)
  execute_process(
    COMMAND "${READELF}" --dynamic --wide "${binary}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE dynamic_section
    ERROR_VARIABLE error
  )
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot inspect ${binary}: ${error}")
  endif()

  string(REGEX MATCHALL "\\(NEEDED\\)[^\n]*" needed_entries "${dynamic_section}")
  foreach(entry IN LISTS needed_entries)
    string(REGEX MATCH "\\[([^]]+)\\]" library_match "${entry}")
    if(NOT library_match)
      message(FATAL_ERROR "Cannot parse dependency of ${binary}: ${entry}")
    endif()
    set(library "${CMAKE_MATCH_1}")
    # glibc shipped these separately before merging some into libc in 2.34.
    # The dynamic loader may itself appear in DT_NEEDED on some architectures.
    if(NOT library MATCHES "^lib(c|m|pthread|dl|rt|resolv|util|anl)\\.so\\.[0-9]+$"
        AND NOT library MATCHES "^ld-linux[^/]*\\.so\\.[0-9]+$"
        AND NOT library MATCHES "^ld64?\\.so\\.[0-9]+$")
      message(FATAL_ERROR
        "${binary} requires non-glibc shared library ${library}; link it statically")
    endif()
  endforeach()
  message(STATUS "${binary}: only glibc runtime dependencies")
endforeach()
