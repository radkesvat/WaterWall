# Exact-result runner for the tunnel hard-abort runtime cases.
#
# CMake supplies the cross-platform process boundary the C test used to build
# with fork()/waitpid(). Every enabled case is invoked separately and must end
# with a numeric result of exactly 1 and print the immediate-abort diagnostic.
# A signal, an access violation, an assertion, a reserved setup-failure code and
# a zero exit all fail, so a crash can no longer pass for abortProgramNow(1).

foreach(required IN ITEMS ABORT_TEST_TARGET ABORT_TEST_EXECUTABLE ABORT_TEST_BUILD_DIR ABORT_TEST_CASES)
  if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
    message(FATAL_ERROR "${required} is required")
  endif()
endforeach()

set(build_args --build "${ABORT_TEST_BUILD_DIR}" --target "${ABORT_TEST_TARGET}")
if(DEFINED ABORT_TEST_CONFIG AND NOT ABORT_TEST_CONFIG STREQUAL "")
  list(APPEND build_args --config "${ABORT_TEST_CONFIG}")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" ${build_args}
  RESULT_VARIABLE build_result
)

if(NOT build_result EQUAL 0)
  message(FATAL_ERROR "Failed to build ${ABORT_TEST_TARGET}")
endif()

if(NOT EXISTS "${ABORT_TEST_EXECUTABLE}")
  message(FATAL_ERROR "Abort runtime executable is missing after build: ${ABORT_TEST_EXECUTABLE}")
endif()

# Printed by abortProgramNow() itself, immediately before _Exit(). Requiring it
# proves the exact hard-abort entry point was reached rather than some other
# path that happens to exit with 1.
set(hard_abort_diagnostic "SignalManager: aborting immediately, registered cleanup is SKIPPED")

# The case list is passed pipe-separated so its separators survive add_test().
string(REPLACE "|" ";" abort_cases "${ABORT_TEST_CASES}")

foreach(case_name IN LISTS abort_cases)
  execute_process(
    COMMAND "${ABORT_TEST_EXECUTABLE}" "${case_name}"
    OUTPUT_VARIABLE case_stdout
    ERROR_VARIABLE case_stderr
    RESULT_VARIABLE case_result
  )

  if(NOT "${case_result}" STREQUAL "1")
    message(
      FATAL_ERROR
      "abort case '${case_name}' did not exit through abortProgramNow(1).\n"
      "expected result: 1\n"
      "actual result:   ${case_result}\n"
      "----- stdout -----\n${case_stdout}\n"
      "----- stderr -----\n${case_stderr}"
    )
  endif()

  string(FIND "${case_stdout}${case_stderr}" "${hard_abort_diagnostic}" diagnostic_position)
  if(diagnostic_position EQUAL -1)
    message(
      FATAL_ERROR
      "abort case '${case_name}' exited with 1 but never reached the immediate-abort entry point.\n"
      "expected output to contain: ${hard_abort_diagnostic}\n"
      "----- stdout -----\n${case_stdout}\n"
      "----- stderr -----\n${case_stderr}"
    )
  endif()

  message(STATUS "abort case '${case_name}': exited 1 through abortProgramNow(1)")
endforeach()
