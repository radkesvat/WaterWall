if(NOT DEFINED UNIT_TEST_TARGET OR UNIT_TEST_TARGET STREQUAL "")
  message(FATAL_ERROR "UNIT_TEST_TARGET is required")
endif()

if(NOT DEFINED UNIT_TEST_EXECUTABLE OR UNIT_TEST_EXECUTABLE STREQUAL "")
  message(FATAL_ERROR "UNIT_TEST_EXECUTABLE is required")
endif()

if(NOT DEFINED UNIT_TEST_BUILD_DIR OR UNIT_TEST_BUILD_DIR STREQUAL "")
  message(FATAL_ERROR "UNIT_TEST_BUILD_DIR is required")
endif()

set(build_args --build "${UNIT_TEST_BUILD_DIR}" --target "${UNIT_TEST_TARGET}")
if(DEFINED UNIT_TEST_CONFIG AND NOT UNIT_TEST_CONFIG STREQUAL "")
  list(APPEND build_args --config "${UNIT_TEST_CONFIG}")
endif()

if(NOT EXISTS "${UNIT_TEST_EXECUTABLE}")
  message(STATUS "Building missing unit-test executable: ${UNIT_TEST_EXECUTABLE}")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" ${build_args}
    RESULT_VARIABLE build_result
  )

  if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "Failed to build ${UNIT_TEST_TARGET}")
  endif()
endif()

if(NOT EXISTS "${UNIT_TEST_EXECUTABLE}")
  message(FATAL_ERROR "Unit-test executable is still missing after build: ${UNIT_TEST_EXECUTABLE}")
endif()

set(unit_log_dir "${CMAKE_CURRENT_LIST_DIR}/log")
set(unit_stdout_log "${unit_log_dir}/${UNIT_TEST_TARGET}.stdout.log")
set(unit_stderr_log "${unit_log_dir}/${UNIT_TEST_TARGET}.stderr.log")

file(MAKE_DIRECTORY "${unit_log_dir}")
file(REMOVE "${unit_stdout_log}" "${unit_stderr_log}")

execute_process(
  COMMAND "${UNIT_TEST_EXECUTABLE}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}"
  OUTPUT_FILE "${unit_stdout_log}"
  ERROR_FILE "${unit_stderr_log}"
  RESULT_VARIABLE test_result
)

if(NOT test_result EQUAL 0)
  if(EXISTS "${unit_stdout_log}")
    file(READ "${unit_stdout_log}" unit_stdout)
    if(NOT unit_stdout STREQUAL "")
      message(STATUS "===== ${UNIT_TEST_TARGET}.stdout.log =====\n${unit_stdout}")
    endif()
  endif()

  if(EXISTS "${unit_stderr_log}")
    file(READ "${unit_stderr_log}" unit_stderr)
    if(NOT unit_stderr STREQUAL "")
      message(STATUS "===== ${UNIT_TEST_TARGET}.stderr.log =====\n${unit_stderr}")
    endif()
  endif()

  message(FATAL_ERROR "${UNIT_TEST_TARGET} failed with exit code ${test_result}")
endif()
