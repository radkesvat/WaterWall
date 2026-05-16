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

execute_process(
  COMMAND "${UNIT_TEST_EXECUTABLE}"
  RESULT_VARIABLE test_result
)

if(NOT test_result EQUAL 0)
  message(FATAL_ERROR "${UNIT_TEST_TARGET} failed with exit code ${test_result}")
endif()
