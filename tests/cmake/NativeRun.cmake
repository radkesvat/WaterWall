# Shared portable process boundary for native runners. The process-scoped lock
# covers both auto-build and execution; callers must not acquire it again.
include_guard(GLOBAL)

macro(ww_native_run_begin)
  foreach(required IN ITEMS WW_RUN_BUILD_DIR WW_RUN_NAME WW_RUN_SOURCE_DIR WW_RUN_FIXTURE_DIR)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
      message(FATAL_ERROR "${required} is required")
    endif()
  endforeach()
  if(NOT DEFINED WW_RUN_CONFIG)
    message(FATAL_ERROR "WW_RUN_CONFIG is required (may be empty for a single-config tree)")
  endif()
  # Resolve before changing the build/child CWD; manual callers may supply a
  # relative build tree just as cmake --build permits.
  get_filename_component(WW_RUN_BUILD_DIR "${WW_RUN_BUILD_DIR}" ABSOLUTE)
  foreach(stage IN ITEMS LOCK BUILD)
    if(NOT DEFINED WW_RUN_${stage}_TIMEOUT)
      if(stage STREQUAL "LOCK")
        set(WW_RUN_${stage}_TIMEOUT 30)
      else()
        set(WW_RUN_${stage}_TIMEOUT 60)
      endif()
    endif()
    if(NOT "${WW_RUN_${stage}_TIMEOUT}" MATCHES "^[1-9][0-9]*$")
      message(FATAL_ERROR "WW_RUN_${stage}_TIMEOUT must be a positive number of seconds")
    endif()
  endforeach()
  set(run_config "${WW_RUN_CONFIG}")
  if(run_config STREQUAL "")
    set(run_config default)
  endif()
  string(REGEX REPLACE "[^A-Za-z0-9_.-]" "_" run_config "${run_config}")
  string(REGEX REPLACE "[^A-Za-z0-9_.-]" "_" run_name "${WW_RUN_NAME}")
  string(TIMESTAMP run_timestamp "%Y%m%dT%H%M%S" UTC)
  string(RANDOM LENGTH 32 ALPHABET 0123456789abcdef run_nonce)
  set(WW_RUN_DIR "${WW_RUN_BUILD_DIR}/test-runs/${run_config}/${run_name}/${run_timestamp}-${run_nonce}")
  file(MAKE_DIRECTORY "${WW_RUN_DIR}")
  # Publish before waiting for the lock or starting any child. An outer timeout
  # leaves this directory and any partially written logs intact.
  message(STATUS "Run artifacts: ${WW_RUN_DIR}")
  file(WRITE "${WW_RUN_DIR}/result.txt" "initialized\n")
  foreach(log IN ITEMS build.stdout build.stderr child.stdout child.stderr)
    file(WRITE "${WW_RUN_DIR}/${log}.log" "")
  endforeach()
  set(ENV{WATERWALL_TEST_SOURCE_DIR} "${WW_RUN_SOURCE_DIR}")
  set(ENV{WATERWALL_TEST_FIXTURE_DIR} "${WW_RUN_FIXTURE_DIR}")
  file(LOCK "${WW_RUN_BUILD_DIR}/waterwall-native-test.lock"
    GUARD PROCESS TIMEOUT "${WW_RUN_LOCK_TIMEOUT}" RESULT_VARIABLE lock_result)
  if(NOT "${lock_result}" STREQUAL "0")
    file(WRITE "${WW_RUN_DIR}/result.txt" "lock failed: ${lock_result}\n")
    message(FATAL_ERROR "Lock acquisition failed: ${lock_result}\nRetained artifacts: ${WW_RUN_DIR}")
  endif()
endmacro()

function(ww_native_run_dump prefix)
  foreach(stream IN ITEMS stdout stderr)
    file(READ "${WW_RUN_DIR}/${prefix}.${stream}.log" output)
    if(NOT output STREQUAL "")
      message(STATUS "===== ${prefix}.${stream}.log =====\n${output}")
    endif()
  endforeach()
endfunction()

function(ww_native_run_build target)
  set(build_args --build "${WW_RUN_BUILD_DIR}" --target "${target}")
  if(NOT WW_RUN_CONFIG STREQUAL "")
    list(APPEND build_args --config "${WW_RUN_CONFIG}")
  endif()
  file(WRITE "${WW_RUN_DIR}/result.txt" "building\n")
  execute_process(COMMAND "${CMAKE_COMMAND}" ${build_args}
    WORKING_DIRECTORY "${WW_RUN_DIR}"
    OUTPUT_FILE "${WW_RUN_DIR}/build.stdout.log"
    ERROR_FILE "${WW_RUN_DIR}/build.stderr.log"
    TIMEOUT "${WW_RUN_BUILD_TIMEOUT}" RESULT_VARIABLE build_result)
  if(NOT "${build_result}" STREQUAL "0")
    file(WRITE "${WW_RUN_DIR}/result.txt" "build failed: ${build_result}\n")
    ww_native_run_dump(build)
    message(FATAL_ERROR "Build failed for ${target}: ${build_result}\nRetained artifacts: ${WW_RUN_DIR}")
  endif()
endfunction()

function(ww_native_run_execute prefix timeout)
  if(NOT "${timeout}" MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "Execution timeout must be a positive number of seconds")
  endif()
  file(WRITE "${WW_RUN_DIR}/result.txt" "executing ${prefix}\n")
  # Do not use cmake -E env here: that intermediary can translate a signal into
  # numeric exit 1, breaking the hard-abort runner's exact-result contract.
  execute_process(COMMAND ${ARGN} WORKING_DIRECTORY "${WW_RUN_DIR}"
    OUTPUT_FILE "${WW_RUN_DIR}/${prefix}.stdout.log"
    ERROR_FILE "${WW_RUN_DIR}/${prefix}.stderr.log"
    TIMEOUT "${timeout}" RESULT_VARIABLE child_result)
  file(WRITE "${WW_RUN_DIR}/${prefix}.result.txt" "${child_result}\n")
  set(WW_RUN_CHILD_RESULT "${child_result}" PARENT_SCOPE)
endfunction()

function(ww_native_run_finish outcome)
  file(WRITE "${WW_RUN_DIR}/result.txt" "${outcome}\n")
  if(outcome STREQUAL "passed" AND NOT "$ENV{WATERWALL_TEST_KEEP_RUN_DIR}" STREQUAL "1")
    file(REMOVE_RECURSE "${WW_RUN_DIR}")
  else()
    message(STATUS "Retained artifacts (${outcome}): ${WW_RUN_DIR}")
  endif()
endfunction()
