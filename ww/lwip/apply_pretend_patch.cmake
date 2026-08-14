if(NOT DEFINED LWIP_DIR OR LWIP_DIR STREQUAL "")
    message(FATAL_ERROR "LWIP_DIR must name an lwIP source tree")
endif()

get_filename_component(lwip_source "${LWIP_DIR}" REALPATH)
if(NOT IS_DIRECTORY "${lwip_source}")
    message(FATAL_ERROR "LWIP_DIR must name an existing lwIP source tree")
endif()
get_filename_component(lwip_parent "${lwip_source}" DIRECTORY)
get_filename_component(lwip_name "${lwip_source}" NAME)
if(lwip_parent STREQUAL "/" OR lwip_name STREQUAL "")
    message(FATAL_ERROR "refusing to patch a broad filesystem path")
endif()

string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef patch_nonce)
set(staging_root "${lwip_parent}/.ww-lwip-patch-${patch_nonce}")
set(staged_source "${staging_root}/${lwip_name}")
set(backup_source "${lwip_parent}/.ww-lwip-backup-${patch_nonce}")

file(MAKE_DIRECTORY "${staging_root}")
file(COPY "${lwip_source}" DESTINATION "${staging_root}")

execute_process(
    COMMAND "${CMAKE_COMMAND}" -DSTAGED_LWIP_DIR=${staged_source}
            -P "${CMAKE_CURRENT_LIST_DIR}/pretend_patch_worker.cmake"
    RESULT_VARIABLE patch_worker_result
)
if(NOT patch_worker_result EQUAL 0)
    file(REMOVE_RECURSE "${staging_root}")
    message(FATAL_ERROR "Waterwall lwIP patch worker failed (${patch_worker_result})")
endif()

file(RENAME "${lwip_source}" "${backup_source}" RESULT move_original_result)
if(NOT move_original_result STREQUAL "0")
    file(REMOVE_RECURSE "${staging_root}")
    message(FATAL_ERROR "failed to stage the original lwIP tree: ${move_original_result}")
endif()

file(RENAME "${staged_source}" "${lwip_source}" RESULT publish_result)
if(NOT publish_result STREQUAL "0")
    file(RENAME "${backup_source}" "${lwip_source}" RESULT rollback_result)
    file(REMOVE_RECURSE "${staging_root}")
    message(FATAL_ERROR "failed to publish patched lwIP tree (${publish_result}); rollback: ${rollback_result}")
endif()

file(REMOVE_RECURSE "${backup_source}" "${staging_root}")
