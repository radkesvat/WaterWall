# Build-owned lwIP generation recipe.
#
# This parent owns provenance, failure cleanup, and publication for the mapping
# from a pristine checkout to patched-deps/lwip. The child worker owns copy and
# patch staging. Both recipes are fingerprinted independently of the standalone
# patch recipe, so changing any output-affecting rule invalidates the result.

set(WW_LWIP_GENERATOR_SCHEMA "2")
if(NOT DEFINED WW_LWIP_GENERATOR_WORKER_FILE)
    set(WW_LWIP_GENERATOR_WORKER_FILE "${CMAKE_CURRENT_LIST_DIR}/generate_patched_lwip_worker.cmake")
endif()
file(REAL_PATH "${WW_LWIP_GENERATOR_WORKER_FILE}" WW_LWIP_GENERATOR_WORKER_FILE)
file(SHA256 "${CMAKE_CURRENT_LIST_FILE}" WW_LWIP_GENERATOR_RECIPE_SHA256)
file(SHA256 "${WW_LWIP_GENERATOR_WORKER_FILE}" WW_LWIP_GENERATOR_WORKER_SHA256)
set(WW_LWIP_GENERATOR_PROVENANCE
    "schema=${WW_LWIP_GENERATOR_SCHEMA}\nrecipe-sha256=${WW_LWIP_GENERATOR_RECIPE_SHA256}\nworker-sha256=${WW_LWIP_GENERATOR_WORKER_SHA256}\n")

set(LWIP_GENERATOR_PROVENANCE ${LWIP_DIR}/.waterwall-lwip-generator-provenance)
set(LWIP_GENERATOR_MARKER ${LWIP_DIR}/.waterwall-lwip-generator-marker)

file(REAL_PATH "${LWIP_ORIGINAL_DIR}" LWIP_ORIGINAL_REAL_DIR)
file(GLOB_RECURSE ww_lwip_pristine_entries
    LIST_DIRECTORIES true
    RELATIVE "${LWIP_ORIGINAL_REAL_DIR}"
    "${LWIP_ORIGINAL_REAL_DIR}/*"
)
list(FILTER ww_lwip_pristine_entries EXCLUDE REGEX "(^|/)\\.git(/|$)")
list(SORT ww_lwip_pristine_entries)
set(ww_lwip_pristine_digest_input "")
foreach(ww_lwip_relative_path IN LISTS ww_lwip_pristine_entries)
    set(ww_lwip_pristine_path "${LWIP_ORIGINAL_REAL_DIR}/${ww_lwip_relative_path}")
    string(LENGTH "${ww_lwip_relative_path}" ww_lwip_relative_path_length)
    if(IS_DIRECTORY "${ww_lwip_pristine_path}")
        string(APPEND ww_lwip_pristine_digest_input "D ${ww_lwip_relative_path_length}:${ww_lwip_relative_path}\n")
    else()
        file(SHA256 "${ww_lwip_pristine_path}" ww_lwip_pristine_file_digest)
        string(APPEND ww_lwip_pristine_digest_input
            "F ${ww_lwip_relative_path_length}:${ww_lwip_relative_path}:${ww_lwip_pristine_file_digest}\n")
    endif()
endforeach()
string(SHA256 ww_lwip_pristine_content_digest "${ww_lwip_pristine_digest_input}")
set(ww_lwip_expected_source_provenance
    "source=${LWIP_ORIGINAL_REAL_DIR}\ncontent-sha256=${ww_lwip_pristine_content_digest}\n")

# All three independent inputs must match before a published tree may be reused:
# pristine identity/content, standalone patch recipe, and this build generator.
set(ww_lwip_rebuild false)
if(EXISTS "${LWIP_PATCH_SENTINEL}")
    file(READ "${LWIP_PATCH_SENTINEL}" ww_lwip_stored_patch_provenance)
    if(NOT ww_lwip_stored_patch_provenance STREQUAL WW_LWIP_PATCH_PROVENANCE)
        set(ww_lwip_rebuild true)
    endif()
elseif(EXISTS "${LWIP_DIR}")
    set(ww_lwip_rebuild true)
else()
    set(ww_lwip_rebuild true)
endif()

if(NOT ww_lwip_rebuild)
    if(NOT EXISTS "${LWIP_SOURCE_PROVENANCE}")
        set(ww_lwip_rebuild true)
    else()
        file(READ "${LWIP_SOURCE_PROVENANCE}" ww_lwip_stored_source_provenance)
        if(NOT ww_lwip_stored_source_provenance STREQUAL ww_lwip_expected_source_provenance)
            set(ww_lwip_rebuild true)
        endif()
    endif()
endif()

if(NOT ww_lwip_rebuild)
    if(NOT EXISTS "${LWIP_GENERATOR_PROVENANCE}")
        set(ww_lwip_rebuild true)
    else()
        file(READ "${LWIP_GENERATOR_PROVENANCE}" ww_lwip_stored_generator_provenance)
        if(NOT ww_lwip_stored_generator_provenance STREQUAL WW_LWIP_GENERATOR_PROVENANCE)
            set(ww_lwip_rebuild true)
        endif()
    endif()
endif()

if(ww_lwip_rebuild)
    set(ww_lwip_staging_dir ${CMAKE_BINARY_DIR}/patched-deps/.waterwall-lwip-source-staging)
    set(ww_lwip_backup_dir ${CMAKE_BINARY_DIR}/patched-deps/.waterwall-lwip-source-backup)
    file(REMOVE_RECURSE "${ww_lwip_staging_dir}" "${ww_lwip_backup_dir}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            "-DWW_LWIP_PRISTINE_DIR=${LWIP_ORIGINAL_REAL_DIR}"
            "-DWW_LWIP_STAGING_DIR=${ww_lwip_staging_dir}"
            "-DWW_LWIP_PATCH_RECIPE_FILE=${WW_LWIP_PATCH_RECIPE_FILE}"
            "-DWW_LWIP_GENERATOR_SCHEMA=${WW_LWIP_GENERATOR_SCHEMA}"
            "-DWW_LWIP_GENERATOR_WORKER_TEST_FAIL_AFTER_COPY=${WW_LWIP_GENERATOR_WORKER_TEST_FAIL_AFTER_COPY}"
            -P "${WW_LWIP_GENERATOR_WORKER_FILE}"
        RESULT_VARIABLE ww_lwip_generation_worker_result
        OUTPUT_VARIABLE ww_lwip_generation_worker_stdout
        ERROR_VARIABLE ww_lwip_generation_worker_stderr
    )
    if(NOT ww_lwip_generation_worker_result EQUAL 0)
        file(REMOVE_RECURSE "${ww_lwip_staging_dir}" "${ww_lwip_backup_dir}")
        message(FATAL_ERROR
            "build-owned lwIP generation worker failed (${ww_lwip_generation_worker_result})\n"
            "${ww_lwip_generation_worker_stdout}${ww_lwip_generation_worker_stderr}")
    endif()
    file(WRITE "${ww_lwip_staging_dir}/.waterwall-lwip-source-provenance"
        "${ww_lwip_expected_source_provenance}")
    # Generator provenance is the final completion record for the build-owned
    # layer. A staged failure therefore cannot leave a reusable partial tree.
    file(WRITE "${ww_lwip_staging_dir}/.waterwall-lwip-generator-provenance"
        "${WW_LWIP_GENERATOR_PROVENANCE}")

    if(WW_LWIP_GENERATOR_TEST_FAIL_BEFORE_PUBLICATION)
        file(REMOVE_RECURSE "${ww_lwip_staging_dir}" "${ww_lwip_backup_dir}")
        message(FATAL_ERROR "requested build-owned lwIP generator failure before publication")
    endif()

    if(EXISTS "${LWIP_DIR}")
        file(RENAME "${LWIP_DIR}" "${ww_lwip_backup_dir}" RESULT ww_lwip_backup_result)
        if(NOT ww_lwip_backup_result STREQUAL "0")
            file(REMOVE_RECURSE "${ww_lwip_staging_dir}")
            message(FATAL_ERROR "failed to stage the prior generated lwIP tree: ${ww_lwip_backup_result}")
        endif()
    endif()
    file(RENAME "${ww_lwip_staging_dir}" "${LWIP_DIR}" RESULT ww_lwip_publish_result)
    if(NOT ww_lwip_publish_result STREQUAL "0")
        set(ww_lwip_rollback_result "not-required")
        if(EXISTS "${ww_lwip_backup_dir}")
            file(RENAME "${ww_lwip_backup_dir}" "${LWIP_DIR}" RESULT ww_lwip_rollback_result)
        endif()
        file(REMOVE_RECURSE "${ww_lwip_staging_dir}")
        message(FATAL_ERROR
            "failed to publish generated lwIP tree (${ww_lwip_publish_result}); rollback: ${ww_lwip_rollback_result}")
    endif()
    file(REMOVE_RECURSE "${ww_lwip_backup_dir}")
else()
    file(REMOVE "${LWIP_DIR}/.waterwall-pretend-patch")
    ww_apply_lwip_pretend_patch("${LWIP_DIR}")
endif()
