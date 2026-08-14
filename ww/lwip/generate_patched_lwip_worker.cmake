if(NOT DEFINED WW_LWIP_PRISTINE_DIR OR WW_LWIP_PRISTINE_DIR STREQUAL "")
    message(FATAL_ERROR "WW_LWIP_PRISTINE_DIR must name the pristine lwIP source tree")
endif()
if(NOT DEFINED WW_LWIP_STAGING_DIR OR WW_LWIP_STAGING_DIR STREQUAL "")
    message(FATAL_ERROR "WW_LWIP_STAGING_DIR must name the build-owned staging tree")
endif()
if(NOT DEFINED WW_LWIP_PATCH_RECIPE_FILE OR WW_LWIP_PATCH_RECIPE_FILE STREQUAL "")
    message(FATAL_ERROR "WW_LWIP_PATCH_RECIPE_FILE must name the standalone patch recipe")
endif()
if(NOT DEFINED WW_LWIP_GENERATOR_SCHEMA OR WW_LWIP_GENERATOR_SCHEMA STREQUAL "")
    message(FATAL_ERROR "WW_LWIP_GENERATOR_SCHEMA must be set")
endif()

file(REAL_PATH "${WW_LWIP_PRISTINE_DIR}" ww_lwip_pristine_real)
get_filename_component(ww_lwip_staging_parent "${WW_LWIP_STAGING_DIR}" DIRECTORY)
if(NOT IS_DIRECTORY "${ww_lwip_pristine_real}" OR ww_lwip_staging_parent STREQUAL "/")
    message(FATAL_ERROR "refusing an invalid or broad lwIP generation path")
endif()

file(REMOVE_RECURSE "${WW_LWIP_STAGING_DIR}")
file(MAKE_DIRECTORY "${WW_LWIP_STAGING_DIR}")
file(COPY "${ww_lwip_pristine_real}/" DESTINATION "${WW_LWIP_STAGING_DIR}" PATTERN ".git" EXCLUDE)

if(WW_LWIP_GENERATOR_WORKER_TEST_FAIL_AFTER_COPY)
    message(FATAL_ERROR "requested build-owned lwIP worker failure after copy")
endif()

# Write the generated addition before patching so the standalone manifest
# authenticates its bytes together with every copied source file.
file(WRITE "${WW_LWIP_STAGING_DIR}/.waterwall-lwip-generator-marker"
    "WaterWall build-owned lwIP generator schema ${WW_LWIP_GENERATOR_SCHEMA}\n")

include("${WW_LWIP_PATCH_RECIPE_FILE}")
ww_apply_lwip_pretend_patch("${WW_LWIP_STAGING_DIR}")
