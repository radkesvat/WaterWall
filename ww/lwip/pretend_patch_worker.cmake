if(NOT DEFINED STAGED_LWIP_DIR OR STAGED_LWIP_DIR STREQUAL "")
    message(FATAL_ERROR "STAGED_LWIP_DIR must name the staged lwIP source tree")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/pretend_patch.cmake")
ww_apply_lwip_pretend_patch("${STAGED_LWIP_DIR}")
