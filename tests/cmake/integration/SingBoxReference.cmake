# Reuse one pinned binary for all protocol interoperability tests. Keep the
# existing VMess target and cache names available to build scripts and CI.
include_guard(GLOBAL)

function(waterwall_add_sing_box_reference)
  if(TARGET waterwall_vmess_SING_BOX_reference)
    return()
  endif()
  set(sing_box_reference_cache "${CMAKE_SOURCE_DIR}/build/test-tools/sing-box-1.12.0")
  set(WATERWALL_VMESS_SING_BOX_REFERENCE "${sing_box_reference_cache}/sing-box" CACHE FILEPATH
      "Pinned sing-box 1.12.0 executable used by interoperability tests")
  add_custom_target(waterwall_vmess_SING_BOX_reference
    COMMAND "${PYTHON3_EXECUTABLE}" "${WATERWALL_TEST_SOURCE_ROOT}/provision_vmess_reference.py"
      --peer sing-box --cache-dir "${sing_box_reference_cache}"
    COMMENT "Provisioning the pinned sing-box 1.12.0 interoperability reference"
    VERBATIM)
endfunction()
