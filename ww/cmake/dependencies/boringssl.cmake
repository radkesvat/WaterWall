# Chromium 154.0.8037.97, ac39ea6853833c1f18fd23614091d11855e71752.
# The source and WaterWall's TLS profile patches remain in TlsClient/boringssl.
include_guard(GLOBAL)

function(waterwall_enable_boringssl)
  if(TARGET WaterWall::BoringSSL)
    return()
  endif()

  # Scope upstream options so dependency tests/tools cannot alter the caller.
  set(BUILD_SHARED_LIBS OFF)
  set(INSTALL_ENABLED OFF)
  set(BUILD_TOOL OFF)
  set(BUILD_TESTING OFF)
  set(BORINGSSL_PREFIX WW_BSSL)
  set(boringssl_source "${PROJECT_SOURCE_DIR}/tunnels/TlsClient/boringssl")
  # Build the ssl/crypto closure requested by consumers. Upstream also defines
  # unused pki/decrepit libraries, which must not join WaterWall's default build.
  add_subdirectory("${boringssl_source}" "${CMAKE_BINARY_DIR}/ww-dependencies/boringssl" EXCLUDE_FROM_ALL)

  if(MSVC)
    # _HAS_EXCEPTIONS changes the MSVC STL exception-class ABI. BoringSSL's
    # private override must not disagree with QUICHE and the other C++ users
    # linked into WaterWall; keep the application's normal exception policy.
    get_directory_property(boringssl_definitions DIRECTORY "${boringssl_source}" COMPILE_DEFINITIONS)
    list(REMOVE_ITEM boringssl_definitions "_HAS_EXCEPTIONS=0")
    set_property(DIRECTORY "${boringssl_source}" PROPERTY COMPILE_DEFINITIONS "${boringssl_definitions}")
  endif()

  foreach(dependency IN ITEMS fipsmodule crypto ssl decrepit pki)
    if(TARGET ${dependency})
      waterwall_configure_runtime_dependency(${dependency})
      set_target_properties(${dependency} PROPERTIES UNITY_BUILD OFF DISABLE_PRECOMPILE_HEADERS ON)
      if(APPLE)
        target_compile_options(${dependency} PRIVATE -Wno-shorten-64-to-32)
      endif()
    endif()
  endforeach()

  add_library(waterwall_boringssl INTERFACE)
  add_library(WaterWall::BoringSSL ALIAS waterwall_boringssl)
  target_include_directories(waterwall_boringssl INTERFACE "${boringssl_source}/include")
  target_compile_definitions(waterwall_boringssl INTERFACE BORINGSSL_PREFIX=WW_BSSL)
  target_link_libraries(waterwall_boringssl INTERFACE ssl crypto)
endfunction()

waterwall_enable_boringssl()
