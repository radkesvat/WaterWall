# Pinned Abseil and protobuf-lite, and a native protoc of the same version.
# The QUIC and GameNetworkingSockets embeddings share this provider, so a build
# links one protobuf runtime whichever of them is enabled.
include_guard(GLOBAL)
include(FetchContent)

function(waterwall_dependency_source name url sha256)
  FetchContent_Declare(${name} URL "${url}" URL_HASH "SHA256=${sha256}"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_GetProperties(${name})
  if(NOT ${name}_POPULATED)
    FetchContent_Populate(${name})
  endif()
  set(${name}_SOURCE_DIR "${${name}_SOURCE_DIR}" PARENT_SCOPE)
endfunction()

function(waterwall_dependency_runtime_tree directory runtime_crt)
  get_property(dependencies DIRECTORY "${directory}" PROPERTY BUILDSYSTEM_TARGETS)
  foreach(dependency IN LISTS dependencies)
    get_target_property(kind ${dependency} TYPE)
    if(kind MATCHES "^(STATIC_LIBRARY|OBJECT_LIBRARY)$")
      waterwall_configure_runtime_dependency(${dependency})
      # Upstream targets use both link signatures. Copy only the CPU options
      # rather than changing their signature or importing application headers.
      get_target_property(cpu_options waterwall_cpu_options INTERFACE_COMPILE_OPTIONS)
      if(cpu_options)
        target_compile_options(${dependency} PRIVATE ${cpu_options})
      endif()
      set_target_properties(${dependency} PROPERTIES CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON UNITY_BUILD OFF DISABLE_PRECOMPILE_HEADERS ON)
      if(MSVC)
        # Abseil/protobuf each select their own CRT in their directory scope.
        # Preserve WaterWall's compiler-specific choice, including Clang Debug.
        set_target_properties(${dependency} PROPERTIES MSVC_RUNTIME_LIBRARY "${runtime_crt}")
      endif()
    endif()
  endforeach()
  get_property(children DIRECTORY "${directory}" PROPERTY SUBDIRECTORIES)
  foreach(child IN LISTS children)
    waterwall_dependency_runtime_tree("${child}" "${runtime_crt}")
  endforeach()
endfunction()

function(waterwall_enable_protobuf)
  set(runtime_crt "${CMAKE_MSVC_RUNTIME_LIBRARY}")
  if(TARGET protobuf::libprotobuf-lite)
    return()
  endif()

  waterwall_dependency_source(ww_quic_abseil
    "https://codeload.github.com/abseil/abseil-cpp/tar.gz/refs/tags/20260107.0"
    4c124408da902be896a2f368042729655709db5e3004ec99f57e3e14439bc1b2)
  waterwall_dependency_source(ww_quic_protobuf
    "https://codeload.github.com/protocolbuffers/protobuf/tar.gz/refs/tags/v31.1"
    c3a0a9ece8932e31c3b736e2db18b1c42e7070cd9b881388b26d01aa71e24ca2)

  # Function scope keeps the repository-wide C++17 baseline and test options.
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_UNITY_BUILD OFF)
  set(BUILD_SHARED_LIBS OFF)
  set(BUILD_TESTING OFF)
  set(ABSL_BUILD_TESTING OFF)
  set(ABSL_ENABLE_INSTALL OFF)
  set(ABSL_PROPAGATE_CXX_STD ON)
  set(ABSL_MSVC_STATIC_RUNTIME ON)
  set(protobuf_BUILD_TESTS OFF)
  set(protobuf_BUILD_EXAMPLES OFF)
  set(protobuf_BUILD_CONFORMANCE OFF)
  set(protobuf_BUILD_SHARED_LIBS OFF)
  set(protobuf_MSVC_STATIC_RUNTIME ON)
  set(protobuf_BUILD_PROTOC_BINARIES OFF)
  set(protobuf_BUILD_LIBPROTOC OFF)
  set(protobuf_BUILD_LIBUPB OFF)
  set(protobuf_INSTALL OFF)
  set(protobuf_LOCAL_DEPENDENCIES_ONLY ON)
  set(protobuf_WITH_ZLIB OFF)
  add_subdirectory("${ww_quic_abseil_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/ww-dependencies/abseil" EXCLUDE_FROM_ALL)
  add_subdirectory("${ww_quic_protobuf_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/ww-dependencies/protobuf" EXCLUDE_FROM_ALL)

  # On targets without native 64-bit atomics protobuf exports bare -latomic.
  # Compiler-runtime static flags do not make that library static on Linux.
  get_directory_property(protobuf_needs_atomic DIRECTORY "${ww_quic_protobuf_SOURCE_DIR}"
    DEFINITION protobuf_LINK_LIBATOMIC)
  if(protobuf_needs_atomic AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
    find_library(WW_QUIC_ATOMIC_STATIC_LIBRARY NAMES libatomic.a
      HINTS ${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES} REQUIRED)
    foreach(link_property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
      get_target_property(protobuf_libraries libprotobuf-lite ${link_property})
      set(static_libraries "")
      foreach(library IN LISTS protobuf_libraries)
        if(library STREQUAL "atomic")
          set(library "${WW_QUIC_ATOMIC_STATIC_LIBRARY}")
        elseif(library STREQUAL "$<LINK_ONLY:atomic>")
          set(library "$<LINK_ONLY:${WW_QUIC_ATOMIC_STATIC_LIBRARY}>")
        endif()
        list(APPEND static_libraries "${library}")
      endforeach()
      set_property(TARGET libprotobuf-lite PROPERTY ${link_property} "${static_libraries}")
    endforeach()
  endif()
  foreach(dependency_directory IN ITEMS "${ww_quic_abseil_SOURCE_DIR}" "${ww_quic_protobuf_SOURCE_DIR}")
    waterwall_dependency_runtime_tree("${dependency_directory}" "${runtime_crt}")
  endforeach()

  # A distinct host build must never execute the cross-built protoc or inherit
  # the application's toolchain, IPO, CPU selection or sanitizer flags.
  set(host_generator Ninja)
  if(CMAKE_HOST_WIN32 AND CMAKE_GENERATOR MATCHES "^Visual Studio")
    set(host_generator "${CMAKE_GENERATOR}")
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
      set(host_platform ARM64)
    else()
      set(host_platform x64)
    endif()
  else()
    find_program(WW_HOST_PROTOC_CC NAMES cc clang gcc cl NO_CMAKE_FIND_ROOT_PATH
      DOC "Native C compiler for the independent protoc build" REQUIRED)
    find_program(WW_HOST_PROTOC_CXX NAMES c++ clang++ g++ cl NO_CMAKE_FIND_ROOT_PATH
      DOC "Native C++ compiler for the independent protoc build" REQUIRED)
    set(host_cc "${WW_HOST_PROTOC_CC}")
    set(host_cxx "${WW_HOST_PROTOC_CXX}")
  endif()
  string(SHA256 host_identity "31.1;20260107.0;${CMAKE_HOST_SYSTEM_NAME};${CMAKE_HOST_SYSTEM_PROCESSOR};${host_cc};${host_cxx};${host_generator}")
  string(SUBSTRING "${host_identity}" 0 12 host_identity)
  set(host_build "${PROJECT_SOURCE_DIR}/build/quic-protoc-host-${host_identity}")
  set(host_protoc "${host_build}/bin/protoc${CMAKE_HOST_EXECUTABLE_SUFFIX}")
  if(CMAKE_HOST_WIN32)
    set(host_protoc "${host_build}/bin/protoc.exe")
  endif()
  add_custom_command(OUTPUT "${host_protoc}"
    COMMAND "${CMAKE_COMMAND}"
      "-DWW_HOST_PROTOC_SOURCE=${CMAKE_CURRENT_FUNCTION_LIST_DIR}/host-protoc"
      "-DWW_HOST_PROTOC_BUILD=${host_build}"
      "-DWW_HOST_PROTOC_GENERATOR=${host_generator}"
      "-DWW_HOST_PROTOC_PLATFORM=${host_platform}"
      "-DWW_HOST_PROTOC_CC=${host_cc}" "-DWW_HOST_PROTOC_CXX=${host_cxx}"
      "-DWW_ABSEIL_SOURCE=${ww_quic_abseil_SOURCE_DIR}"
      "-DWW_PROTOBUF_SOURCE=${ww_quic_protobuf_SOURCE_DIR}"
      -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/build_host_protoc.cmake"
    DEPENDS "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/host-protoc/CMakeLists.txt"
      "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/build_host_protoc.cmake"
    VERBATIM COMMENT "Building pinned native protoc 31.1")
  set_property(GLOBAL PROPERTY WATERWALL_HOST_PROTOC "${host_protoc}")
endfunction()

waterwall_enable_protobuf()
