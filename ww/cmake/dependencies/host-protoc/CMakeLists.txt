cmake_minimum_required(VERSION 3.25)
project(WaterWallHostProtoc LANGUAGES C CXX)

# This is a native build, deliberately independent of runtime toolchain flags,
# instruction selection, sanitizers and IPO. Only its executable is consumed.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
set(BUILD_SHARED_LIBS OFF)
set(ABSL_BUILD_TESTING OFF)
set(ABSL_ENABLE_INSTALL OFF)
set(ABSL_PROPAGATE_CXX_STD ON)
set(ABSL_MSVC_STATIC_RUNTIME ON)
set(protobuf_BUILD_TESTS OFF)
set(protobuf_BUILD_EXAMPLES OFF)
set(protobuf_BUILD_CONFORMANCE OFF)
set(protobuf_BUILD_SHARED_LIBS OFF)
set(protobuf_MSVC_STATIC_RUNTIME ON)
# protoc's upstream compiler library uses the bundled upb bootstrap metadata,
# even though the WaterWall runtime only links protobuf-lite.
set(protobuf_BUILD_LIBUPB ON)
set(protobuf_BUILD_PROTOC_BINARIES ON)
set(protobuf_INSTALL OFF)
set(protobuf_LOCAL_DEPENDENCIES_ONLY ON)
set(protobuf_WITH_ZLIB OFF)
add_subdirectory("${WW_ABSEIL_SOURCE}" abseil EXCLUDE_FROM_ALL)
add_subdirectory("${WW_PROTOBUF_SOURCE}" protobuf EXCLUDE_FROM_ALL)
set_target_properties(protoc PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin")
if(MINGW)
  # The host tool runs on the target's PATH; do not load compiler runtime DLLs
  # from a different MinGW architecture.
  target_link_options(protoc PRIVATE -static)
endif()

# Excluded subdirectories are omitted from the parent Visual Studio solution
# unless a parent target depends on them. Give every generator one root target
# that brings in protoc and only the libraries it needs.
add_custom_target(waterwall_host_protoc)
add_dependencies(waterwall_host_protoc protoc)
