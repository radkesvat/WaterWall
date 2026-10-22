# Native CMake embedding of Google QUICHE's pinned production quiche_core target.
# Do not replace this with Cloudflare quiche, upstream test/tool targets or a
# global source glob. Source groups come directly from build/source_list.json;
# dependency targets mirror quiche/BUILD.bazel at the revision below.
include_guard(GLOBAL)
include(FetchContent)

function(waterwall_quic_source name url sha256)
  FetchContent_Declare(${name} URL "${url}" URL_HASH "SHA256=${sha256}"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_GetProperties(${name})
  if(NOT ${name}_POPULATED)
    FetchContent_Populate(${name})
  endif()
  set(${name}_SOURCE_DIR "${${name}_SOURCE_DIR}" PARENT_SCOPE)
endfunction()

function(waterwall_quic_runtime_tree directory runtime_crt)
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
    waterwall_quic_runtime_tree("${child}" "${runtime_crt}")
  endforeach()
endfunction()

function(waterwall_enable_quiche)
  set(runtime_crt "${CMAKE_MSVC_RUNTIME_LIBRARY}")
  if(TARGET WaterWall::Quiche)
    return()
  endif()
  if(NOT TARGET WaterWall::BoringSSL)
    message(FATAL_ERROR "QUICHE requires the shared prefixed WaterWall BoringSSL provider")
  endif()
  include(TestBigEndian)
  test_big_endian(quiche_big_endian)
  if(quiche_big_endian)
    message(FATAL_ERROR "Google QUICHE supports little-endian targets only")
  endif()

  waterwall_quic_source(ww_quiche
    "https://codeload.github.com/google/quiche/tar.gz/0ded66479add86dae9ae2039bb78c25d4f04c535"
    704efd37c83f273f070fd05dede4a234ff9cecbd16ec57ddf3c3d6726eb7e34e)
  waterwall_quic_source(ww_quic_abseil
    "https://codeload.github.com/abseil/abseil-cpp/tar.gz/refs/tags/20260107.0"
    4c124408da902be896a2f368042729655709db5e3004ec99f57e3e14439bc1b2)
  waterwall_quic_source(ww_quic_protobuf
    "https://codeload.github.com/protocolbuffers/protobuf/tar.gz/refs/tags/v31.1"
    c3a0a9ece8932e31c3b736e2db18b1c42e7070cd9b881388b26d01aa71e24ca2)
  waterwall_quic_source(ww_quic_googleurl
    "https://codeload.github.com/google/gurl/tar.gz/94ff147fe0b96b4cca5d6d316b9af6210c0b8051"
    d8a701123250e03b3c0865babdfc78540d66374db78f74aafd09bf08545c00bd)

  # This Google URL pin assumes CWG2518, a newer constexpr std::string, and
  # C++20 syntax that Clang 14 does not implement. Keep GCC 11 and Clang 14
  # support through generated header overlays, leaving the source cache intact.
  # String-literal arrays have N >= 1, so the dependent assertion still rejects
  # every forbidden overload at instantiation. GURL has no constexpr instances.
  set(gurl_overlay "${CMAKE_BINARY_DIR}/ww-dependencies/googleurl-compat")
  foreach(header IN ITEMS base/strings/utf_string_conversions.h url/gurl.h
      base/numerics/safe_conversions_impl.h base/containers/checked_iterators.h
      base/containers/span.h)
    file(READ "${ww_quic_googleurl_SOURCE_DIR}/${header}" contents)
    if(header STREQUAL "base/strings/utf_string_conversions.h")
      string(REPLACE "static_assert(false," "static_assert(N == 0," contents "${contents}")
    elseif(header STREQUAL "url/gurl.h")
      string(REPLACE "constexpr friend auto operator<=>" "friend auto operator<=>" contents "${contents}")
    elseif(header STREQUAL "base/numerics/safe_conversions_impl.h")
      foreach(dependent_type IN ITEMS "IntegerForDigitsAndSignImpl<Size, IsSigned>::type"
          "BigEnoughPromotionImpl<Lhs, Rhs>::type" "FastIntegerArithmeticPromotionImpl<Lhs, Rhs>::type"
          "T::value_type" "UnderlyingTypeImpl<T>::type")
        string(REPLACE "${dependent_type}" "typename ${dependent_type}" contents "${contents}")
      endforeach()
    elseif(header STREQUAL "base/containers/checked_iterators.h")
      foreach(current IN ITEMS start current)
        string(REPLACE "AssumeValid(start, ${current}, end)" "AssumeValid{start, ${current}, end}"
          contents "${contents}")
      endforeach()
    elseif(header STREQUAL "base/containers/span.h")
      foreach(bound IN ITEMS extent "size()")
        string(REPLACE "AssumeValid(data(), data(), data() + ${bound})"
          "AssumeValid{data(), data(), data() + ${bound}}" contents "${contents}")
        string(REPLACE "AssumeValid(\n        data(), data() + ${bound}, data() + ${bound})"
          "AssumeValid{\n        data(), data() + ${bound}, data() + ${bound}}" contents "${contents}")
      endforeach()
    endif()
    set(previous "")
    if(EXISTS "${gurl_overlay}/${header}")
      file(READ "${gurl_overlay}/${header}" previous)
    endif()
    if(NOT contents STREQUAL previous)
      get_filename_component(header_directory "${gurl_overlay}/${header}" DIRECTORY)
      file(MAKE_DIRECTORY "${header_directory}")
      file(WRITE "${gurl_overlay}/${header}" "${contents}")
    endif()
  endforeach()
  waterwall_quic_source(ww_quic_zlib
    "https://codeload.github.com/madler/zlib/tar.gz/refs/tags/v1.3.1"
    17e88863f3600672ab49182f217281b6fc4d3c762bde361935e436a95214d05c)

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
  set(ZLIB_BUILD_EXAMPLES OFF)
  add_subdirectory("${ww_quic_abseil_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/ww-dependencies/abseil" EXCLUDE_FROM_ALL)
  add_subdirectory("${ww_quic_protobuf_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/ww-dependencies/protobuf" EXCLUDE_FROM_ALL)
  add_subdirectory("${ww_quic_zlib_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/ww-dependencies/zlib" EXCLUDE_FROM_ALL)

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
  foreach(dependency_directory IN ITEMS "${ww_quic_abseil_SOURCE_DIR}"
      "${ww_quic_protobuf_SOURCE_DIR}" "${ww_quic_zlib_SOURCE_DIR}")
    waterwall_quic_runtime_tree("${dependency_directory}" "${runtime_crt}")
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
    find_program(host_cc NAMES cc clang gcc cl NO_CMAKE_FIND_ROOT_PATH REQUIRED)
    find_program(host_cxx NAMES c++ clang++ g++ cl NO_CMAKE_FIND_ROOT_PATH REQUIRED)
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

  file(READ "${ww_quiche_SOURCE_DIR}/build/source_list.json" manifest)
  set(quiche_sources "")
  foreach(group IN ITEMS quiche_core_srcs default_platform_impl_srcs)
    string(JSON source_count LENGTH "${manifest}" "${group}")
    math(EXPR last_source "${source_count} - 1")
    foreach(index RANGE 0 ${last_source})
      string(JSON source GET "${manifest}" "${group}" ${index})
      list(APPEND quiche_sources "${ww_quiche_SOURCE_DIR}/${source}")
    endforeach()
  endforeach()

  # libstdc++ 11 does not yet provide a literal std::vector. The empty option
  # list is read-only runtime state, so const preserves its contract.
  set(config_source "${ww_quiche_SOURCE_DIR}/quiche/quic/core/quic_config.cc")
  set(config_compat "${CMAKE_BINARY_DIR}/ww-dependencies/quiche-compat/quic_config.cc")
  file(READ "${config_source}" config_contents)
  string(REPLACE "static constexpr QuicTagVector no_options;"
    "static const QuicTagVector no_options;" config_contents "${config_contents}")
  set(previous_config "")
  if(EXISTS "${config_compat}")
    file(READ "${config_compat}" previous_config)
  endif()
  if(NOT config_contents STREQUAL previous_config)
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/ww-dependencies/quiche-compat")
    file(WRITE "${config_compat}" "${config_contents}")
  endif()
  list(REMOVE_ITEM quiche_sources "${config_source}")
  list(APPEND quiche_sources "${config_compat}")

  # Clang 14 needs braces for these aggregates. Preserve the initialization
  # values, selected std::variant alternatives, and string copy/move.
  foreach(source IN ITEMS quiche/common/structured_headers.cc quiche/quic/core/quic_ack_timestamp_list.cc)
    get_filename_component(filename "${source}" NAME)
    set(aggregate_source "${ww_quiche_SOURCE_DIR}/${source}")
    set(aggregate_compat "${CMAKE_BINARY_DIR}/ww-dependencies/quiche-compat/${filename}")
    file(READ "${aggregate_source}" aggregate_contents)
    if(filename STREQUAL "structured_headers.cc")
      foreach(value_type IN ITEMS Token ByteSequence)
        foreach(operation IN ITEMS string move)
          string(REPLACE "${value_type}(std::${operation}(value))"
            "${value_type}{std::${operation}(value)}" aggregate_contents "${aggregate_contents}")
        endforeach()
      endforeach()
    else()
      string(REPLACE "TimestampDeltaEncoder encoder(exponent);" "TimestampDeltaEncoder encoder{exponent};"
        aggregate_contents "${aggregate_contents}")
    endif()
    set(previous_aggregate "")
    if(EXISTS "${aggregate_compat}")
      file(READ "${aggregate_compat}" previous_aggregate)
    endif()
    if(NOT aggregate_contents STREQUAL previous_aggregate)
      file(WRITE "${aggregate_compat}" "${aggregate_contents}")
    endif()
    list(REMOVE_ITEM quiche_sources "${aggregate_source}")
    list(APPEND quiche_sources "${aggregate_compat}")
  endforeach()

  # As above for Google URL, defer this forbidden-template-branch assertion
  # until instantiation on compilers predating CWG2518.
  set(headers_source "${ww_quiche_SOURCE_DIR}/quiche/web_transport/web_transport_headers.cc")
  set(headers_compat "${CMAKE_BINARY_DIR}/ww-dependencies/quiche-compat/web_transport_headers.cc")
  file(READ "${headers_source}" headers_contents)
  string(REPLACE "static_assert(false);"
    "static_assert(kExpectedType != kExpectedType);" headers_contents "${headers_contents}")
  set(previous_headers "")
  if(EXISTS "${headers_compat}")
    file(READ "${headers_compat}" previous_headers)
  endif()
  if(NOT headers_contents STREQUAL previous_headers)
    file(WRITE "${headers_compat}" "${headers_contents}")
  endif()
  list(REMOVE_ITEM quiche_sources "${headers_source}")
  list(APPEND quiche_sources "${headers_compat}")

  set(generated_root "${CMAKE_BINARY_DIR}/ww-dependencies/quiche-generated")
  file(MAKE_DIRECTORY "${generated_root}")
  string(JSON proto_count LENGTH "${manifest}" protobuf)
  math(EXPR last_proto "${proto_count} - 1")
  foreach(index RANGE 0 ${last_proto})
    string(JSON proto GET "${manifest}" protobuf ${index})
    string(REGEX REPLACE "\\.proto$" ".pb.cc" proto_cc "${proto}")
    string(REGEX REPLACE "\\.proto$" ".pb.h" proto_h "${proto}")
    add_custom_command(OUTPUT "${generated_root}/${proto_cc}" "${generated_root}/${proto_h}"
      COMMAND "${host_protoc}" "--proto_path=${ww_quiche_SOURCE_DIR}"
        "--cpp_out=${generated_root}" "${ww_quiche_SOURCE_DIR}/${proto}"
      DEPENDS "${host_protoc}" "${ww_quiche_SOURCE_DIR}/${proto}"
      VERBATIM COMMENT "Generating QUICHE lite protobuf ${proto}")
    list(APPEND quiche_sources "${generated_root}/${proto_cc}")
  endforeach()

  # Google URL's supported ASCII-only IDNA path; no ICU dependency. This list
  # follows its url/BUILD and base/BUILD at the pinned revision.
  set(gurl_sources base/debug/crash_logging.cc base/strings/string_util.cc
    base/strings/string_util_constants.cc base/strings/utf_ostream_operators.cc
    base/strings/utf_string_conversion_utils.cc base/strings/utf_string_conversions.cc
    url/gurl.cc url/third_party/mozilla/url_parse.cc url/url_canon.cc
    url/url_canon_etc.cc url/url_canon_filesystemurl.cc url/url_canon_fileurl.cc
    url/url_canon_host.cc url/url_canon_internal.cc url/url_canon_ip.cc
    url/url_canon_mailtourl.cc url/url_canon_non_special_url.cc url/url_canon_path.cc
    url/url_canon_pathurl.cc url/url_canon_query.cc url/url_canon_relative.cc
    url/url_canon_stdstring.cc url/url_canon_stdurl.cc url/url_features.cc
    url/url_parse_file.cc url/url_util.cc url/url_idna_ascii_only.cc)
  if(WIN32)
    list(APPEND gurl_sources base/strings/string_util_win.cc)
  endif()
  list(TRANSFORM gurl_sources PREPEND "${ww_quic_googleurl_SOURCE_DIR}/")
  add_library(waterwall_googleurl STATIC ${gurl_sources})
  target_include_directories(waterwall_googleurl SYSTEM PUBLIC
    "${gurl_overlay}" "${ww_quic_googleurl_SOURCE_DIR}/polyfills" "${ww_quic_googleurl_SOURCE_DIR}")
  target_link_libraries(waterwall_googleurl PRIVATE absl::optional)

  add_library(waterwall_quiche STATIC ${quiche_sources})
  add_library(WaterWall::Quiche ALIAS waterwall_quiche)
  target_include_directories(waterwall_quiche SYSTEM PUBLIC "${ww_quiche_SOURCE_DIR}"
    "${ww_quiche_SOURCE_DIR}/quiche/common/platform/default" "${generated_root}")
  target_link_libraries(waterwall_quiche PUBLIC WaterWall::BoringSSL
    protobuf::libprotobuf-lite waterwall_googleurl zlibstatic
    absl::algorithm_container absl::base absl::config absl::core_headers
    absl::log_severity absl::no_destructor absl::nullability absl::prefetch
    absl::cleanup absl::btree absl::chunked_queue absl::fixed_array
    absl::flat_hash_map absl::flat_hash_set absl::inlined_vector absl::node_hash_map
    absl::stacktrace absl::symbolize absl::flags absl::any_invocable
    absl::function_ref absl::overload absl::hash absl::absl_check absl::absl_log
    absl::log_flags absl::memory absl::bits absl::int128 absl::status absl::statusor
    absl::strings absl::cord absl::str_format absl::synchronization absl::time
    absl::span absl::variant)
  foreach(dependency IN ITEMS waterwall_googleurl waterwall_quiche)
    waterwall_configure_runtime_dependency(${dependency})
    target_link_libraries(${dependency} PRIVATE waterwall_cpu_options)
    set_target_properties(${dependency} PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON
      UNITY_BUILD OFF DISABLE_PRECOMPILE_HEADERS ON)
    if(NOT MSVC)
      target_compile_options(${dependency} PRIVATE -fno-strict-aliasing)
    endif()
  endforeach()
endfunction()

waterwall_enable_quiche()
