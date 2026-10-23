cmake_minimum_required(VERSION 3.25)

foreach(name CC CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS CMAKE_TOOLCHAIN_FILE
    CMAKE_GENERATOR CMAKE_GENERATOR_PLATFORM CMAKE_GENERATOR_TOOLSET
    SDKROOT CMAKE_OSX_ARCHITECTURES MACOSX_DEPLOYMENT_TARGET
    IPHONEOS_DEPLOYMENT_TARGET TVOS_DEPLOYMENT_TARGET
    WATCHOS_DEPLOYMENT_TARGET XROS_DEPLOYMENT_TARGET)
  unset(ENV{${name}})
endforeach()

file(LOCK "${WW_HOST_PROTOC_BUILD}.lock" GUARD PROCESS)

# Runtime FetchContent roots differ between presets. Stage each pinned host
# source once under the shared native-build identity so switching Debug,
# Release or target platforms does not reconfigure protoc against a new path.
# The caller's host identity includes both dependency pins.
foreach(dependency IN ITEMS ABSEIL PROTOBUF)
  string(TOLOWER "${dependency}" dependency_name)
  set(host_source "${WW_HOST_PROTOC_BUILD}/sources/${dependency_name}")
  if(NOT EXISTS "${host_source}/.waterwall-source-ready")
    file(MAKE_DIRECTORY "${host_source}")
    file(COPY "${WW_${dependency}_SOURCE}/" DESTINATION "${host_source}")
    file(WRITE "${host_source}/.waterwall-source-ready" "${dependency}\n")
  endif()
  set(WW_${dependency}_SOURCE "${host_source}")
endforeach()

set(configure_args -S "${WW_HOST_PROTOC_SOURCE}" -B "${WW_HOST_PROTOC_BUILD}"
  -G "${WW_HOST_PROTOC_GENERATOR}" -DCMAKE_BUILD_TYPE=Release
  "-DWW_ABSEIL_SOURCE=${WW_ABSEIL_SOURCE}"
  "-DWW_PROTOBUF_SOURCE=${WW_PROTOBUF_SOURCE}")
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  # Xcode's custom commands inherit the device/simulator SDK environment. Use
  # macOS explicitly, including when repairing a previously contaminated cache.
  list(APPEND configure_args -DCMAKE_OSX_SYSROOT=macosx
    -DCMAKE_OSX_ARCHITECTURES= -DCMAKE_OSX_DEPLOYMENT_TARGET=)
endif()
if(WW_HOST_PROTOC_GENERATOR MATCHES "^Visual Studio")
  list(APPEND configure_args -A "${WW_HOST_PROTOC_PLATFORM}")
else()
  list(APPEND configure_args "-DCMAKE_C_COMPILER=${WW_HOST_PROTOC_CC}"
    "-DCMAKE_CXX_COMPILER=${WW_HOST_PROTOC_CXX}")
  if(CMAKE_HOST_WIN32)
    # Compiler subprocesses must also load the native toolchain's DLLs before
    # any differently sized MinGW runtime inherited from the target build.
    get_filename_component(host_cc_directory "${WW_HOST_PROTOC_CC}" DIRECTORY)
    get_filename_component(host_cxx_directory "${WW_HOST_PROTOC_CXX}" DIRECTORY)
    set(host_compiler_directories "${host_cc_directory}" "${host_cxx_directory}")
    list(REMOVE_DUPLICATES host_compiler_directories)
    set(ENV{PATH} "${host_compiler_directories};$ENV{PATH}")
  endif()
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" ${configure_args} COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${WW_HOST_PROTOC_BUILD}"
  --config Release --target waterwall_host_protoc --parallel 4 COMMAND_ERROR_IS_FATAL ANY)
