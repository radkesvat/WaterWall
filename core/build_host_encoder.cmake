cmake_minimum_required(VERSION 3.25)

# Run in a separate script process: clearing these variables must not change
# the application's toolchain, or the MSVC PATH/INCLUDE/LIB/LIBPATH environment.
foreach(name CC CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS CMAKE_TOOLCHAIN_FILE
    CMAKE_GENERATOR CMAKE_GENERATOR_PLATFORM CMAKE_GENERATOR_TOOLSET)
  unset(ENV{${name}})
endforeach()

file(LOCK "${WW_HOST_ENCODER_BUILD}.lock" GUARD PROCESS)
set(configure_args
  -S "${WATERWALL_SOURCE_DIR}/core/tools/xz_encoder"
  -B "${WW_HOST_ENCODER_BUILD}" -G "${WW_HOST_ENCODER_GENERATOR}"
  "-DCPM_SOURCE_CACHE=${WATERWALL_SOURCE_DIR}/build/.cache"
  -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release)
if(WW_HOST_ENCODER_GENERATOR MATCHES "^Visual Studio")
  list(APPEND configure_args -A "${WW_HOST_ENCODER_PLATFORM}")
elseif(WW_HOST_C_COMPILER)
  list(APPEND configure_args "-DCMAKE_C_COMPILER=${WW_HOST_C_COMPILER}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" ${configure_args}
  COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${WW_HOST_ENCODER_BUILD}"
  --config Release --target waterwall_xz_encoder waterwall_payload_tool
  COMMAND_ERROR_IS_FATAL ANY)
