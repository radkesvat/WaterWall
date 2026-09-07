option(WW_PACKED_PAYLOAD_CRC32 "Verify decompressed payload CRC32 in the packed launcher" OFF)

set(ww_xz_targets xz_embedded)
if(WW_PACK_RUNTIME AND NOT WW_PACKED_PAYLOAD_CRC32)
  # Keep the ordinary decoder strict; only the launcher may omit the payload check.
  list(APPEND ww_xz_targets ww_launcher_xz_embedded)
endif()
foreach(ww_xz_target IN LISTS ww_xz_targets)
  add_library(${ww_xz_target} STATIC
    src/xz_crc32.c
    src/xz_dec_lzma2.c
    src/xz_dec_stream.c
    src/xz_dec_bcj.c
  )
  target_include_directories(${ww_xz_target} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
  target_include_directories(${ww_xz_target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
  target_compile_features(${ww_xz_target} PUBLIC c_std_99)
  target_compile_definitions(${ww_xz_target} PRIVATE XZ_DEC_SINGLE XZ_DEC_X86)
  # Upstream sources have translation-unit-local helpers with overlapping names.
  set_target_properties(${ww_xz_target} PROPERTIES UNITY_BUILD OFF)
endforeach()
add_library(XZEmbedded::XZEmbedded ALIAS xz_embedded)
if(WW_PACK_RUNTIME)
  if(WW_PACKED_PAYLOAD_CRC32)
    add_library(XZEmbedded::Launcher ALIAS xz_embedded)
  else()
    target_compile_definitions(ww_launcher_xz_embedded PRIVATE WW_XZ_SKIP_BLOCK_CRC32)
    add_library(XZEmbedded::Launcher ALIAS ww_launcher_xz_embedded)
  endif()
endif()
