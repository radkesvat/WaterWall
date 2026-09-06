add_library(xz_embedded STATIC
  src/xz_crc32.c
  src/xz_dec_lzma2.c
  src/xz_dec_stream.c
  src/xz_dec_bcj.c
)
add_library(XZEmbedded::XZEmbedded ALIAS xz_embedded)

target_include_directories(xz_embedded PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(xz_embedded PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(xz_embedded PUBLIC c_std_99)
target_compile_definitions(xz_embedded PRIVATE
  XZ_DEC_SINGLE
  XZ_DEC_X86
)
# Upstream sources have translation-unit-local helpers with overlapping names.
set_target_properties(xz_embedded PROPERTIES UNITY_BUILD OFF)
