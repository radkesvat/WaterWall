
add_library(RawDevice STATIC
                    raw_device.c
  
)

target_link_libraries(RawDevice ww)

target_include_directories(RawDevice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared/layer3)

target_compile_definitions(RawDevice PRIVATE  RawDevice_VERSION=0.1)

