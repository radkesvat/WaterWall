
add_library(CaptureDevice STATIC

        caputre_device.c
  
)

target_link_libraries(CaptureDevice ww)

target_include_directories(CaptureDevice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared/layer3)

target_compile_definitions(CaptureDevice PRIVATE  CaptureDevice_VERSION=0.1)

