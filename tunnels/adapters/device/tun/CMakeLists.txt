
add_library(TunDevice STATIC
                    tun_device.c
  
)

target_link_libraries(TunDevice ww)

target_include_directories(TunDevice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../shared/layer3)

target_compile_definitions(TunDevice PRIVATE  TunDevice_VERSION=0.1)

