
add_library(TunDevice STATIC
                    tun_device.c
  
)

target_link_libraries(TunDevice ww)

target_compile_definitions(TunDevice PRIVATE  TunDevice_VERSION=0.1)

