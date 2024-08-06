
add_library(TunDevice STATIC
                    listener.c
  
)

target_link_libraries(TunDevice ww)

target_compile_definitions(TunDevice PRIVATE  TunDevice_VERSION=0.1)

