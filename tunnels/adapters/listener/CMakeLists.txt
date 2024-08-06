
add_library(Listener STATIC
                    listener.c
  
)

target_link_libraries(Listener ww)

target_compile_definitions(Listener PRIVATE  Listener_VERSION=0.1)

