
add_library(Listener STATIC
                    listener.c
  
)

#ww api
target_include_directories(Listener PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(Listener ww)

target_compile_definitions(Listener PRIVATE  Listener_VERSION=0.1)

