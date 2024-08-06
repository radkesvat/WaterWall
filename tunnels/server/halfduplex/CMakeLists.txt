
add_library(HalfDuplexServer STATIC
      halfduplex_server.c

)

target_link_libraries(HalfDuplexServer PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)


target_compile_definitions(HalfDuplexServer PRIVATE  HalfDuplexServer_VERSION=0.1)

