
add_library(HalfDuplexClient STATIC
      halfduplex_client.c

)

target_link_libraries(HalfDuplexClient PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_compile_definitions(HalfDuplexClient PRIVATE  HalfDuplexClient_VERSION=0.1)
