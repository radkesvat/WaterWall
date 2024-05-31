
add_library(HalfDuplexClient STATIC
      halfduplex_client.c

)

#ww api
target_include_directories(HalfDuplexClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(HalfDuplexClient PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(HalfDuplexClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/halfduplex)


target_compile_definitions(HalfDuplexClient PRIVATE  HalfDuplexClient_VERSION=0.1)
