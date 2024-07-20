
add_library(MuxClient STATIC
      mux_client.c

)

#ww api
target_include_directories(MuxClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(MuxClient PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(MuxClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/mux)

target_compile_definitions(MuxClient PRIVATE  MuxClient_VERSION=0.1)
