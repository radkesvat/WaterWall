
add_library(MuxServer STATIC
      mux_server.c

)

#ww api
target_include_directories(MuxServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../ww)
target_link_libraries(MuxServer PUBLIC ww)

# add dependencies
include(${CMAKE_BINARY_DIR}/cmake/CPM.cmake)

target_include_directories(MuxServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/mux)

target_compile_definitions(MuxServer PRIVATE  MuxServer_VERSION=0.1)
