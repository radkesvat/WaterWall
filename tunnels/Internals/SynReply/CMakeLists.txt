add_library(SynReply STATIC
    instance/create.c
    instance/node.c
    upstream/fin.c
    upstream/payload.c
    downstream/fin.c
)
target_include_directories(SynReply PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(SynReply PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/SynReply)
target_link_libraries(SynReply PRIVATE ww)
if(NOT APPLE)
    target_precompile_headers(SynReply REUSE_FROM ww)
endif()
