add_library(DnsLineClient STATIC
                    common/client.c
                    common/codec.c
                    common/cache.c
                    common/config.c
)

target_include_directories(DnsLineClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(DnsLineClient ww)
if(NOT APPLE)
    target_precompile_headers(DnsLineClient REUSE_FROM ww)
endif()
