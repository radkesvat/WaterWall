add_library(SocksAddress STATIC src/address_codec.c)
target_include_directories(SocksAddress PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
