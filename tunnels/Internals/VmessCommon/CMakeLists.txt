add_library(VmessCommon STATIC src/crypto.c src/options.c src/packetaddr.c)

target_include_directories(VmessCommon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(VmessCommon PRIVATE ww OpenSSL::Crypto)
if(NOT APPLE)
    target_precompile_headers(VmessCommon REUSE_FROM ww)
endif()

# Compile the capability probe without linking a not-yet-built static provider.
# The actual node link verifies that the provider exports the declared function.
function(vmess_check_openssl)
  get_target_property(pinned_version OpenSSL::Crypto WW_PINNED_OPENSSL_VERSION)
  if(pinned_version AND pinned_version VERSION_GREATER_EQUAL "3.3")
    return()
  endif()
  include(CheckSymbolExists)
  set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto)
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  check_symbol_exists(EVP_DigestSqueeze "openssl/evp.h" VMESS_HAVE_DIGEST_SQUEEZE_DECL)
  if(NOT VMESS_HAVE_DIGEST_SQUEEZE_DECL)
    message(FATAL_ERROR "VMess requires OpenSSL with EVP_DigestSqueeze (3.3 or newer)")
  endif()
endfunction()
vmess_check_openssl()
