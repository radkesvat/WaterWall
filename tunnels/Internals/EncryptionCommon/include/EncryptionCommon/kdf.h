#pragma once

#include "wcrypto.h"

/* The caller validates the credential lengths for the selected profile. */
WCRYPTO_MUST_USE wcrypto_status_t encryptionDeriveBaseKey(const char *password, size_t password_len, const char *salt,
                                                          size_t salt_len, uint32_t iterations, bool packet_mode,
                                                          uint8_t out_key[32]);
