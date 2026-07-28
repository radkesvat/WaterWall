#pragma once

#include "wwapi.h"

/**
 * Decode the historical HTTP2-Settings Base64URL form.
 *
 * HTTP policy permits SP/HTAB anywhere and ignores any number of terminal '='
 * bytes. A non-padding byte after the first '=' remains invalid. The generic
 * Base64URL decoder intentionally stays strict.
 */
bool httpserverBase64UrlDecodeCompat(const char *source, uint8_t *destination, size_t destination_capacity,
                                     size_t *output_length);
