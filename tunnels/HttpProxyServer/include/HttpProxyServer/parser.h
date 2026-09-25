#pragma once

#include "HttpProxyCommon/parser.h"

bool hpsRewriteHeader(const hps_header_t *h, bool response, bool client_http10, bool close, char *out, size_t capacity,
                      size_t *length);
bool hpsDecodeBasic(const char *value, char username[256], char password[256], char key[512]);
