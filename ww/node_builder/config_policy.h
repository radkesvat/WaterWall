#pragma once

#include "cJSON.h"
#include "wlibc.h"

#define WW_HOST_CORE_JSON_LIMIT  (2U * 1024U * 1024U)
#define WW_HOST_NODE_JSON_LIMIT  (8U * 1024U * 1024U)
#define WW_HOST_JSON_DEPTH_LIMIT 128U

/* Main startup owner selects this once, before parsing or creating threads.
 * There is deliberately no JSON/environment setting or runtime reset. */
void        configPolicyRestrict(void);
bool        configPolicyIsRestricted(void);
const char *configPolicyDiagnostic(const char *identifier);

/* Bounded input, excluding the terminating NUL. Caller closes the stream. */
char *configPolicyRead(FILE *input, size_t limit, size_t *length);
/* Validate raw encoding before comment stripping or any strlen-based consumer. */
bool configPolicyCheckEncoding(const char *input, size_t length);
/* Strict whole-document cJSON parse, with bounded diagnostics and depth. */
cJSON *configPolicyParse(const char *input, size_t length);
