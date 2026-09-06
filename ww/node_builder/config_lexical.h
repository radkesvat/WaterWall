#pragma once

#include "cJSON.h"
#include <stdbool.h>
#include <stddef.h>

#define WW_HOST_CORE_JSON_LIMIT  (2U * 1024U * 1024U)
#define WW_HOST_NODE_JSON_LIMIT  (8U * 1024U * 1024U)
#define WW_HOST_JSON_DEPTH_LIMIT 128U

#ifdef __cplusplus
extern "C"
{
#endif

    bool   configLexicalCheckEncoding(const char *input, size_t length);
    bool   configLexicalCheckTokens(const char *input, size_t length, size_t max_depth);
    bool   configLexicalCheckKeys(const cJSON *item);
    cJSON *configLexicalParse(const char *input, size_t length, size_t max_depth);

#ifdef __cplusplus
}
#endif
