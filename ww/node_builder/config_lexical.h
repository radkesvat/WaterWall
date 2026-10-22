#pragma once

#include "cJSON.h"
#include <stdbool.h>
#include <stddef.h>

#define WW_HOST_CORE_JSON_LIMIT  (2U * 1024U * 1024U)
#define WW_HOST_NODE_JSON_LIMIT  (8U * 1024U * 1024U)
#define WW_HOST_JSON_DEPTH_LIMIT 128U

/* Static category text never contains source bytes. Tree-wide checks report
 * the document-end offset; lexical and syntax errors report their byte position. */
typedef struct config_lexical_error_s
{
    const char *category;
    size_t      offset;
} config_lexical_error_t;

#ifdef __cplusplus
extern "C"
{
#endif

    bool   configLexicalCheckEncoding(const char *input, size_t length);
    bool   configLexicalCheckEncodingQuiet(const char *input, size_t length);
    bool   configLexicalCheckTokens(const char *input, size_t length, size_t max_depth);
    bool   configLexicalCheckKeys(const cJSON *item);
    cJSON *configLexicalParse(const char *input, size_t length, size_t max_depth);
    /* Runtime input uses the same strict parser without configuration diagnostics. */
    cJSON *configLexicalParseQuiet(const char *input, size_t length, size_t max_depth);
    /* Additional lexical value limit for small protocol envelopes. Host configuration
     * parsing keeps its existing limits. Bounds are checked before tree allocation. */
    cJSON *configLexicalParseBounded(const char *input, size_t length, size_t max_depth, size_t max_values);
    cJSON *configLexicalParseBoundedQuiet(const char *input, size_t length, size_t max_depth, size_t max_values);
    /* Before deleting a fully parsed but rejected tree, invoke before_delete.
     * The callback must not free the tree. The caller owns cleanup on success.
     * This does not expose partial trees discarded inside cJSON on syntax errors. */
    cJSON *configLexicalParseBoundedQuietWithCleanup(const char *input, size_t length, size_t max_depth,
                                                     size_t max_values, void (*before_delete)(cJSON *));
    /* Quiet parse with the same cleanup contract. A non-NULL error is cleared
     * on entry and receives a source-free reason if parsing fails. */
    cJSON *configLexicalParseBoundedWithError(const char *input, size_t length, size_t max_depth, size_t max_values,
                                              void (*before_delete)(cJSON *), config_lexical_error_t *error);

#ifdef __cplusplus
}
#endif
