#pragma once

#include "structure.h"

/*
 * "attributes" matcher.
 *
 * Metadata-based matching. The field must be a JSON array of attribute names.
 */
router_field_parse_t routerAttributesParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerAttributesMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerAttributesDestroy(router_rule_t *rule);
