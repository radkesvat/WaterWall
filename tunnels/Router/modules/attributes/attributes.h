#pragma once

#include "structure.h"

/*
 * "attributes" matcher.
 *
 * Reserved for future metadata-based matching. The field is parsed structurally
 * (it must be a JSON array) but is not interpreted yet; the match implementation
 * is a stub that returns true.
 */
router_field_parse_t routerAttributesParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerAttributesMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerAttributesDestroy(router_rule_t *rule);
