#pragma once

#include "structure.h"

/*
 * "password" matcher.
 *
 * Matches raw authenticated credential markers attached to the line. When a
 * rule also has "username", the username and password must match the same
 * credential marker. Matching is exact and case-sensitive.
 */
router_field_parse_t routerPasswordParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerPasswordMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerPasswordDestroy(router_rule_t *rule);
