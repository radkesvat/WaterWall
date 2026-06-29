#pragma once

#include "structure.h"

/*
 * "username" matcher.
 *
 * Matches raw authenticated credential markers attached to the line. When a
 * rule also has "password", the username and password must match the same
 * credential marker. Matching is exact and case-sensitive.
 */
router_field_parse_t routerUsernameParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerUsernameMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerUsernameDestroy(router_rule_t *rule);
