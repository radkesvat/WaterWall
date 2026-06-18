#pragma once

#include "structure.h"

/*
 * "password" matcher.
 *
 * Matches the raw password of the authenticated user attached to the line
 * against a list of passwords. The authenticating tunnel stores the raw password
 * on the line (lineGetAuthenticatedPassword); matching is exact and
 * case-sensitive.
 */
router_field_parse_t routerPasswordParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerPasswordMatch(const router_rule_t *rule, const router_match_ctx_t *mctx);
void                 routerPasswordDestroy(router_rule_t *rule);
