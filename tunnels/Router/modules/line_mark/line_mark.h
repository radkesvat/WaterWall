#pragma once

#include "structure.h"

router_field_parse_t routerLineMarkParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                 routerLineMarkMatch(const router_rule_t *rule, router_match_ctx_t *mctx);
void                 routerLineMarkDestroy(router_rule_t *rule);
