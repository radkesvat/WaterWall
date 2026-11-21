#include "modules/line_mark/line_mark.h"

#include "loggers/network_logger.h"

router_field_parse_t routerLineMarkParse(router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(rule_json, "line-mark");
    rule->line_mark    = (router_match_line_mark_t) {0};
    if (value == NULL)
        return kRouterFieldAbsent;
    if (! jsonObjectFieldStringsAreExact(rule_json, "line-mark") || ! cJSON_IsString(value) ||
        ! lineMarkParseHex(value->valuestring, &rule->line_mark.value))
    {
        LOGF("Router: rule %u \"line-mark\" must be a string of exactly 32 hexadecimal digits",
             (unsigned int) rule_index);
        return kRouterFieldError;
    }
    rule->line_mark.present = true;
    return kRouterFieldPresent;
}

bool routerLineMarkMatch(const router_rule_t *rule, router_match_ctx_t *mctx)
{
    if (! rule->line_mark.present)
        return true;
    const line_mark_t *mark = lineGetMark(mctx->line);
    return mark != NULL && memoryEqual(mark->bytes, rule->line_mark.value.bytes, kLineMarkSize);
}

void routerLineMarkDestroy(router_rule_t *rule)
{
    rule->line_mark = (router_match_line_mark_t) {0};
}
