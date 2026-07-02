#include "Router/structure.h"
#include "modules/destination_ip/destination_ip.h"
#include "modules/source_ips/source_ips.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static line_t *testLineCreate(void)
{
    line_t *line = memoryAllocateZero(sizeof(*line));
    require(line != NULL, "failed to allocate test line");
    line->alive = true;
    return line;
}

static void testLineDestroy(line_t *line)
{
    addresscontextReset(&line->routing_context.src_ctx);
    addresscontextReset(&line->routing_context.dest_ctx);
    memoryFree(line);
}

static cJSON *parseJsonObject(const char *text)
{
    cJSON *json = cJSON_Parse(text);
    require(json != NULL, "failed to parse test JSON");
    require(cJSON_IsObject(json), "test JSON is not an object");
    return json;
}

static router_tstate_t testRouterStateOpen(void)
{
    router_tstate_t ts = {0};

    ts.geoip_db_path = stringDuplicate(ROUTER_GEOIP_TEST_DB);
    require(ts.geoip_db_path != NULL, "failed to duplicate GeoIP test DB path");

    int status = MMDB_open(ts.geoip_db_path, MMDB_MODE_MMAP, &ts.geoip_db);
    if (status != MMDB_SUCCESS)
    {
        fprintf(stderr, "failed to open GeoIP test DB %s: %s\n", ts.geoip_db_path, MMDB_strerror(status));
        exit(1);
    }

    ts.geoip_db_opened = true;
    return ts;
}

static router_rule_t parseSourceIpsRule(const char *json_text)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerSourceIpsParse(&rule, json, 0) == kRouterFieldPresent, "source-ips parse failed");
    cJSON_Delete(json);
    return rule;
}

static router_rule_t parseDestinationIpRule(const char *json_text)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerDestinationIpParse(&rule, json, 0) == kRouterFieldPresent, "destination-ip parse failed");
    cJSON_Delete(json);
    return rule;
}

static bool sourceIpsRuleParseSucceeds(const char *json_text)
{
    router_rule_t       rule   = {0};
    cJSON              *json   = parseJsonObject(json_text);
    router_field_parse_t result = routerSourceIpsParse(&rule, json, 0);

    routerSourceIpsDestroy(&rule);
    cJSON_Delete(json);
    return result == kRouterFieldPresent;
}

static void testSourceGeoipMatchAndMiss(router_tstate_t *ts)
{
    line_t *line = testLineCreate();
    require(addresscontextSetIpAddress(&line->routing_context.src_ctx, "2.125.160.216"), "failed to set GB source IP");

    router_match_ctx_t mctx = {.router_state = ts, .line = line};

    router_rule_t gb_rule = parseSourceIpsRule("{\"source-ips\":\"GeoIP:gB\"}");
    require(routerSourceIpsMatch(&gb_rule, &mctx), "geoip:gb did not match 2.125.160.216");
    routerSourceIpsDestroy(&gb_rule);

    router_rule_t fr_rule = parseSourceIpsRule("{\"source-ips\":\"geoip:fr\"}");
    require(! routerSourceIpsMatch(&fr_rule, &mctx), "geoip:fr matched GB country.iso_code unexpectedly");
    routerSourceIpsDestroy(&fr_rule);

    testLineDestroy(line);
}

static void testDestinationIpv6Geoip(router_tstate_t *ts)
{
    line_t *line = testLineCreate();
    require(addresscontextSetIpAddress(&line->routing_context.dest_ctx, "2001:218::1"), "failed to set JP IPv6 dest IP");

    router_rule_t      rule = parseDestinationIpRule("{\"destination-ip\":\"geoip:jp\"}");
    router_match_ctx_t mctx = {.router_state = ts, .line = line};

    require(routerDestinationIpMatch(&rule, &mctx), "geoip:jp did not match 2001:218::1");

    routerDestinationIpDestroy(&rule);
    testLineDestroy(line);
}

static void testMixedNumericAndGeoipOrSemantics(router_tstate_t *ts)
{
    line_t *line = testLineCreate();
    require(addresscontextSetIpAddress(&line->routing_context.src_ctx, "50.114.0.1"), "failed to set US source IP");

    router_match_ctx_t mctx = {.router_state = ts, .line = line};

    router_rule_t geo_rule = parseSourceIpsRule("{\"source-ips\":[\"203.0.113.0/24\",\"geoip:us\"]}");
    require(routerSourceIpsMatch(&geo_rule, &mctx), "mixed source-ips did not match through GeoIP branch");
    routerSourceIpsDestroy(&geo_rule);

    require(addresscontextSetIpAddress(&line->routing_context.src_ctx, "2.125.160.216"), "failed to set numeric source IP");

    router_rule_t numeric_rule = parseSourceIpsRule("{\"source-ips\":[\"2.125.160.216/32\",\"geoip:fr\"]}");
    require(routerSourceIpsMatch(&numeric_rule, &mctx), "mixed source-ips did not match through numeric branch");
    routerSourceIpsDestroy(&numeric_rule);

    testLineDestroy(line);
}

static void testDomainDestinationDoesNotMatchGeoip(router_tstate_t *ts)
{
    line_t *line = testLineCreate();
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, "example.com");

    router_rule_t      rule = parseDestinationIpRule("{\"destination-ip\":\"geoip:us\"}");
    router_match_ctx_t mctx = {.router_state = ts, .line = line};

    require(! routerDestinationIpMatch(&rule, &mctx), "domain destination matched destination-ip geoip rule");

    routerDestinationIpDestroy(&rule);
    testLineDestroy(line);
}

static void testInvalidGeoipTokens(void)
{
    require(! sourceIpsRuleParseSucceeds("{\"source-ips\":\"geoip:\"}"), "geoip: token was accepted");
    require(! sourceIpsRuleParseSucceeds("{\"source-ips\":\"geoip:usa\"}"), "geoip:usa token was accepted");
    require(! sourceIpsRuleParseSucceeds("{\"source-ips\":\"geoip:1r\"}"), "geoip:1r token was accepted");
}

static void testGeoipRequiresDbPath(void)
{
    router_geoip_code_t code = {.code = {'U', 'S', '\0'}};
    router_rule_t       rule = {
        .source_ips = {
            .geoip_codes       = &code,
            .geoip_codes_count = 1,
        },
    };
    router_tstate_t ts = {
        .rules       = &rule,
        .rules_count = 1,
    };

    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL, "failed to allocate settings object");
    require(! routerGeoipOpenIfNeeded(&ts, settings), "geoip rules were accepted without geoip-db-path");
    cJSON_Delete(settings);
}

int main(void)
{
    router_tstate_t ts = testRouterStateOpen();

    testSourceGeoipMatchAndMiss(&ts);
    testDestinationIpv6Geoip(&ts);
    testMixedNumericAndGeoipOrSemantics(&ts);
    testDomainDestinationDoesNotMatchGeoip(&ts);
    testInvalidGeoipTokens();
    testGeoipRequiresDbPath();

    routerGeoipClose(&ts);
    return 0;
}
