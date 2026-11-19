/*
 * Covers: router geoip; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testRouterStateOpen, testSourceGeoipMatchAndMiss, testDestinationIpv6Geoip,
 * testMixedNumericAndGeoipOrSemantics, testDomainDestinationDoesNotMatchGeoip, testInvalidGeoipTokens,
 * testNegatedTokenForms, testNegatedGeoipOutcomes, testGeoipRequiresDbPath
 * Checks: Assertion labels include: test JSON is not an object; source-ips parse failed; destination-ip
 * parse failed; 2.125.160.216
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.router_geoip_unit
 */
#include "Router/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "modules/destination_ip/destination_ip.h"
#include "modules/source_ips/source_ips.h"


static line_t *testLineCreate(void)
{
    line_t *line = memoryAllocateCacheAlignedZero(sizeof(*line));
    require(line != NULL, "failed to allocate test line");
    memorySet(line->active_tunnels_mask, 0xFF, sizeof(line->active_tunnels_mask));
    line->alive = true;
    return line;
}

static void testLineDestroy(line_t *line)
{
    addresscontextReset(&line->routing_context.src_ctx);
    addresscontextReset(&line->routing_context.dest_ctx);
    memoryFreeAligned(line);
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

static void testNegatedTokenForms(void)
{
    static const char *const cases[] = {
        "{\"source-ips\":\"!geoip:ir\"}",
        "{\"source-ips\":[\"!GeoIP:iR\"]}",
        "{\"destination-ip\":\"!GeoIP:iR\"}",
        "{\"destination-ip\":[\"!geoip:ir\"]}",
    };
    bool all_accepted = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        router_rule_t        rule = {0};
        cJSON               *json = parseJsonObject(cases[i]);
        router_field_parse_t result =
            i < 2 ? routerSourceIpsParse(&rule, json, 0) : routerDestinationIpParse(&rule, json, 0);
        if (result != kRouterFieldPresent)
        {
            fprintf(stderr, "negated token form rejected: %s\n", cases[i]);
            all_accepted = false;
        }
        else
        {
            const router_geoip_code_t *codes = i < 2 ? rule.source_ips.geoip_codes : rule.destination_ip.geoip_codes;
            const uint32_t count = i < 2 ? rule.source_ips.geoip_codes_count : rule.destination_ip.geoip_codes_count;
            require(count == 1, "negative country token was not counted");
            require(codes[0].negated && stringCompare(codes[0].code, "IR") == 0,
                    "negative country token was not normalized or marked negated");
        }
        routerSourceIpsDestroy(&rule);
        routerDestinationIpDestroy(&rule);
        cJSON_Delete(json);
    }
    require(all_accepted, "negated scalar/array tokens must parse in both IP fields");
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
    require(addresscontextSetIpAddress(&line->routing_context.dest_ctx, "2001:218::1"),
            "failed to set JP IPv6 dest IP");

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

    require(addresscontextSetIpAddress(&line->routing_context.src_ctx, "2.125.160.216"),
            "failed to set numeric source IP");

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
    rule = parseDestinationIpRule("{\"destination-ip\":\"!geoip:ir\"}");
    require(! routerDestinationIpMatch(&rule, &mctx), "domain destination matched negative GeoIP token");
    require(! mctx.evaluation_failed, "domain destination failed GeoIP evaluation");
    routerDestinationIpDestroy(&rule);
    testLineDestroy(line);
}

static void testNegatedGeoipOutcomes(router_tstate_t *ts)
{
    // Confirm that the fixture's documentation address really has no database record.
    address_context_t absent = {0};
    require(addresscontextSetIpAddress(&absent, "192.0.2.1"), "failed to set absent fixture IP");
    sockaddr_u addr             = {0};
    addr.sin.sin_family         = AF_INET;
    addr.sin.sin_addr.s_addr    = absent.ip_address.u_addr.ip4.addr;
    int                  error  = MMDB_SUCCESS;
    MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&ts->geoip_db, &addr.sa, &error);
    require(error == MMDB_SUCCESS && ! result.found_entry, "no-record fixture address unexpectedly has a record");

    static const struct
    {
        const char *patterns;
        const char *ip;
        bool        matches;
    } cases[] = {
        {"\"!GeoIP:iR\"", "2.125.160.216", true},
        {"[\"!geoip:gb\"]", "2.125.160.216", false},
        {"\"!geoip:us\"", "50.114.0.1", false},
        {"[\"!geoip:ir\"]", "50.114.0.1", true},
        {"\"!geoip:jp\"", "2001:218::1", false},
        {"[\"!geoip:ir\"]", "2001:218::1", true},
        {"\"geoip:ir\"", "192.0.2.1", false},
        {"\"!geoip:ir\"", "192.0.2.1", true},
        {"\"!geoip:ir\"", NULL, false},
        {"\"geoip:ir\"", NULL, false},
        {"[\"10.0.0.0/8\",\"geoip:us\",\"!geoip:gb\"]", "50.114.0.1", true},
        {"[\"10.0.0.0/8\",\"geoip:us\",\"!geoip:gb\"]", "2.125.160.216", false},
        {"[\"10.0.0.0/8\",\"!geoip:ir\"]", "10.1.2.3", true},
        {"[\"geoip:gb\",\"!geoip:gb\"]", "2.125.160.216", true},
        {"[\"geoip:gb\",\"!geoip:gb\"]", "50.114.0.1", true},
        {"[\"geoip:ir\",\"!geoip:ir\"]", "192.0.2.1", true},
        {"[\"!geoip:ir\",\"!geoip:de\"]", "2.125.160.216", true},
    };
    for (unsigned field = 0; field < 2; ++field)
    {
        const char *key = field == 0 ? "source-ips" : "destination-ip";
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        {
            router_rule_t rule     = {0};
            cJSON        *json     = cJSON_CreateObject();
            cJSON        *patterns = cJSON_Parse(cases[i].patterns);
            require(patterns != NULL && cJSON_AddItemToObject(json, key, patterns), "failed to create condition JSON");
            router_field_parse_t parsed =
                field == 0 ? routerSourceIpsParse(&rule, json, 0) : routerDestinationIpParse(&rule, json, 0);
            require(parsed == kRouterFieldPresent, "IP outcome condition failed to parse");

            line_t            *line = testLineCreate();
            address_context_t *ctx  = field == 0 ? &line->routing_context.src_ctx : &line->routing_context.dest_ctx;
            if (cases[i].ip != NULL)
                require(addresscontextSetIpAddress(ctx, cases[i].ip), "failed to set outcome IP");
            router_match_ctx_t mctx = {.router_state = ts, .line = line};
            bool matched = field == 0 ? routerSourceIpsMatch(&rule, &mctx) : routerDestinationIpMatch(&rule, &mctx);
            if (matched != cases[i].matches || mctx.evaluation_failed)
                fprintf(stderr,
                        "unexpected %s result for %s at %s\n",
                        key,
                        cases[i].patterns,
                        cases[i].ip != NULL ? cases[i].ip : "<no address>");
            require(matched == cases[i].matches && ! mctx.evaluation_failed, "GeoIP outcome differs from contract");

            routerSourceIpsDestroy(&rule);
            routerDestinationIpDestroy(&rule);
            cJSON_Delete(json);
            testLineDestroy(line);
        }
    }
}

static void testInvalidGeoipTokens(void)
{
    static const char *const invalid[] = {
        "geoip:",
        "geoip:usa",
        "geoip:1r",
        "!geoip:",
        "!geoip:usa",
        "!geoip:1r",
        "!!geoip:ir",
        "!192.0.2.1",
        "!10.0.0.0/8",
        "!geosite:ir",
        " !geoip:ir",
        "!geoip:ir ",
        "! geoip:ir",
        "!geoip: ir",
    };
    for (unsigned field = 0; field < 2; ++field)
    {
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        {
            // An earlier numeric and country entry also exercise partial-parse cleanup.
            router_rule_t rule     = {0};
            cJSON        *json     = cJSON_CreateObject();
            cJSON        *patterns = cJSON_AddArrayToObject(json, field == 0 ? "source-ips" : "destination-ip");
            cJSON_AddItemToArray(patterns, cJSON_CreateString("10.0.0.0/8"));
            cJSON_AddItemToArray(patterns, cJSON_CreateString("!geoip:ir"));
            cJSON_AddItemToArray(patterns, cJSON_CreateString(invalid[i]));
            router_field_parse_t parsed =
                field == 0 ? routerSourceIpsParse(&rule, json, 0) : routerDestinationIpParse(&rule, json, 0);
            require(parsed == kRouterFieldError, "malformed GeoIP or unsupported negative token was accepted");
            routerSourceIpsDestroy(&rule);
            routerDestinationIpDestroy(&rule);
            cJSON_Delete(json);
        }
    }
}

static void testGeoipRequiresDbPath(void)
{
    for (unsigned field = 0; field < 2; ++field)
    {
        router_rule_t   rule = field == 0 ? parseSourceIpsRule("{\"source-ips\":\"!geoip:ir\"}")
                                          : parseDestinationIpRule("{\"destination-ip\":[\"!geoip:ir\"]}");
        router_tstate_t ts   = {.rules = &rule, .rules_count = 1};
        require(routerRuleTableNeedsGeoip(&ts), "negative-only rules did not require a database");
        require(! routerGeoipOpenIfNeeded(&ts, NULL), "negative-only rules accepted absent settings");
        cJSON *settings = cJSON_CreateObject();
        require(! routerGeoipOpenIfNeeded(&ts, settings), "negative-only rules accepted a missing database path");
        cJSON_AddStringToObject(settings, "geoip-db-path", "/nonexistent/waterwall-geoip-test.mmdb");
        require(! routerGeoipOpenIfNeeded(&ts, settings), "negative-only rules accepted an unreadable database");
        require(! ts.geoip_db_opened && ts.geoip_db_path == NULL, "failed database open left resources behind");
        cJSON_ReplaceItemInObjectCaseSensitive(settings, "geoip-db-path", cJSON_CreateString(ROUTER_GEOIP_TEST_DB));
        require(routerGeoipOpenIfNeeded(&ts, settings), "negative-only rules could not open the fixture database");
        routerGeoipClose(&ts);
        routerSourceIpsDestroy(&rule);
        routerDestinationIpDestroy(&rule);
        cJSON_Delete(settings);
    }
}

int main(void)
{
    testCaseSet("router_geoip_test");
    router_tstate_t ts = testRouterStateOpen();

    testNegatedTokenForms();
    testSourceGeoipMatchAndMiss(&ts);
    testDestinationIpv6Geoip(&ts);
    testMixedNumericAndGeoipOrSemantics(&ts);
    testDomainDestinationDoesNotMatchGeoip(&ts);
    testNegatedGeoipOutcomes(&ts);
    testInvalidGeoipTokens();
    testGeoipRequiresDbPath();

    routerGeoipClose(&ts);
    return 0;
}
