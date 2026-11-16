/*
 * Covers: router evaluation failure; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseClassificationStopsAtEvaluationError, caseUndecidedLineIsClosedSafely,
 * caseHealthyGeoipStillRoutes, caseInitMetadataErrorBeforeProtocol, caseGeoipLookupOutcome,
 * caseNoEligibleAddress, caseNumericShortCircuit, caseTokenOrAndRuleOrdering
 * Checks: Assertion labels include: the evaluation-error flag and the classification result disagree; a
 * runtime evaluation error did not surface as kRouterClassifyError; an evaluation error still selected a
 * rule target; Router opened a branch before it decided on a route
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.router_evaluation_failure_unit
 */
/*
 * Router runtime evaluation-error propagation.
 *
 * A MaxMind lookup failure or a regex engine failure means Router could not establish the facts a rule asks
 * about. That is not "the rule did not match": falling through would silently route the connection somewhere the
 * operator never approved. Classification must stop at the first evaluation error, and a payload-dependent undecided
 * line must be closed toward the previous side only because its selected branch has not been initialized yet.
 */
#include "Router/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

#include <stdarg.h>

// ---------------------------------------------------------------------------
// MaxMind / regex injection
// ---------------------------------------------------------------------------

typedef enum router_injection_e
{
    kInjectNothing = 0,
    kInjectLookupError,
    kInjectGetValueError,
    kInjectBadIsoCode,
    kInjectBadIsoSize,
    kInjectBadIsoLetters,
    kInjectNoEntry,
    kInjectNoCountry,
    kInjectNoCountryPath,
    kInjectRegisteredCountry,
    kInjectBadRegisteredCountry,
    kInjectIpv6InIpv4Database,
    kInjectRegexError
} router_injection_t;

static router_injection_t g_injection = kInjectNothing;
static uint32_t           g_lookup_calls;
static uint32_t           g_value_calls;

MMDB_lookup_result_s __wrap_MMDB_lookup_sockaddr(const MMDB_s *const mmdb, const struct sockaddr *const sockaddr,
                                                 int *const mmdb_error);
int                  __wrap_MMDB_get_value(MMDB_entry_s *const start, MMDB_entry_data_s *const entry_data, ...);
int __wrap_cregex_match_opt(const cregex *re, const char *input, const char *input_end, struct cregex_match_opt opt);
int __real_cregex_match_opt(const cregex *re, const char *input, const char *input_end, struct cregex_match_opt opt);

MMDB_lookup_result_s __wrap_MMDB_lookup_sockaddr(const MMDB_s *const mmdb, const struct sockaddr *const sockaddr,
                                                 int *const mmdb_error)
{
    discard mmdb;
    discard sockaddr;
    ++g_lookup_calls;

    MMDB_lookup_result_s result;
    memoryZero(&result, sizeof(result));

    if (g_injection == kInjectLookupError)
    {
        *mmdb_error = MMDB_INVALID_DATA_ERROR;
        return result;
    }
    if (g_injection == kInjectIpv6InIpv4Database)
    {
        *mmdb_error = MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR;
        return result;
    }

    // Return a record unless the case is exercising a valid IP without a database entry.
    *mmdb_error         = MMDB_SUCCESS;
    result.found_entry  = g_injection != kInjectNoEntry;
    result.entry.mmdb   = mmdb;
    result.entry.offset = 0;
    return result;
}

int __wrap_MMDB_get_value(MMDB_entry_s *const start, MMDB_entry_data_s *const entry_data, ...)
{
    discard start;
    ++g_value_calls;
    va_list args;
    va_start(args, entry_data);
    const char *map_name = va_arg(args, const char *);
    va_end(args);
    memoryZero(entry_data, sizeof(*entry_data));

    if (g_injection == kInjectNoCountryPath ||
        ((g_injection == kInjectRegisteredCountry || g_injection == kInjectBadRegisteredCountry) &&
         stringCompare(map_name, "country") == 0))
        return MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
    if (g_injection == kInjectNoCountry)
        return MMDB_SUCCESS;

    if (g_injection == kInjectGetValueError || g_injection == kInjectBadRegisteredCountry)
    {
        return MMDB_INVALID_DATA_ERROR;
    }

    if (g_injection == kInjectBadIsoCode)
    {
        memoryZero(entry_data, sizeof(*entry_data));
        entry_data->has_data = true;
        // A country map whose iso_code is neither a string nor two bytes long is a corrupt database entry that one
        // peer address can select, so it must not be able to take the process down.
        entry_data->type      = MMDB_DATA_TYPE_UINT32;
        entry_data->data_size = 4;
        return MMDB_SUCCESS;
    }

    memoryZero(entry_data, sizeof(*entry_data));
    entry_data->has_data    = true;
    entry_data->type        = MMDB_DATA_TYPE_UTF8_STRING;
    entry_data->data_size   = 2;
    entry_data->utf8_string = "ir";
    if (g_injection == kInjectBadIsoSize)
    {
        entry_data->data_size   = 3;
        entry_data->utf8_string = "ira";
    }
    if (g_injection == kInjectBadIsoLetters)
        entry_data->utf8_string = "1r";
    return MMDB_SUCCESS;
}

int __wrap_cregex_match_opt(const cregex *re, const char *input, const char *input_end, struct cregex_match_opt opt)
{
    if (g_injection == kInjectRegexError)
    {
        return CREG_MATCHERROR;
    }
    return __real_cregex_match_opt(re, input, input_end, opt);
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

enum
{
    kTestLargeBufferSize = 4096
};

typedef struct router_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *router;
    tunnel_t        *next;
    tunnel_t        *rule_target;

    router_rule_t                   rules[2];
    router_geoip_code_t             geoip_code;
    router_geosite_compiled_list_t  geosite_list;
    router_geosite_compiled_list_t *geosite_list_slot[1];
    cregex                          regex_slot[1];
} router_fixture_t;

static void fixtureSetup(router_fixture_t *fixture)
{
    g_lookup_calls = 0;
    g_value_calls  = 0;
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    memoryZero(fixture->rules, sizeof(fixture->rules));
    memoryZero(&fixture->geosite_list, sizeof(fixture->geosite_list));
    memoryZero(fixture->regex_slot, sizeof(fixture->regex_slot));

    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev   = twfCreatePrevTunnel(&fixture->trace);
    fixture->router = tunnelCreate(NULL, sizeof(router_tstate_t), sizeof(router_lstate_t));
    twfRequire(fixture->router != NULL, "failed to create the Router tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    // A distinct fake branch, so a rule target being selected by mistake is visible instead of looking like the
    // default route.
    fixture->rule_target = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->router);
    tunnelBind(fixture->router, fixture->next);

    fixture->router->fnInitU    = &routerTunnelUpStreamInit;
    fixture->router->fnPayloadU = &routerTunnelUpStreamPayload;
    fixture->router->fnFinU     = &routerTunnelUpStreamFinish;

    router_tstate_t *ts = tunnelGetState(fixture->router);
    ts->rules           = fixture->rules;
    ts->rules_count     = 2;
    ts->geoip_db_opened = true; // every MaxMind entry point is wrapped, so no real database is needed

    // rule 0 is the one that fails to evaluate, rule 1 is an unconditional catch-all that must never be reached.
    fixture->geoip_code             = (router_geoip_code_t) {.code = {'I', 'R', '\0'}, .negated = false};
    fixture->rules[1].target_tunnel = fixture->rule_target;
}

static void useGeoipRule(router_fixture_t *fixture)
{
    fixture->rules[0].destination_ip.present           = true;
    fixture->rules[0].destination_ip.geoip_codes       = &fixture->geoip_code;
    fixture->rules[0].destination_ip.geoip_codes_count = 1;
    fixture->rules[0].target_tunnel                    = fixture->rule_target;
}

static void useGeositeRule(router_fixture_t *fixture)
{
    fixture->geosite_list.name                 = (char *) (uintptr_t) "test-list";
    fixture->geosite_list.regex_patterns       = fixture->regex_slot;
    fixture->geosite_list.regex_patterns_count = 1;
    fixture->geosite_list_slot[0]              = &fixture->geosite_list;

    fixture->rules[0].destination_domain.present             = true;
    fixture->rules[0].destination_domain.geosite_lists       = fixture->geosite_list_slot;
    fixture->rules[0].destination_domain.geosite_lists_count = 1;
    fixture->rules[0].target_tunnel                          = fixture->rule_target;
}

static void fixtureTeardown(router_fixture_t *fixture)
{
    twfRequireNoLeakedBuffers();
    memoryFree(fixture->prev);
    memoryFree(fixture->router);
    memoryFree(fixture->next);
    memoryFree(fixture->rule_target);
}

static line_t *makeIpv4Line(router_fixture_t *fixture)
{
    line_t *l = twfLineCreate(fixture->router->lstate_size);

    address_context_t *dest = &l->routing_context.dest_ctx;
    dest->type_ip           = true;
    dest->proto_tcp         = true;
    dest->ip_address.type   = IPADDR_TYPE_V4;
    // 203.0.113.7, a documentation address; the lookup itself is wrapped anyway.
    dest->ip_address.u_addr.ip4.addr = htonl(0xCB007107U);
    twfRequire(addresscontextSetIpAddress(&l->routing_context.src_ctx, "192.0.2.1"), "failed to set source IP");
    return l;
}

static line_t *makeDomainLine(router_fixture_t *fixture, const char *domain)
{
    line_t *l = twfLineCreate(fixture->router->lstate_size);
    addresscontextDomainSetByString(&l->routing_context.dest_ctx, domain);
    l->routing_context.dest_ctx.proto_tcp = true;
    return l;
}

static router_match_t classify(router_fixture_t *fixture, line_t *l)
{
    router_tstate_t *ts = tunnelGetState(fixture->router);
    router_lstate_t *ls = lineGetState(l, fixture->router);

    static const uint8_t kProbe[] = {'h', 'i'};

    router_match_ctx_t mctx = {
        .router_state = ts,
        .line         = l,
        .line_state   = ls,
        .payload      = kProbe,
        .payload_len  = (uint32_t) sizeof(kProbe),
    };

    router_match_t match = routerClassify(ts, &mctx);
    twfRequire(mctx.evaluation_failed == (match.result == kRouterClassifyError),
               "the evaluation-error flag and the classification result disagree");
    return match;
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

static void caseClassificationStopsAtEvaluationError(router_injection_t injection, bool geosite, bool negated,
                                                     bool source, const char *case_name)
{
    twfSetCase(case_name);

    router_fixture_t fixture;
    fixtureSetup(&fixture);

    line_t *l = NULL;
    if (geosite)
    {
        useGeositeRule(&fixture);
        l = makeDomainLine(&fixture, "example.com");
    }
    else
    {
        useGeoipRule(&fixture);
        fixture.geoip_code.negated = negated;
        if (source)
        {
            fixture.rules[0].destination_ip.present       = false;
            fixture.rules[0].source_ips.present           = true;
            fixture.rules[0].source_ips.geoip_codes       = &fixture.geoip_code;
            fixture.rules[0].source_ips.geoip_codes_count = 1;
        }
        l = makeIpv4Line(&fixture);
    }

    routerLinestateInitialize(lineGetState(l, fixture.router));

    g_injection          = injection;
    router_match_t match = classify(&fixture, l);
    g_injection          = kInjectNothing;

    twfRequireEqualU32((uint32_t) match.result,
                       (uint32_t) kRouterClassifyError,
                       "a runtime evaluation error did not surface as kRouterClassifyError");
    twfRequire(match.target == NULL, "an evaluation error still selected a rule target");

    // Also prove that failure cannot select the default when there is no later rule.
    router_tstate_t *ts = tunnelGetState(fixture.router);
    ts->rules_count     = 1;
    g_injection         = injection;
    match               = classify(&fixture, l);
    g_injection         = kInjectNothing;
    twfRequire(match.result == kRouterClassifyError && match.target == NULL, "an evaluation error selected default");

    routerLinestateDestroy(l, lineGetState(l, fixture.router));
    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

static void caseUndecidedLineIsClosedSafely(bool negated)
{
    twfSetCase("an undecided line closes toward the previous side only");

    router_fixture_t fixture;
    fixtureSetup(&fixture);
    useGeoipRule(&fixture);
    fixture.geoip_code.negated = negated;

    /* Root sniffing deliberately makes this configuration payload-dependent.
     * Metadata-only GeoIP rules now commit during Init, while this fixture must
     * exercise an evaluation error before a branch becomes reachable. */
    router_tstate_t *ts = tunnelGetState(fixture.router);
    ts->sniffing_modes  = kRouterSniffHttp1;

    line_t        *l              = makeIpv4Line(&fixture);
    const uint32_t refc_at_start  = twfLineRefCount(l);
    const uint32_t recycled_start = twfRecycleCount();

    routerTunnelUpStreamInit(fixture.router, l);
    twfRequireEqualU32(fixture.trace.next_init, 0, "Router opened a branch before it decided on a route");

    sbuf_t *payload = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(payload, 4);
    memorySet(sbufGetMutablePtr(payload), 0x41, 4);

    g_injection = kInjectLookupError;
    routerTunnelUpStreamPayload(fixture.router, l, payload);
    g_injection = kInjectNothing;

    twfRequireEqualText(fixture.trace.seq, "f", "the undecided line did not close exactly the previous side");
    twfRequireEqualU32(fixture.trace.next_init, 0, "the default branch received Init after an evaluation error");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "the pending payload was routed after an evaluation error");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "the default branch received Finish it never opened");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "the previous side was not finished exactly once");
    twfRequireEqualU32(twfRecycleCount() - recycled_start, 1, "the pending payload was not recycled exactly once");
    twfRequireLineStateZeroed(l, fixture.router, "the undecided Router line state was not zeroed");
    twfRequireEqualU32(twfLineRefCount(l), refc_at_start, "the line reference count did not return to its start");

    twfLineDestroy(l);

    // A second line must still be routed once the database behaves again.
    memoryZero(&fixture.trace, sizeof(fixture.trace));
    line_t *sibling = makeIpv4Line(&fixture);
    routerTunnelUpStreamInit(fixture.router, sibling);

    sbuf_t *sibling_payload = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(sibling_payload, 4);
    memorySet(sbufGetMutablePtr(sibling_payload), 0x42, 4);
    routerTunnelUpStreamPayload(fixture.router, sibling, sibling_payload);

    twfRequireEqualU32(fixture.trace.prev_finish, 0, "the sibling line was closed even though nothing failed");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the sibling line did not open a branch");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "the sibling line did not replay its buffered payload");

    routerTunnelUpStreamFinish(fixture.router, sibling);
    twfRequireLineStateZeroed(sibling, fixture.router, "the sibling Router line state was not zeroed");
    twfLineDestroy(sibling);

    fixtureTeardown(&fixture);
}

static void caseHealthyGeoipStillRoutes(void)
{
    twfSetCase("a successful geoip match still selects its rule target");

    router_fixture_t fixture;
    fixtureSetup(&fixture);
    useGeoipRule(&fixture);

    line_t *l = makeIpv4Line(&fixture);
    routerLinestateInitialize(lineGetState(l, fixture.router));

    router_match_t match = classify(&fixture, l);

    twfRequireEqualU32((uint32_t) match.result,
                       (uint32_t) kRouterClassifyTarget,
                       "a healthy geoip lookup did not select the rule target");
    twfRequire(match.target == fixture.rule_target, "a healthy geoip lookup selected the wrong target");

    routerLinestateDestroy(l, lineGetState(l, fixture.router));
    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

static void caseInitMetadataErrorBeforeProtocol(bool negated)
{
    twfSetCase("metadata evaluation error closes before a later protocol rule");
    router_fixture_t fixture;
    fixtureSetup(&fixture);
    useGeoipRule(&fixture);
    fixture.geoip_code.negated             = negated;
    fixture.rules[1].protocol.present      = true;
    fixture.rules[1].protocol.wanted_flags = kAddressContextProtocolTls;
    router_tstate_t *ts                    = tunnelGetState(fixture.router);
    ts->needed_protocols                   = kAddressContextProtocolTls;

    line_t        *line               = makeIpv4Line(&fixture);
    const uint32_t initial_references = twfLineRefCount(line);
    g_injection                       = kInjectLookupError;
    routerTunnelUpStreamInit(fixture.router, line);
    g_injection = kInjectNothing;
    twfRequireEqualText(fixture.trace.seq, "f", "Init metadata failure did not finish only the previous side");
    twfRequireEqualU32(fixture.trace.next_init, 0, "Init metadata failure opened an outgoing branch");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "Init metadata failure finished an unopened branch");
    twfRequireLineStateZeroed(line, fixture.router, "Init metadata failure left Router state alive");
    twfRequireEqualU32(twfLineRefCount(line), initial_references, "Init metadata failure leaked a line reference");
    twfLineDestroy(line);
    fixtureTeardown(&fixture);
}

static void caseGeoipLookupOutcome(router_injection_t injection, bool negated, bool source, uint32_t value_reads,
                                   const char *case_name)
{
    twfSetCase(case_name);
    router_fixture_t fixture;
    fixtureSetup(&fixture);
    useGeoipRule(&fixture);
    fixture.geoip_code.negated = negated;
    if (source)
    {
        fixture.rules[0].destination_ip.present       = false;
        fixture.rules[0].source_ips.present           = true;
        fixture.rules[0].source_ips.geoip_codes       = &fixture.geoip_code;
        fixture.rules[0].source_ips.geoip_codes_count = 1;
    }
    router_tstate_t *ts = tunnelGetState(fixture.router);
    ts->rules_count     = 1;
    line_t *line        = makeIpv4Line(&fixture);
    routerLinestateInitialize(lineGetState(line, fixture.router));
    if (injection == kInjectIpv6InIpv4Database)
    {
        address_context_t *ctx = source ? &line->routing_context.src_ctx : &line->routing_context.dest_ctx;
        twfRequire(addresscontextSetIpAddress(ctx, "2001:db8::1"), "failed to set IPv6 address");
    }

    g_injection              = injection;
    router_match_t     match = classify(&fixture, line);
    router_match_ctx_t mctx  = {.router_state = ts, .line = line, .line_state = lineGetState(line, fixture.router)};
    router_match_t     init_match = routerClassifyDuringInit(ts, &mctx);
    g_injection                   = kInjectNothing;
    const bool has_country        = injection == kInjectRegisteredCountry;
    const bool expected           = has_country != negated; // The wrapped country, when present, is IR.
    twfRequire(match.result == (expected ? kRouterClassifyTarget : kRouterClassifyDefault),
               "ordinary GeoIP outcome did not apply token negation");
    twfRequire(match.target == (expected ? fixture.rule_target : NULL), "ordinary GeoIP selected the wrong target");
    twfRequire(init_match.result == match.result && init_match.target == match.target && ! mctx.evaluation_failed,
               "Init and deferred classification disagree about an ordinary GeoIP outcome");
    twfRequireEqualU32(g_lookup_calls, 2, "a field performed more than one country lookup per evaluation");
    twfRequireEqualU32(g_value_calls, value_reads * 2, "country lookup did not preserve fallback order");
    routerLinestateDestroy(line, lineGetState(line, fixture.router));
    twfLineDestroy(line);
    fixtureTeardown(&fixture);
}

static void caseNoEligibleAddress(void)
{
    twfSetCase("missing, domain-only and unsupported addresses cannot match negative countries");
    router_fixture_t fixture;
    fixtureSetup(&fixture);
    router_tstate_t  *ts  = tunnelGetState(fixture.router);
    address_context_t ctx = {0};
    for (unsigned kind = 0; kind < 3; ++kind)
    {
        if (kind == 1)
            addresscontextDomainSetByString(&ctx, "example.com");
        if (kind == 2)
        {
            addresscontextReset(&ctx);
            ctx.type_ip         = true;
            ctx.ip_address.type = IPADDR_TYPE_ANY;
        }
        for (unsigned negated = 0; negated < 2; ++negated)
        {
            fixture.geoip_code.negated = negated != 0;
            bool failed                = false;
            g_injection                = kInjectLookupError;
            bool matched               = routerGeoipCodesMatch(ts, &ctx, &fixture.geoip_code, 1, &failed);
            g_injection                = kInjectNothing;
            twfRequire(! matched && ! failed, "ineligible address became a country match or evaluation failure");
        }
    }
    twfRequireEqualU32(g_lookup_calls, 0, "ineligible address reached MaxMind");
    addresscontextReset(&ctx);
    fixtureTeardown(&fixture);
}

static void caseNumericShortCircuit(void)
{
    twfSetCase("numeric matches skip GeoIP in mixed negative fields");
    router_fixture_t fixture;
    fixtureSetup(&fixture);
    cJSON   *json    = cJSON_Parse("{\"source-ips\":[\"192.0.2.0/24\",\"!geoip:ir\"],"
                                   "\"destination-ip\":[\"203.0.113.0/24\",\"!geoip:ir\"]}");
    uint32_t present = 0;
    twfRequire(json != NULL && routerRuleParseConditions(&fixture.rules[0], json, 0, &present) && present == 2,
               "failed to parse mixed negative/numeric fields");
    fixture.rules[0].target_tunnel = fixture.rule_target;
    cJSON_Delete(json);
    line_t *line = makeIpv4Line(&fixture);
    routerLinestateInitialize(lineGetState(line, fixture.router));
    g_injection          = kInjectLookupError;
    router_match_t match = classify(&fixture, line);
    twfRequire(match.result == kRouterClassifyTarget && match.target == fixture.rule_target,
               "numeric matches failed under an injected GeoIP error");
    twfRequireEqualU32(g_lookup_calls, 0, "numeric match performed a GeoIP lookup");
    twfRequire(addresscontextSetIpAddress(&line->routing_context.dest_ctx, "198.51.100.7"), "failed to change IP");
    match       = classify(&fixture, line);
    g_injection = kInjectNothing;
    twfRequire(match.result == kRouterClassifyError && match.target == NULL,
               "numeric miss did not propagate the negative GeoIP evaluation error");
    twfRequireEqualU32(g_lookup_calls, 1, "numeric miss did not perform exactly one GeoIP lookup");
    routerRuleDestroyConditions(&fixture.rules[0]);
    routerLinestateDestroy(line, lineGetState(line, fixture.router));
    twfLineDestroy(line);
    fixtureTeardown(&fixture);
}

static void caseTokenOrAndRuleOrdering(void)
{
    twfSetCase("GeoIP token OR, field AND and first-match ordering");
    router_fixture_t fixture;
    fixtureSetup(&fixture);
    useGeoipRule(&fixture);
    fixture.rules[1].target_tunnel = fixture.next;
    router_geoip_code_t codes[]    = {
        {.code = "IR", .negated = false},
        {.code = "IR", .negated = true},
    };
    fixture.rules[0].destination_ip.geoip_codes       = codes;
    fixture.rules[0].destination_ip.geoip_codes_count = 2;
    line_t *line                                      = makeIpv4Line(&fixture);
    routerLinestateInitialize(lineGetState(line, fixture.router));
    router_match_t match = classify(&fixture, line);
    twfRequire(match.result == kRouterClassifyTarget && match.target == fixture.rule_target,
               "positive/negative OR did not select the first rule");
    twfRequireEqualU32(g_lookup_calls, 1, "country list performed multiple lookups");
    codes[0].negated = true;
    codes[1]         = (router_geoip_code_t) {.code = "DE", .negated = true};
    match            = classify(&fixture, line);
    twfRequire(match.target == fixture.rule_target, "negative countries were not OR-combined for an IR address");
    twfRequireEqualU32(g_lookup_calls, 2, "negative country list performed multiple lookups");

    fixture.rules[0].destination_ip.geoip_codes_count = 1;
    match                                             = classify(&fixture, line);
    twfRequire(match.result == kRouterClassifyTarget && match.target == fixture.next,
               "!geoip:ir matched Iran instead of selecting the later rule");
    router_tstate_t *ts = tunnelGetState(fixture.router);
    ts->rules_count     = 1;
    match               = classify(&fixture, line);
    twfRequire(match.result == kRouterClassifyDefault && match.target == NULL,
               "!geoip:ir did not fall through to default for Iran");
    codes[0]        = (router_geoip_code_t) {.code = "US", .negated = true};
    ts->rules_count = 2;
    match           = classify(&fixture, line);
    twfRequire(match.target == fixture.rule_target, "negative country match did not win over a later rule");

    router_port_range_t port                       = {.low = 443, .high = 443};
    fixture.rules[0].destination_port.present      = true;
    fixture.rules[0].destination_port.ranges       = &port;
    fixture.rules[0].destination_port.ranges_count = 1;
    match                                          = classify(&fixture, line);
    twfRequire(match.target == fixture.next, "negative GeoIP match bypassed another field's constraint");
    line->routing_context.dest_ctx.port = 443;
    match                               = classify(&fixture, line);
    twfRequire(match.target == fixture.rule_target, "matching GeoIP and port fields failed conjunction");
    routerLinestateDestroy(line, lineGetState(line, fixture.router));
    twfLineDestroy(line);
    fixtureTeardown(&fixture);
}

int main(void)
{
    for (unsigned source = 0; source < 2; ++source)
    {
        for (unsigned negated = 0; negated < 2; ++negated)
        {
            caseClassificationStopsAtEvaluationError(kInjectLookupError, false, negated, source, "MMDB lookup error");
            caseClassificationStopsAtEvaluationError(kInjectGetValueError, false, negated, source, "MMDB value error");
            caseClassificationStopsAtEvaluationError(kInjectBadIsoCode, false, negated, source, "ISO wrong type");
            caseClassificationStopsAtEvaluationError(kInjectBadIsoSize, false, negated, source, "ISO wrong size");
            caseClassificationStopsAtEvaluationError(kInjectBadIsoLetters, false, negated, source, "ISO nonletters");
            caseClassificationStopsAtEvaluationError(
                kInjectBadRegisteredCountry, false, negated, source, "registered country read error");
            caseGeoipLookupOutcome(kInjectNoEntry, negated, source, 0, "no country record");
            caseGeoipLookupOutcome(kInjectNoCountry, negated, source, 2, "record without country codes");
            caseGeoipLookupOutcome(kInjectNoCountryPath, negated, source, 2, "country maps absent");
            caseGeoipLookupOutcome(kInjectRegisteredCountry, negated, source, 2, "registered country fallback");
            caseGeoipLookupOutcome(kInjectIpv6InIpv4Database, negated, source, 0, "IPv6 in IPv4 database");
        }
    }
    caseClassificationStopsAtEvaluationError(kInjectRegexError, true, false, false, "cregex reports CREG_MATCHERROR");
    caseUndecidedLineIsClosedSafely(false);
    caseUndecidedLineIsClosedSafely(true);
    caseHealthyGeoipStillRoutes();
    caseInitMetadataErrorBeforeProtocol(false);
    caseInitMetadataErrorBeforeProtocol(true);
    caseNoEligibleAddress();
    caseNumericShortCircuit();
    caseTokenOrAndRuleOrdering();

    printf("router_evaluation_failure_test: all cases passed\n");
    return 0;
}
