/*
 * Router runtime evaluation-error propagation.
 *
 * A MaxMind lookup failure or a regex engine failure means Router could not establish the facts a rule asks
 * about. That is not "the rule did not match": falling through would silently route the connection somewhere the
 * operator never approved. Classification must stop at the first evaluation error, and a payload-dependent undecided
 * line must be closed toward the previous side only because its selected branch has not been initialized yet.
 */
#include "Router/structure.h"

#include "tunnel_line_failure_harness.h"

// ---------------------------------------------------------------------------
// MaxMind / regex injection
// ---------------------------------------------------------------------------

typedef enum router_injection_e
{
    kInjectNothing = 0,
    kInjectLookupError,
    kInjectGetValueError,
    kInjectBadIsoCode,
    kInjectRegexError
} router_injection_t;

static router_injection_t g_injection = kInjectNothing;

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

    MMDB_lookup_result_s result;
    memoryZero(&result, sizeof(result));

    if (g_injection == kInjectLookupError)
    {
        *mmdb_error = MMDB_INVALID_DATA_ERROR;
        return result;
    }

    // Every geoip case that gets past the lookup needs an entry to read the ISO code from.
    *mmdb_error         = MMDB_SUCCESS;
    result.found_entry  = true;
    result.entry.mmdb   = mmdb;
    result.entry.offset = 0;
    return result;
}

int __wrap_MMDB_get_value(MMDB_entry_s *const start, MMDB_entry_data_s *const entry_data, ...)
{
    discard start;

    if (g_injection == kInjectGetValueError)
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
    fixture->geoip_code             = (router_geoip_code_t) {.code = {'I', 'R', '\0'}};
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

static void caseClassificationStopsAtEvaluationError(router_injection_t injection, bool geosite, const char *case_name)
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

    routerLinestateDestroy(l, lineGetState(l, fixture.router));
    twfLineDestroy(l);
    fixtureTeardown(&fixture);
}

static void caseUndecidedLineIsClosedSafely(void)
{
    twfSetCase("an undecided line closes toward the previous side only");

    router_fixture_t fixture;
    fixtureSetup(&fixture);
    useGeoipRule(&fixture);

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

int main(void)
{
    caseClassificationStopsAtEvaluationError(kInjectLookupError, false, "MMDB_lookup_sockaddr generic error");
    caseClassificationStopsAtEvaluationError(kInjectGetValueError, false, "MMDB_get_value generic error");
    caseClassificationStopsAtEvaluationError(kInjectBadIsoCode, false, "country iso_code has the wrong type");
    caseClassificationStopsAtEvaluationError(kInjectRegexError, true, "cregex reports CREG_MATCHERROR");

    caseUndecidedLineIsClosedSafely();
    caseHealthyGeoipStillRoutes();

    printf("router_evaluation_failure_test: all cases passed\n");
    return 0;
}
