/*
 * Covers: DomainResolver DNS "chain" mode: flat dns-key parsing for the standalone node, the chain-mode
 * lifecycle hooks, chain resolution through dnslineclientResolve() reusing the ordinary completion path,
 * the recursion guard for resolver-origin lines, and downstream dispatch of an injected DNS query line to
 * DnsLineClient without reaching prev.
 * Setup: Real DomainResolver code with the explicit worker/line/neighbour fixture. The DnsLineClient runtime
 * entry points are linker-wrapped (dnslineclientConfigParse stays real) so this suite observes exactly what
 * the resolver hands to the client. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testConfigParse, testCoreModeHooks, testChainResolve, testInjectedLineDispatch, testRecursionGuard,
 * testResolveRefused
 * Checks: Assertion labels include: chain resolve reached adjacent Init early; injected line reached prev;
 * detach did not zero the injected line state; resolver-origin domain started a chain resolution
 * Limits: Component fixture only; the real DnsLineClient wire behaviour has its own suite.
 * CTest: waterwall.domainresolver_chain_unit
 */
#include "DomainResolver/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

static dnslineclient_t *const       kFakeClient = (dnslineclient_t *) (uintptr_t) 0x5100;
static dnslineclient_query_t *const kFakeQuery  = (dnslineclient_query_t *) (uintptr_t) 0x5200;

static tunnel_t               *resolver;
static unsigned                create_calls, destroy_calls, quiesce_calls, stop_calls;
static dnslineclient_open_fn   open_fn;
static dnslineclient_detach_fn detach_fn;
static tunnel_t               *client_host;

static unsigned             resolve_calls;
static int                  resolve_rc;
static LineDnsResolveFn     resolve_cb;
static line_t              *resolve_line;
static tunnel_t            *resolve_tunnel;
static enum domain_strategy resolve_strategy;
static char                 resolve_domain[64];

static unsigned est_calls, payload_calls, finish_calls, pause_calls, resume_calls;
static unsigned prev_est, prev_payload, prev_finish, prev_pause, prev_resume;
static unsigned next_init, next_finish;

dnslineclient_t *__wrap_dnslineclientCreate(const dnslineclient_config_t *cfg, tunnel_t *host,
                                            dnslineclient_open_fn open, dnslineclient_detach_fn detach);
void             __wrap_dnslineclientDestroy(dnslineclient_t *client);
void             __wrap_dnslineclientWorkerQuiesce(dnslineclient_t *client, wid_t wid);
void             __wrap_dnslineclientWorkerStop(dnslineclient_t *client, wid_t wid);
int              __wrap_dnslineclientResolve(dnslineclient_t *client, line_t *waiter, const char *domain,
                                             enum domain_strategy strategy, LineDnsResolveFn cb, tunnel_t *t, void *userdata);
void             __wrap_dnslineclientOnLineEst(dnslineclient_query_t *query, line_t *l);
void             __wrap_dnslineclientOnLinePayload(dnslineclient_query_t *query, line_t *l, sbuf_t *buf);
void             __wrap_dnslineclientOnLineFinish(dnslineclient_query_t *query, line_t *l);
void             __wrap_dnslineclientOnLinePause(dnslineclient_query_t *query, line_t *l);
void             __wrap_dnslineclientOnLineResume(dnslineclient_query_t *query, line_t *l);
int __wrap_lineResolveDomainServiceAsync(line_t *line, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata);

dnslineclient_t *__wrap_dnslineclientCreate(const dnslineclient_config_t *cfg, tunnel_t *host,
                                            dnslineclient_open_fn open, dnslineclient_detach_fn detach)
{
    twfRequire(cfg != NULL && cfg->servers_count == 1 && cfg->servers[0].port == 5353,
               "client received the wrong parsed configuration");
    ++create_calls;
    client_host = host;
    open_fn     = open;
    detach_fn   = detach;
    return kFakeClient;
}

void __wrap_dnslineclientDestroy(dnslineclient_t *client)
{
    twfRequire(client == kFakeClient, "destroyed the wrong client");
    ++destroy_calls;
}

void __wrap_dnslineclientWorkerQuiesce(dnslineclient_t *client, wid_t wid)
{
    twfRequire(client == kFakeClient && wid == 0, "quiesced the wrong client or worker");
    ++quiesce_calls;
}

void __wrap_dnslineclientWorkerStop(dnslineclient_t *client, wid_t wid)
{
    twfRequire(client == kFakeClient && wid == 0, "stopped the wrong client or worker");
    ++stop_calls;
}

int __wrap_dnslineclientResolve(dnslineclient_t *client, line_t *waiter, const char *domain,
                                enum domain_strategy strategy, LineDnsResolveFn cb, tunnel_t *t, void *userdata)
{
    twfRequire(client == kFakeClient && userdata == NULL, "chain resolve used the wrong client");
    ++resolve_calls;
    if (resolve_rc != ARES_SUCCESS)
        return resolve_rc;
    stringCopyN(resolve_domain, domain, sizeof(resolve_domain));
    resolve_cb       = cb;
    resolve_line     = waiter;
    resolve_tunnel   = t;
    resolve_strategy = strategy;
    lineRef(waiter);
    return ARES_SUCCESS;
}

static void requireInjectedBinding(line_t *l, const char *message)
{
    domainresolver_lstate_t *ls = lineGetState(l, resolver);
    twfRequire(ls->chain_query == kFakeQuery && ls->phase == kDomainResolverPhaseIdle, message);
}

void __wrap_dnslineclientOnLineEst(dnslineclient_query_t *query, line_t *l)
{
    twfRequire(query == kFakeQuery, "Est carried the wrong query");
    requireInjectedBinding(l, "Est reached the client without its binding");
    ++est_calls;
}

void __wrap_dnslineclientOnLinePayload(dnslineclient_query_t *query, line_t *l, sbuf_t *buf)
{
    twfRequire(query == kFakeQuery, "payload carried the wrong query");
    requireInjectedBinding(l, "payload reached the client without its binding");
    ++payload_calls;
    lineReuseBuffer(l, buf);
}

void __wrap_dnslineclientOnLineFinish(dnslineclient_query_t *query, line_t *l)
{
    twfRequire(query == kFakeQuery, "Finish carried the wrong query");
    twfRequireLineStateZeroed(l, resolver, "detach did not zero the injected line state before Finish");
    ++finish_calls;
}

void __wrap_dnslineclientOnLinePause(dnslineclient_query_t *query, line_t *l)
{
    twfRequire(query == kFakeQuery, "Pause carried the wrong query");
    requireInjectedBinding(l, "Pause reached the client without its binding");
    ++pause_calls;
}

void __wrap_dnslineclientOnLineResume(dnslineclient_query_t *query, line_t *l)
{
    twfRequire(query == kFakeQuery, "Resume carried the wrong query");
    requireInjectedBinding(l, "Resume reached the client without its binding");
    ++resume_calls;
}

int __wrap_lineResolveDomainServiceAsync(line_t *line, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata)
{
    discard line;
    discard domain;
    discard service;
    discard socktype;
    discard callback;
    discard t;
    discard userdata;
    twfRequire(false, "chain mode used the worker c-ares path");
    return ARES_ENOTIMP;
}

static void prevEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++prev_est;
}
static void prevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    ++prev_payload;
    lineReuseBuffer(l, buf);
}
static void prevFinish(tunnel_t *t, line_t *l)
{
    discard t;
    ++prev_finish;
    lineDestroy(l);
}
static void prevPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++prev_pause;
}
static void prevResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++prev_resume;
}
static void nextInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++next_init;
}
static void nextFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++next_finish;
}

static void resetCounters(void)
{
    create_calls = destroy_calls = quiesce_calls = stop_calls = 0;
    resolve_calls = est_calls = payload_calls = finish_calls = pause_calls = resume_calls = 0;
    prev_est = prev_payload = prev_finish = prev_pause = prev_resume = 0;
    next_init = next_finish = 0;
    resolve_rc              = ARES_SUCCESS;
    resolve_cb              = NULL;
    resolve_line            = NULL;
    resolve_tunnel          = NULL;
    open_fn                 = NULL;
    detach_fn               = NULL;
    client_host             = NULL;
}

static tunnel_t *createWithSettings(const char *json_text)
{
    cJSON *settings = json_text != NULL ? cJSON_Parse(json_text) : NULL;
    twfRequire(json_text == NULL || settings != NULL, "test settings JSON is invalid");
    node_t    node = {.type = (char *) "DomainResolver", .node_settings_json = settings};
    tunnel_t *t    = domainresolverTunnelCreate(&node);
    if (settings != NULL)
        cJSON_Delete(settings);
    return t;
}

static void testConfigParse(void)
{
    twfSetCase("DomainResolver parses its flat dns keys strictly");

    tunnel_t *t = createWithSettings(NULL);
    twfRequire(t != NULL, "no settings failed creation");
    domainresolver_tstate_t *ts = tunnelGetState(t);
    twfRequire(ts->mode == kDnsLineClientModeCore && ts->inject == NULL && ts->inject_owner == NULL,
               "absent settings did not keep core mode");
    tunnelDestroy(t);

    t = createWithSettings("{\"strategy\":\"only-ipv4\"}");
    twfRequire(t != NULL && ((domainresolver_tstate_t *) tunnelGetState(t))->mode == kDnsLineClientModeCore,
               "omitted mode did not default to core");
    tunnelDestroy(t);

    // Without mode "chain" the DNS key names are not validated, so existing configs keep loading.
    t = createWithSettings("{\"timeout-ms\":\"2s\",\"servers\":\"x\"}");
    twfRequire(t != NULL && ((domainresolver_tstate_t *) tunnelGetState(t))->mode == kDnsLineClientModeCore,
               "mode-absent config with reused key names was rejected");
    tunnelDestroy(t);

    t = createWithSettings("{\"mode\":\"core\"}");
    twfRequire(t != NULL && ((domainresolver_tstate_t *) tunnelGetState(t))->mode == kDnsLineClientModeCore,
               "explicit core mode was refused");
    tunnelDestroy(t);

    t = createWithSettings("{\"mode\":\"chain\",\"servers\":[\"127.0.0.1:5353\"],\"timeout-ms\":500,\"tries\":3}");
    twfRequire(t != NULL, "valid chain settings failed creation");
    ts = tunnelGetState(t);
    twfRequire(ts->mode == kDnsLineClientModeChain && ts->inject_owner == t &&
                   ts->inject == domainresolverChainInjectNext && ts->chain_client == NULL,
               "standalone chain mode did not inject into its own next");
    twfRequire(ts->chain_cfg.servers_count == 1 && ts->chain_cfg.servers[0].port == 5353 &&
                   ts->chain_cfg.timeout_ms == 500 && ts->chain_cfg.tries == 3,
               "standalone chain settings were not stored");
    tunnelDestroy(t);

    twfRequire(createWithSettings("{\"mode\":\"chain\"}") == NULL, "chain mode without servers was accepted");
    twfRequire(createWithSettings("{\"mode\":\"chain\",\"servers\":[]}") == NULL,
               "chain mode with empty servers was accepted");
    twfRequire(createWithSettings("{\"mode\":7}") == NULL, "non-string mode was accepted");
    twfRequire(createWithSettings("{\"mode\":\"doh\"}") == NULL, "unknown mode was accepted");
    twfRequire(createWithSettings("{\"mode\":\"chain\",\"servers\":[\"dns.example\"]}") == NULL,
               "domain server was accepted");
    twfRequire(createWithSettings("{\"mode\":\"chain\",\"servers\":[\"1.1.1.1\"],\"timeout-ms\":\"2s\"}") == NULL,
               "non-integer timeout-ms was accepted");
    twfRequire(createWithSettings("{\"mode\":\"chain\",\"servers\":[\"1.1.1.1\"],\"fallback-to-core\":1}") == NULL,
               "non-boolean fallback-to-core was accepted");
}

static void testCoreModeHooks(void)
{
    twfSetCase("DomainResolver core mode lifecycle hooks are no-ops");
    resetCounters();
    tunnel_t *t = createWithSettings(NULL);
    twfRequire(t != NULL, "failed to create core resolver");
    t->onPrepare(t);
    t->onWorkerQuiesce(t, 0, wwLifecycleOwnedChildStop());
    t->onWorkerStop(t, 0, wwLifecycleOwnedChildStop());
    twfRequire(((domainresolver_tstate_t *) tunnelGetState(t))->chain_client == NULL, "core mode created a client");
    t->onDestroy(t, wwLifecycleOwnedChildStop());
    twfRequire(create_calls == 0 && quiesce_calls == 0 && stop_calls == 0 && destroy_calls == 0,
               "core mode reached DnsLineClient");
}

typedef struct chain_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    tunnel_t        *prev;
    tunnel_t        *next;
} chain_fixture_t;

static void fixtureSetup(chain_fixture_t *f)
{
    twfWorkerEnvSetup(&f->env, 4096, 32);
    resetCounters();
    resolver = createWithSettings("{\"mode\":\"chain\",\"servers\":[\"127.0.0.1:5353\"],\"strategy\":\"only-ipv4\"}");
    twfRequire(resolver != NULL, "failed to create chain resolver");
    f->prev = tunnelCreate(NULL, 0, 0);
    f->next = tunnelCreate(NULL, 0, 0);
    tunnelBind(f->prev, resolver);
    tunnelBind(resolver, f->next);
    f->prev->chain_index  = 0;
    resolver->chain_index = 1;
    f->next->chain_index  = 2;
    f->prev->fnEstD       = prevEst;
    f->prev->fnPayloadD   = prevPayload;
    f->prev->fnFinD       = prevFinish;
    f->prev->fnPauseD     = prevPause;
    f->prev->fnResumeD    = prevResume;
    f->next->fnInitU      = nextInit;
    f->next->fnFinU       = nextFinish;
    resolver->onPrepare(resolver);
    twfRequire(create_calls == 1 && client_host == resolver && open_fn == domainresolverChainOpenLine &&
                   detach_fn == domainresolverChainDetachLine,
               "onPrepare did not create the chain client with the resolver host hooks");
    twfLinePoolSetup(&f->lines, resolver->lstate_size, 4);
}

static void fixtureTeardown(chain_fixture_t *f)
{
    resolver->onWorkerQuiesce(resolver, 0, wwLifecycleOwnedChildStop());
    resolver->onWorkerStop(resolver, 0, wwLifecycleOwnedChildStop());
    twfRequire(quiesce_calls == 1 && stop_calls == 1, "worker hooks did not reach the chain client");
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&f->lines);
    tunnelDestroy(f->next);
    tunnelDestroy(f->prev);
    resolver->onDestroy(resolver, wwLifecycleOwnedChildStop());
    twfRequire(destroy_calls == 1, "onDestroy did not destroy the chain client");
    resolver = NULL;
    twfWorkerEnvTeardown(&f->env);
}

static line_t *domainLine(chain_fixture_t *f, bool resolver_origin)
{
    line_t *l = twfLinePoolCreateLine(&f->lines);
    lineRef(l);
    address_context_t *dest = lineGetDestinationAddressContext(l);
    addresscontextDomainSet(dest, "chain.invalid", 13);
    addresscontextSetPort(dest, 443);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
    addresscontextSetResolverOrigin(dest, resolver_origin);
    return l;
}

static void testChainResolve(void)
{
    twfSetCase("DomainResolver chain mode resolves through DnsLineClient and reuses the completion path");
    chain_fixture_t f;
    fixtureSetup(&f);

    line_t *line = domainLine(&f, false);
    tunnelUpStreamInit(resolver, line);
    twfRequire(resolve_calls == 1 && next_init == 0, "chain resolve reached adjacent Init early");
    twfRequire(resolve_line == line && resolve_tunnel == resolver &&
                   stringCompare(resolve_domain, "chain.invalid") == 0 && resolve_strategy == kDsOnlyIpV4,
               "chain resolve received the wrong waiter, domain or strategy");
    twfRequire(((domainresolver_lstate_t *) lineGetState(line, resolver))->phase == kDomainResolverPhaseResolving,
               "waiter line was not marked resolving");

    dns_resolved_addr_t answer = {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in)};
    struct sockaddr_in *addr   = (struct sockaddr_in *) &answer.addr;
    addr->sin_family           = AF_INET;
    addr->sin_addr.s_addr      = htonl(INADDR_LOOPBACK);
    resolve_cb(resolve_tunnel, resolve_line, NULL, ARES_SUCCESS, NULL, &answer, 1);
    lineUnref(resolve_line);
    twfRequire(next_init == 1 && addresscontextIsDomainResolved(lineGetDestinationAddressContext(line)),
               "chain result did not apply the address and open the path");
    twfRequire(! tunnelIsActiveForLine(resolver, line), "settled waiter line did not bypass the resolver");

    tunnelUpStreamFin(resolver, line);
    lineDestroy(line);
    lineUnref(line);

    line = domainLine(&f, false);
    tunnelUpStreamInit(resolver, line);
    twfRequire(resolve_calls == 2, "second chain resolve did not start");
    resolve_cb(resolve_tunnel, resolve_line, NULL, ARES_ETIMEOUT, NULL, NULL, 0);
    lineUnref(resolve_line);
    twfRequire(! lineIsAlive(line) && prev_finish == 1 && next_init == 1 && next_finish == 1,
               "chain failure did not close only the prev side");
    lineUnref(line);

    fixtureTeardown(&f);
}

static void testInjectedLineDispatch(void)
{
    twfSetCase("DomainResolver forwards an injected DNS line's downstream callbacks to DnsLineClient only");
    chain_fixture_t f;
    fixtureSetup(&f);

    line_t *line = twfLinePoolCreateLine(&f.lines);
    lineRef(line);
    address_context_t *dest = lineGetDestinationAddressContext(line);
    addresscontextSetIpAddress(dest, "127.0.0.1");
    addresscontextSetPort(dest, 5353);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_UDP);
    addresscontextSetResolverOrigin(dest, true);

    open_fn(resolver, line, kFakeQuery);
    twfRequire(next_init == 1 && resolve_calls == 0, "open did not inject the query line into next");
    requireInjectedBinding(line, "open did not bind the query to the line state");
    twfRequire(tunnelIsActiveForLine(resolver, line), "injected line bypassed the resolver");

    tunnelDownStreamEst(resolver, line);
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(buf, 1);
    tunnelDownStreamPayload(resolver, line, buf);
    tunnelDownStreamPause(resolver, line);
    tunnelDownStreamResume(resolver, line);
    twfRequire(est_calls == 1 && payload_calls == 1 && pause_calls == 1 && resume_calls == 1,
               "downstream callbacks did not reach DnsLineClient");
    tunnelDownStreamFin(resolver, line);
    twfRequire(finish_calls == 1, "downstream Finish did not reach DnsLineClient");
    twfRequire(prev_est == 0 && prev_payload == 0 && prev_finish == 0 && prev_pause == 0 && prev_resume == 0,
               "injected line reached prev");

    detach_fn(resolver, line); // idempotent after Finish already detached
    twfRequireLineStateZeroed(line, resolver, "repeated detach changed the line state");
    lineDestroy(line); // DnsLineClient is the creator of the query line
    lineUnref(line);

    // Owner-side close: detach before upstream Finish leaves nothing for later callbacks.
    line = twfLinePoolCreateLine(&f.lines);
    lineRef(line);
    dest = lineGetDestinationAddressContext(line);
    addresscontextSetIpAddress(dest, "127.0.0.1");
    addresscontextSetPort(dest, 5353);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_UDP);
    addresscontextSetResolverOrigin(dest, true);
    open_fn(resolver, line, kFakeQuery);
    detach_fn(resolver, line);
    twfRequireLineStateZeroed(line, resolver, "detach did not zero the injected line state");
    tunnelNextUpStreamFinish(resolver, line);
    twfRequire(next_finish == 1, "owner Finish did not reach next");
    lineDestroy(line);
    lineUnref(line);

    fixtureTeardown(&f);
}

static void testRecursionGuard(void)
{
    twfSetCase("DomainResolver refuses to chain-resolve a resolver-origin line");
    chain_fixture_t f;
    fixtureSetup(&f);

    line_t *line = domainLine(&f, true);
    tunnelUpStreamInit(resolver, line);
    twfRequire(resolve_calls == 0, "resolver-origin domain started a chain resolution");
    twfRequire(! lineIsAlive(line) && prev_finish == 1 && next_init == 0, "guarded line was not closed toward prev");
    lineUnref(line);

    fixtureTeardown(&f);
}

static void testResolveRefused(void)
{
    twfSetCase("DomainResolver closes the waiter when DnsLineClient refuses a request");
    chain_fixture_t f;
    fixtureSetup(&f);

    resolve_rc   = ARES_ECANCELLED;
    line_t *line = domainLine(&f, false);
    tunnelUpStreamInit(resolver, line);
    twfRequire(resolve_calls == 1 && ! lineIsAlive(line) && prev_finish == 1 && next_init == 0,
               "refused chain resolve did not close only prev");
    lineUnref(line);

    fixtureTeardown(&f);
}

int main(void)
{
    testConfigParse();
    testCoreModeHooks();
    testChainResolve();
    testInjectedLineDispatch();
    testRecursionGuard();
    testResolveRefused();
    return 0;
}
