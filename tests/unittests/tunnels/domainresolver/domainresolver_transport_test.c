/*
 * Covers: c-ares virtual socket transport, with real owner-worker pools and a
 * synchronous fake egress. Checks pending TCP establishment, copied/short writes,
 * independent receive/send pressure, input bounds, stale handles, Finish,
 * default UDP/TCP connection reuse, explicit idle retirement, and synchronous
 * DNS responses deferred until the enclosing c-ares call returns.
 * CTest: waterwall.domainresolver_transport_unit
 */
#include "DomainResolver/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

/* Exercise the private socket boundary without exposing test-only runtime APIs. */
#include "../../../../tunnels/Internals/DomainResolver/common/transport.c"

static tunnel_t *resolver;
static line_t   *observed_line;
static sbuf_t   *retained_write;
static unsigned  inits, writes, finishes, pauses, resumes, results, cancellations;
static unsigned  preparations, preparation_cleanups;
static bool      preparation_refuses;
static bool      init_establishes, init_finishes, init_pauses, answer_queries, submitting;
static bool      answer_ipv6, inject_empty_tcp;
static unsigned  a_questions, aaaa_questions;

static bool prepareOwned(tunnel_t *helper, tunnel_t *owner, line_t *line, void *storage)
{
    discard                  owner;
    domainresolver_lstate_t *ls = lineGetState(line, helper);
    twfRequire(ls->dns_transport != NULL, "owned preparation lost exact transport association");
    twfRequire(storage != NULL && ((uint8_t *) storage)[0] == 0, "owned preparation storage was not initialized");
    address_context_t *target = lineGetDestinationAddressContext(line);
    twfRequire(addresscontextDestinationIsPinned(target) && addresscontextIsResolverDns(target) && target->port == 53 &&
                   addresscontextIsIpType(target),
               "owned preparation lost authoritative target");
    ((uint8_t *) storage)[0] = 0x5a;
    ++preparations;
    return ! preparation_refuses;
}

static void destroyOwnedPreparation(tunnel_t *helper, tunnel_t *owner, line_t *line, void *storage)
{
    discard helper;
    discard owner;
    discard line;
    twfRequire(((uint8_t *) storage)[0] == 0x5a, "owned preparation storage was overwritten before cleanup");
    ++preparation_cleanups;
}

static void observeInit(tunnel_t *next, line_t *line)
{
    discard next;
    twfRequire(observed_line == NULL, "previous owned line was not released by fixture");
    ++inits;
    observed_line = line;
    lineRef(line);
    twfRequire(addresscontextIsResolverDns(lineGetDestinationAddressContext(line)), "DNS marker missing at Init");
    address_context_t *target = lineGetDestinationAddressContext(line);
    twfRequire(addresscontextDestinationIsPinned(target) && target->port == 53 && addresscontextIsIpType(target),
               "generated DNS endpoint was not pinned before outward Init");
    /* The fixture is the terminal peer consumer, like UdpConnector or the
     * logical target selection in a proxy client. */
    addresscontextSetDestinationPinned(target, false);
    twfRequire(linePrefersOrdinaryReadDownstream(line), "DNS endpoint did not request ordinary bytes");
    if (init_finishes)
        domainresolverTransportFinish(resolver, line);
    else if (init_establishes)
        domainresolverTransportEst(resolver, line);
    if (init_pauses)
        domainresolverTransportPause(resolver, line);
}

static void observeFinish(tunnel_t *next, line_t *line)
{
    discard next;
    discard line;
    ++finishes;
}

static void observePause(tunnel_t *next, line_t *line)
{
    discard next;
    discard line;
    ++pauses;
}

static void observeResume(tunnel_t *next, line_t *line)
{
    discard next;
    discard line;
    ++resumes;
}

static sbuf_t *makeInput(line_t *line, size_t length, int fill)
{
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(line), length, 32);
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), fill, length);
    return buf;
}

static void answerQuery(line_t *line, const uint8_t *query, size_t query_length, bool tcp)
{
    size_t end = 12;
    twfRequire(query_length > 16, "short DNS query");
    while (end < query_length && query[end] != 0)
        end += (size_t) query[end] + 1;
    end += 5;
    twfRequire(end <= query_length, "invalid DNS question");
    const bool   ipv4          = query[end - 4] == 0 && query[end - 3] == 1;
    twfRequire(ipv4 || (query[end - 4] == 0 && query[end - 3] == 28), "unexpected DNS question type");
    if (ipv4)
        ++a_questions;
    else
        ++aaaa_questions;
    const size_t answer_length = end + (ipv4 ? 16 : answer_ipv6 ? 28 : 0);
    const size_t prefix        = tcp ? 2 : 0;
    sbuf_t      *answer        = makeInput(line, prefix + answer_length, 0);
    uint8_t     *wire          = sbufGetMutablePtr(answer);
    if (tcp)
    {
        wire[0] = (uint8_t) (answer_length >> 8);
        wire[1] = (uint8_t) answer_length;
        wire += prefix;
    }
    memoryCopy(wire, query, end);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6] = 0;
    wire[7] = ipv4 || answer_ipv6 ? 1 : 0;
    wire[8] = wire[9] = wire[10] = wire[11] = 0;
    if (ipv4)
    {
        const uint8_t record[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 42};
        memoryCopy(wire + end, record, sizeof(record));
    }
    else if (answer_ipv6)
    {
        const uint8_t record[] = {0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x20, 0x01,
                                  0x0d, 0xb8, 0, 0,  0, 0, 0, 0, 0, 0,  0, 0,  0,    42};
        memoryCopy(wire + end, record, sizeof(record));
    }
    if (tcp && inject_empty_tcp)
        domainresolverTransportPayload(resolver, line, makeInput(line, 0, 0));
    domainresolverTransportPayload(resolver, line, answer);
    if (tcp && inject_empty_tcp)
        domainresolverTransportPayload(resolver, line, makeInput(line, 0, 0));
}

static void observeWrite(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    discard next;
    ++writes;
    if (! answer_queries)
    {
        twfRequire(retained_write == NULL, "fixture retained two writes");
        retained_write = buf;
        return;
    }
    const uint8_t *query     = sbufGetRawPtr(buf);
    size_t         remaining = sbufGetLength(buf);
    if (lineGetDestinationAddressContext(line)->proto_tcp)
    {
        // These short fixture questions fit within a transport write chunk;
        // c-ares may combine multiple length-prefixed questions in one write.
        while (remaining != 0)
        {
            twfRequire(remaining >= 2, "short TCP DNS length prefix");
            size_t length = ((size_t) query[0] << 8) | query[1];
            twfRequire(length <= remaining - 2, "incomplete fixture TCP DNS query");
            answerQuery(line, query + 2, length, true);
            query += length + 2;
            remaining -= length + 2;
        }
    }
    else
        answerQuery(line, query, remaining, false);
    lineReuseBuffer(line, buf);
}

static void resolved(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs, size_t count)
{
    discard userdata;
    discard error;
    twfRequire(! submitting, "synchronous line response reentered the enclosing c-ares call");
    twfRequire(status == ARES_SUCCESS && count == 1 && addrs[0].family == AF_INET, "fake DNS answer was not resolved");
    const struct sockaddr_in *address = (const struct sockaddr_in *) &addrs[0].addr;
    twfRequire(ntohl(address->sin_addr.s_addr) == 0x7f00002aU, "DNS answer changed");
    ++results;
}

static void releaseObserved(void)
{
    twfRequire(observed_line != NULL && ! lineIsAlive(observed_line), "owned DNS line survived close");
    twfRequireLineStateZeroed(observed_line, resolver, "DNS close left resolver state behind");
    twfRequire(twfLineRefCount(observed_line) == 1, "DNS close leaked a line reference");
    lineUnref(observed_line);
    observed_line = NULL;
}

static void testUdpResume(tunnel_t *next, const asyncdns_options_t *options)
{
    twfSetCase("c-ares UDP writes resume before the retry deadline");
    domainresolver_transport_t *transport = domainresolverTransportCreate(resolver, next, 0, options);
    twfRequire(transport != NULL, "failed to create paused UDP channel");
    const unsigned initial_writes  = writes;
    const unsigned initial_results = results;
    init_pauses                    = true;
    submitting                     = true;
    twfRequire(asyncdnsResolve(&transport->resolver, "resume.test", NULL, SOCK_STREAM, resolved, NULL) == ARES_SUCCESS,
               "paused UDP lookup submission failed");
    submitting  = false;
    init_pauses = false;
    twfRequire(observed_line != NULL && writes == initial_writes, "UDP query escaped an Init-time Pause");
    dnsTransportProcess(transport);
    twfRequire(writes == initial_writes && results == initial_results, "paused UDP processing made progress");
    domainresolverTransportResume(resolver, observed_line);
    // Real c-ares buffers the blocked datagrams. No timeout, new request or direct
    // socket-send call is allowed to rescue them after the producer resumes.
    dnsTransportProcess(transport);
    dnsTransportProcess(transport);
    twfRequire(writes > initial_writes && results == initial_results + 1,
               "UDP Resume left c-ares output waiting for a DNS timeout or another request");
    const unsigned completed_writes = writes;
    dnsTransportProcess(transport);
    twfRequire(writes == completed_writes && results == initial_results + 1,
               "completed UDP output was sent again after Resume");
    domainresolverTransportQuiesce(transport);
    releaseObserved();
    domainresolverTransportDestroy(transport);
}

static void testWakeDeadline(tunnel_t *next, const asyncdns_options_t *options)
{
    twfSetCase("custom DNS readiness preserves its first deadline");
    domainresolver_transport_t *transport = domainresolverTransportCreate(resolver, next, 0, options);
    twfRequire(transport != NULL, "failed to create readiness channel");
    const unsigned initial_results = results;
    twfRequire(asyncdnsResolve(&transport->resolver, "deadline-first.test", NULL, SOCK_STREAM, resolved, NULL) ==
                   ARES_SUCCESS,
               "first readiness lookup failed");
    dns_resolver_t *dns  = &transport->resolver;
    wloop_t        *loop = dns->loop;
    twfRequire(dns->timer != NULL && dns->transport_pending, "DNS input did not schedule processing");
    const uint64_t original_now = loop->cur_hrtime;
    const uint64_t original_due = dns->timer->next_timeout;
    // Model successive sub-millisecond input notifications without sleeps. An
    // already-armed deadline must survive both wakes and lookup-time refreshes.
    for (unsigned i = 0; i < 10; ++i)
    {
        loop->cur_hrtime += 500;
        asyncdnsWakeTransport(dns);
        twfRequire(dns->timer->next_timeout == original_due, "another readiness wake postponed DNS processing");
    }
    twfRequire(asyncdnsResolve(dns, "deadline-second.test", NULL, SOCK_STREAM, resolved, NULL) == ARES_SUCCESS,
               "second readiness lookup failed");
    twfRequire(dns->timer->next_timeout == original_due, "lookup-time refresh postponed pending DNS processing");
    loop->cur_hrtime = original_now;
    for (unsigned i = 0; i < 8 && results != initial_results + 2; ++i)
        twfRequire(wloopProcessEvents(loop, 5) >= 0, "DNS readiness event-loop dispatch failed");
    twfRequire(results == initial_results + 2, "queued DNS answers did not complete through the timer");
    domainresolverTransportQuiesce(transport);
    releaseObserved();
    domainresolverTransportDestroy(transport);
}

static void cancelled(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs, size_t count)
{
    discard userdata;
    discard error;
    twfRequire(asyncdnsStatusIsShutdown(status) && addrs == NULL && count == 0,
               "pending TCP lookup was not cancelled during quiescence");
    ++cancellations;
}

static void testPendingTcpQuiesce(tunnel_t *next, const asyncdns_options_t *options)
{
    twfSetCase("quiescence drains a c-ares-owned pending TCP connection");
    asyncdns_options_t tcp_options        = *options;
    tcp_options.flags_set                 = true;
    tcp_options.flags                     = ARES_FLAG_USEVC;
    domainresolver_transport_t *transport = domainresolverTransportCreate(resolver, next, 0, &tcp_options);
    twfRequire(transport != NULL, "failed to create pending TCP channel");
    const unsigned initial_writes        = writes;
    const unsigned initial_finishes      = finishes;
    const unsigned initial_cancellations = cancellations;
    init_establishes                     = false;
    twfRequire(asyncdnsResolve(&transport->resolver, "pending-tcp.test", NULL, SOCK_STREAM, cancelled, NULL) ==
                   ARES_SUCCESS,
               "pending TCP lookup submission failed");
    twfRequire(observed_line != NULL && transport->socket_count == 1 && transport->sockets->tcp &&
                   ! transport->sockets->established && writes == initial_writes,
               "fixture did not leave a real DNS TCP connection awaiting Est");
    domainresolverTransportQuiesce(transport);
    twfRequire(cancellations == initial_cancellations + 1 && finishes == initial_finishes + 1 &&
                   transport->sockets == NULL && transport->resolver.channel == NULL &&
                   transport->resolver.timer == NULL,
               "pending TCP quiescence did not settle its query, socket, timer and line once");
    releaseObserved();
    domainresolverTransportDestroy(transport);
    twfRequire(cancellations == initial_cancellations + 1 && finishes == initial_finishes + 1,
               "destroy repeated pending TCP settlement");
    init_establishes = true;
}

static void testOwnedPreparation(tunnel_t *next, const asyncdns_options_t *options)
{
    twfSetCase("shared entries prepare and clean owned UDP/TCP lines without helper Init");
    domainresolver_tstate_t *ts = tunnelGetState(resolver);
    ts->shared_entry = ts->dns_egress     = next;
    domainresolver_transport_t *transport = domainresolverTransportCreate(resolver, next, 0, options);
    twfRequire(transport != NULL, "owned preparation transport construction failed");
    sockaddr_u peer          = {0};
    peer.sin.sin_family      = AF_INET;
    peer.sin.sin_port        = htons(53);
    peer.sin.sin_addr.s_addr = htonl(0x7f000035U);
    for (unsigned tcp = 0; tcp < 2; ++tcp)
    {
        for (unsigned synchronous_finish = 0; synchronous_finish < 2; ++synchronous_finish)
        {
            init_finishes                  = synchronous_finish != 0;
            const unsigned prepared_before = preparations;
            const unsigned cleanup_before  = preparation_cleanups;
            ares_socket_t  socket          = dnsTransportOpen(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0, transport);
            int            result          = dnsTransportConnect(socket, &peer.sa, sizeof(peer.sin), 0, transport);
            twfRequire((synchronous_finish ? result == -1 : result == 0) && preparations == prepared_before + 1,
                       "owned preparation failed or ran more than once");
            dnsTransportClose(socket, transport);
            releaseObserved();
            twfRequire(preparation_cleanups == cleanup_before + 1, "owned line cleanup did not run exactly once");
        }
    }
    init_finishes                 = false;
    preparation_refuses           = true;
    const unsigned cleanup_before = preparation_cleanups;
    ares_socket_t  refused        = dnsTransportOpen(AF_INET, SOCK_DGRAM, 0, transport);
    twfRequire(dnsTransportConnect(refused, &peer.sa, sizeof(peer.sin), 0, transport) == -1 &&
                   transport->sockets->line == NULL && observed_line == NULL,
               "failed preparation entered owner Init or left owned line alive");
    dnsTransportClose(refused, transport);
    twfRequire(preparation_cleanups == cleanup_before + 1, "failed owned preparation did not settle storage");
    preparation_refuses = false;
    domainresolverTransportDestroy(transport);
    ts->shared_entry = ts->dns_egress = NULL;
}

static void resolveUncached(domainresolver_transport_t *transport, const char *name)
{
    const unsigned initial_results = results;
    const unsigned initial_writes  = writes;
    submitting                     = true;
    twfRequire(asyncdnsResolve(&transport->resolver, name, NULL, SOCK_STREAM, resolved, NULL) == ARES_SUCCESS,
               "connection reuse lookup submission failed");
    submitting = false;
    for (unsigned i = 0; i < 8 && results == initial_results; ++i)
        dnsTransportProcess(transport);
    twfRequire(results == initial_results + 1 && writes > initial_writes,
               "uncached query did not exchange DNS data and complete");
    twfRequire(ares_queue_active_queries(transport->resolver.channel) == 0,
               "connection reuse check ran while a query was still active");
}

static void testConnectionReuse(tunnel_t *next, const asyncdns_options_t *options, bool tcp, bool stay_open)
{
    twfSetCase(stay_open ? (tcp ? "default TCP DNS connection reuse" : "default UDP DNS connection reuse")
                         : (tcp ? "explicit TCP DNS idle retirement" : "explicit UDP DNS idle retirement"));
    asyncdns_options_t configured = *options;
    if (! stay_open)
    {
        configured.flags_set = true;
        configured.flags     = ARES_FLAG_EDNS;
    }
    if (tcp)
    {
        configured.flags_set = true;
        configured.flags |= ARES_FLAG_USEVC;
    }
    domainresolver_transport_t *transport = domainresolverTransportCreate(resolver, next, 0, &configured);
    twfRequire(transport != NULL, "connection reuse transport construction failed");
    const unsigned initial_inits    = inits;
    const unsigned initial_finishes = finishes;
    resolveUncached(transport, "reuse-first.test");
    twfRequire(inits == initial_inits + 1 && observed_line != NULL &&
                   lineGetDestinationAddressContext(observed_line)->proto_tcp == tcp,
               "first lookup did not use the intended DNS transport");
    if (stay_open)
    {
        line_t *first_line = observed_line;
        twfRequire(lineIsAlive(first_line) && transport->socket_count == 1 && finishes == initial_finishes,
                   "default DNS connection closed when its first lookup became idle");
        const ares_socket_t first_handle = transport->sockets->handle;
        resolveUncached(transport, "reuse-second.test");
        twfRequire(observed_line == first_line && lineIsAlive(first_line) && inits == initial_inits + 1 &&
                       transport->socket_count == 1 && transport->sockets->handle == first_handle &&
                       finishes == initial_finishes,
                   "sequential uncached lookup did not reuse the idle DNS connection");
        domainresolverTransportQuiesce(transport);
        twfRequire(finishes == initial_finishes + 1, "quiescence did not close the reused DNS line once");
        releaseObserved();
    }
    else
    {
        twfRequire(transport->socket_count == 0 && finishes == initial_finishes + 1,
                   "explicit flags without stay-open retained an idle DNS connection");
        releaseObserved();
        resolveUncached(transport, "reuse-second.test");
        twfRequire(inits == initial_inits + 2 && transport->socket_count == 0 && finishes == initial_finishes + 2,
                   "explicit idle retirement did not open and close a fresh connection for the next lookup");
        releaseObserved();
        domainresolverTransportQuiesce(transport);
    }
    twfRequire(transport->sockets == NULL && transport->resolver.channel == NULL && transport->resolver.timer == NULL,
               "DNS connection lifetime test left channel, socket or timer state after quiescence");
    const unsigned quiesced_finishes = finishes;
    domainresolverTransportDestroy(transport);
    twfRequire(finishes == quiesced_finishes, "destroy repeated idle DNS connection cleanup");
}

static void testNativeChannelFlags(const asyncdns_options_t *options)
{
    twfSetCase("native DNS honors default stay-open and explicit flag replacement");
    for (unsigned explicit_flags = 0; explicit_flags < 2; ++explicit_flags)
    {
        asyncdns_options_t configured = *options;
        if (explicit_flags)
        {
            configured.flags_set = true;
            configured.flags     = ARES_FLAG_EDNS;
        }
        dns_resolver_t native;
        twfRequire(asyncdnsInit(&native, getWorkerLoop(0), &configured) == ARES_SUCCESS,
                   "native channel flag check failed to initialize");
        struct ares_options saved = {0};
        int                 mask  = 0;
        twfRequire(ares_save_options(native.channel, &saved, &mask) == ARES_SUCCESS,
                   "native channel effective flags could not be read");
        twfRequire((saved.flags & ARES_FLAG_EDNS) != 0 && ((saved.flags & ARES_FLAG_STAYOPEN) != 0) == ! explicit_flags,
                   "native channel changed default EDNS/stay-open or ignored explicit flag replacement");
        ares_destroy_options(&saved);
        asyncdnsCleanup(&native);
    }
}

typedef struct family_result_s
{
    int      family;
    unsigned callbacks;
} family_result_t;

static void familyResolved(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                           size_t count)
{
    discard          error;
    family_result_t *result = userdata;
    twfRequire(status == ARES_SUCCESS && count == (result->family == AF_UNSPEC ? 2U : 1U),
               "family-constrained lookup returned the wrong result count");
    for (size_t i = 0; i < count; ++i)
        twfRequire(result->family == AF_UNSPEC || addrs[i].family == result->family,
                   "family-constrained lookup returned another family");
    ++result->callbacks;
}

static void familyLineResolved(tunnel_t *t, line_t *line, void *userdata, int status, const char *error,
                               const dns_resolved_addr_t *addrs, size_t count)
{
    discard t;
    twfRequire(lineIsAlive(line), "family lookup completed on a dead application line");
    familyResolved(userdata, status, error, addrs, count);
}

static void testQueryFamilies(tunnel_t *next, const asyncdns_options_t *options)
{
    twfSetCase("effective DNS strategies query only required address families");
    const enum domain_strategy    strategies[] = {kDsInvalid, kDsPreferIpV4, kDsPreferIpV6, kDsOnlyIpV4, kDsOnlyIpV6};
    domainresolver_tstate_t      *ts           = tunnelGetState(resolver);
    const domainresolver_tstate_t saved        = *ts;
    node_t                        helper_node  = {.type = (char *) "DomainResolver"};
    tunnel_t                     *helper       = domainresolverTunnelCreate(&helper_node);
    twfRequire(helper != NULL, "family strategy helper creation failed");
    domainresolverTunnelSetProvider(helper, resolver);
    domainresolverTunnelUseLineStrategy(helper, true);
    domainresolver_transport_t *workers[1] = {NULL};
    bool                        closed[1]  = {false};
    ts->dns_workers                        = workers;
    ts->dns_worker_closed                  = closed;
    ts->dns_workers_count                  = 1;
    ts->dns_egress                         = next;
    answer_ipv6                            = true;
    for (unsigned mode = kDomainResolverModeDirect; mode <= kDomainResolverModeChain; ++mode)
    {
        ts->mode = (domainresolver_mode_t) mode;
        for (unsigned strategy_index = 0; strategy_index < ARRAY_SIZE(strategies); ++strategy_index)
        {
            const enum domain_strategy strategy = strategies[strategy_index];
            const int family = strategy == kDsOnlyIpV4 ? AF_INET : strategy == kDsOnlyIpV6 ? AF_INET6 : AF_UNSPEC;
            for (unsigned api = 0; api < 3; ++api)
            {
                workers[0] = domainresolverTransportCreate(resolver, next, 0, options);
                twfRequire(workers[0] != NULL, "family channel creation failed");
                line_t         *line     = lineCreate(tunnelchainGetLinePools(tunnelGetChain(resolver)), 0);
                family_result_t result   = {.family = family};
                const unsigned  before_a = a_questions, before_aaaa = aaaa_questions;
                ts->use_line_strategy = false;
                ts->strategy          = api == 0 ? strategy : (family == AF_INET ? kDsOnlyIpV6 : kDsOnlyIpV4);
                addresscontextSetDomainStrategy(lineGetDestinationAddressContext(line),
                                                api == 1 ? strategy : ts->strategy);
                int status =
                    api == 2 ? domainresolverTunnelResolveRawWithStrategy(
                                   resolver, line, "family.test", NULL, SOCK_STREAM, strategy, familyResolved, &result)
                             : domainresolverTunnelResolve(api == 1 ? helper : resolver,
                                                           line,
                                                           "family.test",
                                                           NULL,
                                                           SOCK_STREAM,
                                                           familyLineResolved,
                                                           resolver,
                                                           &result);
                twfRequire(status == ARES_SUCCESS, "family lookup submission failed");
                for (unsigned i = 0; i < 8 && result.callbacks == 0; ++i)
                    dnsTransportProcess(workers[0]);
                twfRequire(result.callbacks == 1 && a_questions - before_a == (family == AF_INET6 ? 0U : 1U) &&
                               aaaa_questions - before_aaaa == (family == AF_INET ? 0U : 1U),
                           "effective family did not control A/AAAA query emission");
                domainresolverTransportDestroy(workers[0]);
                workers[0] = NULL;
                releaseObserved();
                lineDestroy(line);
            }
        }
    }
    answer_ipv6 = false;
    *ts         = saved;
    domainresolverTunnelDestroy(helper, wwLifecycleStartupRollback());
}

int main(int argc, char **argv)
{
    const char *selected = argc == 2 ? argv[1] : NULL;
    twfRequire(argc <= 2 &&
                   (selected == NULL || strcmp(selected, "udp-resume") == 0 || strcmp(selected, "wake-deadline") == 0 ||
                    strcmp(selected, "pending-tcp") == 0 || strcmp(selected, "connection-reuse") == 0),
               "unknown transport test case");
    twfSetCase("DomainResolver virtual socket semantics and callback deferral");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 65536, 32);
    twfRequire(ares_library_init(ARES_LIB_INIT_ALL) == ARES_SUCCESS, "c-ares library init failed");
    node_t node    = {.type = (char *) "DomainResolver"};
    resolver       = domainresolverTunnelCreate(&node);
    tunnel_t *next = tunnelCreate(NULL, 0, 0);
    twfRequire(resolver != NULL && next != NULL, "failed to create fixture tunnels");
    tunnelBind(resolver, next);
    resolver->chain_index = 0;
    next->chain_index     = 1;
    next->fnInitU         = observeInit;
    next->fnPayloadU      = observeWrite;
    next->fnFinU          = observeFinish;
    next->fnPauseU        = observePause;
    next->fnResumeU       = observeResume;
    domainresolverTunnelSetPrepareHook(resolver, next, 32, prepareOwned, destroyOwnedPreparation);
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, resolver->lstate_size, 8);
    tunnel_chain_t *chain = tunnelchainCreate(1);
    chain->line_pools[0]  = lines.pools[0];
    resolver->chain       = chain;
    asyncdns_options_t options;
    asyncdnsOptionsSetDefaults(&options);
    options.servers_csv                   = (char *) "127.0.0.53:53";
    options.lookups                       = (char *) "b";
    domainresolver_transport_t *transport = domainresolverTransportCreate(resolver, next, 0, &options);
    twfRequire(transport != NULL, "failed to create custom channel");
    sockaddr_u peer          = {0};
    peer.sin.sin_family      = AF_INET;
    peer.sin.sin_port        = htons(53);
    peer.sin.sin_addr.s_addr = htonl(0x7f000035U);

    ares_socket_t handle = dnsTransportOpen(AF_INET, SOCK_STREAM, 0, transport);
    twfRequire(handle != ARES_SOCKET_BAD, "virtual TCP socket creation failed");
    twfRequire(dnsTransportConnect(handle, &peer.sa, sizeof(peer.sin), 0, transport) == -1 && errno == EINPROGRESS,
               "pending TCP establishment was reported as writable");
    char data[20000];
    memorySet(data, 'A', sizeof(data));
    twfRequire(dnsTransportSend(handle, data, sizeof(data), 0, NULL, 0, transport) == -1 && errno == EWOULDBLOCK &&
                   writes == 0,
               "send escaped before TCP Est");
    domainresolverTransportEst(resolver, observed_line);
    domainresolverTransportPayload(resolver, observed_line, makeInput(observed_line, 0, 0));
    char empty_probe;
    twfRequire(dnsTransportReceive(handle, &empty_probe, 1, 0, NULL, NULL, transport) == -1 && errno == EWOULDBLOCK &&
                   bufferqueueGetEntryCount(&dnsTransportSocket(transport, handle)->input) == 0,
               "empty TCP payload became EOF or retained an input entry");
    twfRequire(dnsTransportSend(handle, data, sizeof(data), 0, NULL, 0, transport) == kDnsTransportTcpWriteChunk,
               "TCP short write did not preserve bounded chunking");
    data[0] = 'B';
    twfRequire(sbufGetRawPtr(retained_write)[0] == 'A', "adapter retained borrowed c-ares write memory");
    lineReuseBuffer(observed_line, retained_write);
    retained_write = NULL;
    domainresolverTransportPause(resolver, observed_line);
    twfRequire(dnsTransportSend(handle, data, 1, 0, NULL, 0, transport) == -1 && errno == EWOULDBLOCK,
               "received Pause did not stop writes");
    domainresolverTransportPayload(resolver, observed_line, makeInput(observed_line, kDnsTransportReadHigh, 'Q'));
    twfRequire(pauses == 1, "bounded input failed to pause the DNS receiver");
    char received[kDnsTransportReadHigh];
    twfRequire(dnsTransportReceive(handle, received, sizeof(received), 0, NULL, NULL, transport) == sizeof(received) &&
                   received[0] == 'Q' && resumes == 1,
               "input drain failed to release receiver pressure");
    twfRequire(dnsTransportSend(handle, data, 1, 0, NULL, 0, transport) == -1,
               "local receive Resume released independently received send Pause");
    domainresolverTransportResume(resolver, observed_line);
    twfRequire(dnsTransportSend(handle, data, 1, 0, NULL, 0, transport) == 1, "send Resume did not restore capacity");
    lineReuseBuffer(observed_line, retained_write);
    retained_write          = NULL;
    sockaddr_u wrong_peer   = peer;
    wrong_peer.sin.sin_port = htons(54);
    twfRequire(dnsTransportSend(handle, data, 1, 0, &wrong_peer.sa, sizeof(wrong_peer.sin), transport) == -1,
               "send accepted an unrelated DNS peer port");
    domainresolverTransportPayload(resolver, observed_line, makeInput(observed_line, 3, 'X'));
    domainresolverTransportPayload(resolver, observed_line, makeInput(observed_line, 3, 'Y'));
    twfRequire(dnsTransportReceive(handle, received, 2, 0, NULL, NULL, transport) == 2 && received[0] == 'X',
               "partial TCP receive lost bytes");
    twfRequire(dnsTransportReceive(handle, received, 8, 0, NULL, NULL, transport) == 1 && received[0] == 'X',
               "TCP receive reordered a partial suffix");
    twfRequire(dnsTransportReceive(handle, received, 8, 0, NULL, NULL, transport) == 3 && received[0] == 'Y',
               "TCP receive lost the next entry");
    domainresolverTransportFinish(resolver, observed_line);
    twfRequire(dnsTransportReceive(handle, received, 8, 0, NULL, NULL, transport) == 0,
               "TCP Finish did not become EOF");
    releaseObserved();
    twfRequire(dnsTransportClose(handle, transport) == 0 && finishes == 0, "received Finish reflected toward sender");

    init_finishes        = true;
    ares_socket_t closed = dnsTransportOpen(AF_INET, SOCK_STREAM, 0, transport);
    twfRequire(closed != handle && dnsTransportConnect(closed, &peer.sa, sizeof(peer.sin), 0, transport) == -1,
               "synchronous Finish during Init survived");
    releaseObserved();
    dnsTransportClose(closed, transport);
    init_finishes = false;

    ares_socket_t bounded = dnsTransportOpen(AF_INET, SOCK_DGRAM, 0, transport);
    twfRequire(dnsTransportConnect(bounded, &peer.sa, sizeof(peer.sin), 0, transport) == 0, "UDP connect failed");
    dnsTransportState(transport, closed, 1, 1);
    twfRequire(! dnsTransportSocket(transport, bounded)->write_interest, "stale readiness affected a new handle");
    for (unsigned i = 0; i <= kDnsTransportMaxInputEntries; ++i)
        domainresolverTransportPayload(resolver, observed_line, makeInput(observed_line, 0, 0));
    twfRequire(! lineIsAlive(observed_line), "input entry overflow failed to close owned DNS line");
    releaseObserved();
    dnsTransportClose(bounded, transport);
    twfRequire(finishes == 1, "overflow did not notify next exactly once");

    answer_queries   = true;
    init_establishes = true;
    submitting       = true;
    twfRequire(asyncdnsResolve(&transport->resolver, "fixture.test", NULL, SOCK_STREAM, resolved, NULL) == ARES_SUCCESS,
               "real c-ares lookup submission failed");
    submitting = false;
    twfRequire(results == 0 && transport->resolver.watches == NULL,
               "virtual handle reached native watcher or reentered");
    dnsTransportProcess(transport);
    twfRequire(results == 1, "timer-deferred synchronous DNS answers did not complete");
    const unsigned writes_before_cache = writes;
    twfRequire(asyncdnsResolve(&transport->resolver, "fixture.test", NULL, SOCK_STREAM, resolved, NULL) ==
                       ARES_SUCCESS &&
                   results == 2 && writes == writes_before_cache,
               "synchronous cache completion opened another transport or failed to settle");
    domainresolverTransportQuiesce(transport);
    releaseObserved();
    domainresolverTransportDestroy(transport);
    if (selected == NULL || strcmp(selected, "udp-resume") == 0)
        testUdpResume(next, &options);
    if (selected == NULL || strcmp(selected, "wake-deadline") == 0)
        testWakeDeadline(next, &options);
    if (selected == NULL || strcmp(selected, "pending-tcp") == 0)
        testPendingTcpQuiesce(next, &options);
    testOwnedPreparation(next, &options);
    if (selected == NULL || strcmp(selected, "connection-reuse") == 0)
    {
        for (unsigned tcp = 0; tcp < 2; ++tcp)
            for (unsigned stay_open = 0; stay_open < 2; ++stay_open)
            {
                inject_empty_tcp = tcp != 0;
                testConnectionReuse(next, &options, tcp != 0, stay_open != 0);
            }
        inject_empty_tcp = false;
        testNativeChannelFlags(&options);
    }
    testQueryFamilies(next, &options);
    chain->line_pools[0] = NULL;
    tunnelchainDestroy(chain);
    twfLinePoolTeardown(&lines);
    tunnelDestroy(next);
    tunnelDestroy(resolver);
    ares_library_cleanup();
    twfWorkerEnvTeardown(&env);
    return 0;
}
