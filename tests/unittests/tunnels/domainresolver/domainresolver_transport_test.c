/*
 * Covers: c-ares virtual socket transport, with real owner-worker pools and a
 * synchronous fake egress. Checks pending TCP establishment, copied/short writes,
 * independent receive/send pressure, input bounds, stale handles, Finish and
 * synchronous DNS responses deferred until the enclosing c-ares call returns.
 * CTest: waterwall.domainresolver_transport_unit
 */
#include "DomainResolver/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

/* Exercise the private socket boundary without exposing test-only runtime APIs. */
#include "../../../../tunnels/Internals/DomainResolver/common/transport.c"

static tunnel_t *resolver;
static line_t   *observed_line;
static sbuf_t   *retained_write;
static unsigned  writes, finishes, pauses, resumes, results, cancellations;
static bool      init_establishes, init_finishes, init_pauses, answer_queries, submitting;

static void observeInit(tunnel_t *next, line_t *line)
{
    discard next;
    twfRequire(observed_line == NULL, "previous owned line was not released by fixture");
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
    const uint8_t *query        = sbufGetRawPtr(buf);
    const size_t   query_length = sbufGetLength(buf);
    size_t         end          = 12;
    twfRequire(query_length > 16, "short DNS query");
    while (end < query_length && query[end] != 0)
        end += (size_t) query[end] + 1;
    end += 5;
    twfRequire(end <= query_length, "invalid DNS question");
    const bool ipv4   = query[end - 4] == 0 && query[end - 3] == 1;
    sbuf_t    *answer = makeInput(line, end + (ipv4 ? 16 : 0), 0);
    uint8_t   *wire   = sbufGetMutablePtr(answer);
    memoryCopy(wire, query, end);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6] = 0;
    wire[7] = ipv4 ? 1 : 0;
    wire[8] = wire[9] = wire[10] = wire[11] = 0;
    if (ipv4)
    {
        const uint8_t record[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 42};
        memoryCopy(wire + end, record, sizeof(record));
    }
    lineReuseBuffer(line, buf);
    domainresolverTransportPayload(resolver, line, answer);
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

int main(int argc, char **argv)
{
    const char *selected = argc == 2 ? argv[1] : NULL;
    twfRequire(argc <= 2 && (selected == NULL || strcmp(selected, "udp-resume") == 0 ||
                             strcmp(selected, "wake-deadline") == 0 || strcmp(selected, "pending-tcp") == 0),
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
    chain->line_pools[0] = NULL;
    tunnelchainDestroy(chain);
    twfLinePoolTeardown(&lines);
    tunnelDestroy(next);
    tunnelDestroy(resolver);
    ares_library_cleanup();
    twfWorkerEnvTeardown(&env);
    return 0;
}
