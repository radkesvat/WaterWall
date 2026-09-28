#include "PacketsToConnection/structure.h"
#include "devices/device_flow_affinity.h"
#include "lwip/stats.h"

/* Keep the two nodes' private state-size enums in separate translation units. */
tunnel_t *ipoverriderCreate(node_t *node);
void      ipoverriderDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
#include "worker_messages.h"

#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! (x))                                                                                                     \
        {                                                                                                              \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

typedef struct fixture_s
{
    tunnel_t       *ptc, *prev, *next;
    tunnel_chain_t *chain;
} fixture_t;
typedef struct probe_s
{
    unsigned tcp, udp, init, finish, reservations;
    unsigned rewritten_hash_mismatches;
    bool     byte_reserved;
} probe_t;
static fixture_t         fixtures[2];
static probe_t           probes[2];
static pthread_barrier_t barrier;
static atomic_bool       finished[2];
static uint32_t          fake_address;

void __real_nodemanagerQuiesceWorker(wid_t, const ww_lifecycle_context_t *);
void __wrap_nodemanagerQuiesceWorker(wid_t, const ww_lifecycle_context_t *);
void __real_nodemanagerStopWorkerResources(wid_t, const ww_lifecycle_context_t *);
void __wrap_nodemanagerStopWorkerResources(wid_t, const ww_lifecycle_context_t *);
void __real_workerMessagesDestroyDetached(worker_message_queue_t *);
void __wrap_workerMessagesDestroyDetached(worker_message_queue_t *);
void __wrap_nodemanagerQuiesceWorker(wid_t wid, const ww_lifecycle_context_t *context)
{
    __real_nodemanagerQuiesceWorker(wid, context);
}
void __wrap_nodemanagerStopWorkerResources(wid_t wid, const ww_lifecycle_context_t *context)
{
    for (unsigned i = 0; i < 2; ++i)
        ptcTunnelOnWorkerStop(fixtures[i].ptc, wid, context);
    __real_nodemanagerStopWorkerResources(wid, context);
}
void __wrap_workerMessagesDestroyDetached(worker_message_queue_t *queue)
{
    __real_workerMessagesDestroyDetached(queue);
}
static void rendezvous(void)
{
    int r = pthread_barrier_wait(&barrier);
    CHECK(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
}
static fixture_t *fixtureFor(tunnel_t *t)
{
    for (unsigned i = 0; i < 2; ++i)
        if (fixtures[i].prev == t || fixtures[i].next == t)
            return &fixtures[i];
    CHECK(false);
    return NULL;
}
static sbuf_t *packet(line_t *line, uint8_t protocol, uint32_t destination, uint8_t flags, uint32_t ack,
                      const void *payload, unsigned length)
{
    unsigned header = protocol == 6 ? 40 : 28;
    sbuf_t  *buf    = bufferpoolGetBestFit(lineGetBufferPool(line), header + length, 0);
    CHECK(buf);
    sbufSetLength(buf, header + length);
    uint8_t *p = sbufGetMutablePtr(buf);
    memset(p, 0, header + length);
    p[0] = 0x45;
    PUT_BE16(p + 2, header + length);
    p[8]  = 64;
    p[9]  = protocol;
    p[12] = 10;
    p[15] = 2;
    memcpy(p + 16, &destination, 4);
    PUT_BE16(p + 20, 40001);
    PUT_BE16(p + 22, protocol == 6 ? 80 : 81);
    if (protocol == 6)
    {
        PUT_BE32(p + 24, flags == TCP_SYN ? 1000 : 1001);
        PUT_BE32(p + 28, ack);
        p[32] = 0x50;
        p[33] = flags;
        PUT_BE16(p + 34, 16384);
    }
    else
        PUT_BE16(p + 24, 8 + length);
    if (length)
        memcpy(p + header, payload, length);
    CHECK(calcFullPacketChecksum(p, header + length));
    return buf;
}
/* Model device placement before a real tuple transform. The incoming hash
 * selects this worker; IpOverrider changes the source without moving the packet
 * line, and PTC must preserve that owner even when the new hash differs. */
static void inject(fixture_t *f, line_t *line, sbuf_t *buf)
{
    uint8_t *raw = sbufGetMutablePtr(buf);
    uint64_t hash;
    CHECK(deviceFlowAffinityHash(raw, sbufGetLength(buf), &hash));
    if (hash % 2 != lineGetWID(line))
        ++probes[lineGetWID(line)].rewritten_hash_mismatches;
    unsigned candidate;
    for (candidate = 3; candidate < 255; ++candidate)
    {
        raw[15] = (uint8_t) candidate;
        CHECK(deviceFlowAffinityHash(raw, sbufGetLength(buf), &hash));
        if (hash % 2 == lineGetWID(line))
            break;
    }
    CHECK(candidate < 255);
    CHECK(calcFullPacketChecksum(raw, sbufGetLength(buf)));
    f->prev->fnPayloadU(f->prev, line, buf);
}
static void emit(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    CHECK(wwLwipEngineCurrent() == NULL);
    fixture_t     *f     = fixtureFor(t);
    probe_t       *probe = &probes[lineGetWID(line)];
    const uint8_t *p     = sbufGetRawPtr(buf);
    unsigned       h     = (p[0] & 15) * 4;
    CHECK(inet_chksum(p, (u16_t) h) == 0);
    if (p[9] == 6 && (p[h + 13] & TCP_SYN))
    {
        uint32_t destination;
        memcpy(&destination, p + 12, 4);
        uint32_t ack = GET_BE32(p + h + 4) + 1;
        lineReuseBuffer(line, buf);
        inject(f, line, packet(line, 6, destination, TCP_ACK | TCP_PSH, ack, "hello", 5));
        return;
    }
    if (p[9] == 6 && sbufGetLength(buf) > h + (p[h + 12] >> 4) * 4U)
    {
        CHECK(sbufGetLength(buf) == h + (p[h + 12] >> 4) * 4U + 5);
        CHECK(memcmp(p + h + (p[h + 12] >> 4) * 4, "hello", 5) == 0);
        ++probe->tcp;
    }
    if (p[9] == 17)
    {
        CHECK(sbufGetLength(buf) == h + 8 + 5);
        CHECK(memcmp(p + h + 8, "world", 5) == 0);
        ++probe->udp;
    }
    lineReuseBuffer(line, buf);
}
static void opened(tunnel_t *t, line_t *line)
{
    CHECK(wwLwipEngineCurrent() == NULL && currentThreadIsEventWorkerWID(lineGetWID(line)));
    CHECK(strcmp(lineGetDestinationAddressContext(line)->domain, "shared.test") == 0);
    ++probes[lineGetWID(line)].init;
    tunnelPrevDownStreamEst(t, line);
}
static void payload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    CHECK(wwLwipEngineCurrent() == NULL);
    const bool close = lineGetDestinationAddressContext(line)->proto_tcp || fixtureFor(t) == &fixtures[1];
    lineRef(line);
    tunnelPrevDownStreamPayload(t, line, buf);
    if (close)
    {
        tunnelPrevDownStreamFinish(t, line);
        CHECK(! lineIsAlive(line));
    }
    lineUnref(line);
}
static void finishedLine(tunnel_t *t, line_t *line)
{
    (void) t;
    ++probes[lineGetWID(line)].finish;
}
static uint32_t query(tunnel_t *t, line_t *line, const char *label)
{
    uint8_t  dns[128] = {0};
    unsigned len      = (unsigned) strlen(label);
    CHECK(len < 64);
    dns[5]  = 1;
    dns[12] = (uint8_t) len;
    memcpy(dns + 13, label, len);
    unsigned n = 13 + len;
    dns[n++]   = 4;
    memcpy(dns + n, "test", 4);
    n += 4;
    dns[n++] = 0;
    dns[n++] = 0;
    dns[n++] = 1;
    dns[n++] = 0;
    dns[n++] = 1;
    ip4_addr_t dest;
    IP4_ADDR(&dest, 198, 18, 0, 2);
    sbuf_t  *buf = packet(line, 17, dest.addr, 0, 0, dns, n);
    uint8_t *p   = sbufGetMutablePtr(buf);
    PUT_BE16(p + 22, 53);
    CHECK(calcFullPacketChecksum(p, sbufGetLength(buf)));
    ptc_fake_dns_result_t r =
        ptcFakeDnsHandleIpv4UdpPacket(t, line, buf, (struct ip_hdr *) p, (struct udp_hdr *) (p + 20));
    CHECK(r.handled && r.response);
    const uint8_t *out = sbufGetRawPtr(r.response);
    CHECK(GET_BE16(out + 8 + 6) == 1);
    uint32_t answer;
    memcpy(&answer, out + sbufGetLength(r.response) - 4, 4);
    lineReuseBuffer(line, r.response);
    return answer;
}
static void finishTimer(wtimer_t *timer)
{
    wid_t    wid = getLoopEventWorkerWID(weventGetLoop(timer));
    probe_t *p   = &probes[wid];
    CHECK(p->tcp == 2 && p->udp == 2 && p->init == 4);
    atomicStoreExplicit(&finished[wid], true, memory_order_release);
    if (wid == 0 && ! atomicLoadExplicit(&finished[1], memory_order_acquire))
    {
        CHECK(wtimerReset(timer, 10));
        return;
    }
    CHECK((wid == 0 ? workerInstallApplicationQuiesceRequest(getWorker(wid), wwLifecycleProcessShutdown())
                    : workerRequestQuiesceResult(getWorker(wid))) != kWorkerQuiesceRequestUnavailable);
}
static void setup(void *worker_ptr, void *a, void *b, void *c)
{
    (void) a;
    (void) b;
    (void) c;
    wid_t         wid         = ((worker_t *) worker_ptr)->wid;
    line_t       *line        = tunnelchainGetWorkerPacketLine(fixtures[0].chain, wid);
    ptc_tstate_t *ts          = tunnelGetState(fixtures[0].ptc);
    probes[wid].byte_reserved = ptcDrainBudgetReserve(ts, kPtcMaxDrainBytesTotal / 2 + 1);
    rendezvous();
    CHECK(probes[0].byte_reserved != probes[1].byte_reserved);
    rendezvous();
    if (probes[wid].byte_reserved)
        ptcDrainBudgetRelease(ts, kPtcMaxDrainBytesTotal / 2 + 1);
    rendezvous();
    while (ptcDrainBudgetReserve(ts, 0))
        ++probes[wid].reservations;
    rendezvous();
    CHECK(probes[0].reservations + probes[1].reservations == kPtcMaxDrains);
    rendezvous();
    for (unsigned i = 0; i < probes[wid].reservations; ++i)
        ptcDrainBudgetRelease(ts, 0);
    rendezvous();
    /* Concurrent reverse lookup/eviction must always copy a complete name. */
    for (unsigned i = 0; i < 300; ++i)
    {
        char name[32];
        snprintf(name, sizeof(name), "w%u-n%u", wid, i);
        uint32_t  addr = query(fixtures[0].ptc, line, name);
        ip_addr_t ip;
        IP_SET_TYPE_VAL(ip, IPADDR_TYPE_V4);
        ip.u_addr.ip4.addr    = addr;
        address_context_t dst = {0};
        if (ptcFakeDnsApplyMappedDestination(fixtures[0].ptc, &dst, &ip, 80, 6))
        {
            CHECK(dst.domain_len >= 8 && strcmp(dst.domain + dst.domain_len - 5, ".test") == 0);
            addresscontextReset(&dst);
        }
    }
    rendezvous();
    if (wid == 0)
    {
        fake_address = query(fixtures[0].ptc, line, "shared");
        if ((lwip_ntohl(fake_address) & 1) != 0)
            (void) query(fixtures[1].ptc, tunnelchainGetWorkerPacketLine(fixtures[1].chain, 0), "filler");
        CHECK(query(fixtures[1].ptc, tunnelchainGetWorkerPacketLine(fixtures[1].chain, 0), "shared") == fake_address);
    }
    rendezvous();
    for (unsigned i = 0; i < 2; ++i)
    {
        line = tunnelchainGetWorkerPacketLine(fixtures[i].chain, wid);
        inject(&fixtures[i], line, packet(line, 6, fake_address, TCP_SYN, 0, NULL, 0));
        inject(&fixtures[i], line, packet(line, 17, fake_address, 0, 0, "world", 5));
        interface_route_context_t *route = ((ptc_tstate_t *) tunnelGetState(fixtures[i].ptc))->routes_v4[wid];
        CHECK(route && route->packet_wid == wid && route->engine == wwLwipRuntimeGet(wid));
    }
    CHECK(wtimerAdd(getWorkerLoop(wid), finishTimer, 1000, 1));
}
int main(void)
{
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 2;
    data.ram_profile                    = 4;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = off;
    data.core_logger_data.log_level     = off;
    data.network_logger_data.log_level  = off;
    data.dns_logger_data.log_level      = off;
    CHECK(wwStartupSucceeded(createGlobalState(data)));
    initTcpIpStack();
    CHECK(GSTATE.flag_lwip_initialized);
    CHECK(pthread_barrier_init(&barrier, NULL, 2) == 0);
    static node_t nodes[2];
    for (unsigned i = 0; i < 2; ++i)
    {
        fixture_t *f                = &fixtures[i];
        nodes[i].node_settings_json = cJSON_Parse("{\"fake-dns\":{\"cache-size\":2}}");
        f->ptc                      = ptcTunnelCreate(&nodes[i]);
        CHECK(f->ptc);
        cJSON_Delete(nodes[i].node_settings_json);
        nodes[i].node_settings_json = NULL;
        node_t rewrite_node         = {.node_settings_json =
                                           cJSON_Parse("{\"up\":{\"source-ip\":{\"ipv4\":\"10.0.0.2\"}},\"chance\":100}")};
        CHECK(rewrite_node.node_settings_json);
        f->prev = ipoverriderCreate(&rewrite_node);
        cJSON_Delete(rewrite_node.node_settings_json);
        f->next = tunnelCreate(NULL, 0, 0);
        CHECK(f->prev && f->next);
        f->prev->fnPayloadD = emit;
        f->next->fnInitU    = opened;
        f->next->fnPayloadU = payload;
        f->next->fnFinU     = finishedLine;
        tunnelBind(f->prev, f->ptc);
        tunnelBind(f->ptc, f->next);
        f->chain = tunnelchainCreate(2);
        CHECK(f->chain);
        f->chain->sum_line_state_size  = f->ptc->lstate_size;
        f->chain->contains_packet_node = true;
        tunnelchainFinalize(f->chain);
        CHECK(f->chain->finalized);
        f->ptc->chain  = f->chain;
        f->prev->chain = f->chain;
        f->next->chain = f->chain;
        ptcTunnelOnStart(f->ptc);
    }
    for (wid_t i = 0; i < 2; ++i)
        CHECK(sendWorkerMessageForceQueueWithCleanup(i, setup, NULL, NULL, NULL, NULL) == kWorkerMessageSubmitAccepted);
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    CHECK(wloopRun(getWorkerLoop(0)) == kWLoopRunQuiesced);
    for (unsigned i = 0; i < 2; ++i)
        ptcTunnelOnQuiesceRequest(fixtures[i].ptc, wwLifecycleProcessShutdown());
    workerPerformQuiesce(getWorker(0), wwLifecycleProcessShutdown());
    CHECK(workerWaitForPhase(getWorker(1), kWorkerLifecycleQuiesced, 5000));
    for (unsigned i = 0; i < 2; ++i)
        ptcTunnelOnQuiesceWait(fixtures[i].ptc, wwLifecycleProcessShutdown());
    for (wid_t i = 0; i < 2; ++i)
        CHECK(workerRequestDrain(getWorker(i)));
    workerPerformDrain(getWorker(0), wwLifecycleProcessShutdown());
    CHECK(workerWaitForPhase(getWorker(1), kWorkerLifecycleDrained, 5000));
    for (unsigned i = 0; i < 2; ++i)
    {
        ptc_tstate_t *s = tunnelGetState(fixtures[i].ptc);
        CHECK(s->drain_count == 0 && s->drain_bytes == 0);
        ptcTunnelOnStop(fixtures[i].ptc, wwLifecycleProcessShutdown());
    }
    CHECK(probes[0].finish == 1 && probes[1].finish == 1);
    CHECK(probes[0].rewritten_hash_mismatches + probes[1].rewritten_hash_mismatches > 0);
    for (wid_t i = 0; i < 2; ++i)
        CHECK(workerRequestTeardown(getWorker(i)));
    workerPerformTeardown(getWorker(0));
    CHECK(workerWaitForPhase(getWorker(1), kWorkerLifecycleExited, 5000));
    CHECK(workerJoin(getWorker(1)));
    CHECK(wwLwipShutdown());
    GSTATE.flag_lwip_initialized = 0;
    for (unsigned i = 0; i < 2; ++i)
    {
        tunnelchainDestroy(fixtures[i].chain);
        ptcTunnelDestroy(fixtures[i].ptc, wwLifecycleProcessShutdown());
        ipoverriderDestroy(fixtures[i].prev, wwLifecycleProcessShutdown());
        tunnelDestroy(fixtures[i].next);
    }
    CHECK(pthread_barrier_destroy(&barrier) == 0);
    destroyGlobalState();
    puts("PTC concurrent engines, identical tuples/netifs, DNS coherence/eviction, aggregate drains, callbacks and "
         "shutdown passed");
    return 0;
}
