/*
 * Covers: lwip ptc engine; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Checksum cases: complete shifted TCP/UDP requests cross PTC's alignment replacement;
 * the ordinary variant requires repaired bytes for stack acceptance, while trusted receive
 * exercises the same explicit requests alongside existing unrequested partial input.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.lwip_ptc_engine_unit; waterwall.lwip_ptc_trusted_engine_unit
 */
#include "PacketsToConnection/structure.h"
#include "devices/device_flow_affinity.h"
#include "lwip/stats.h"

/* Keep the two nodes' private state-size enums in separate translation units. */
tunnel_t *ipoverriderCreate(node_t *node);
void      ipoverriderDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
#include "worker_messages.h"

/* Suite-owned abort() preserves its original failure boundary. */

#include "test_assert.h"

#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! TEST_CHECK(x, "requirement failed"))                                                                     \
        {                                                                                                              \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

#include "lwip_udp_length_cases.h"

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
    sbuf_t  *tcp_input[2];
    unsigned undelivered_udp[2];
    unsigned udp_length_init[2][kUdpLengthInputs];
    unsigned udp_length_payload[2][kUdpLengthInputs];
    unsigned udp_length_next[2];
    unsigned requested_alignment_copies[2];
} probe_t;
static fixture_t         fixtures[2];
static probe_t           probes[2];
static pthread_barrier_t barrier;
static atomic_bool       finished[2];
static uint32_t          fake_address;
static void              stageUndeliveredChild(wid_t wid);
static unsigned          ownedLineCount(tunnel_t *t, wid_t wid);
static unsigned          routeChildCount(interface_route_context_t *route);
static void              udpLengthMatrix(fixture_t *fixture, line_t *packet_line);

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
    {
        interface_route_context_t *route = ((ptc_tstate_t *) tunnelGetState(fixtures[i].ptc))->routes_v4[wid];
        CHECK(route != NULL && probes[wid].undelivered_udp[i] == (i == 0 ? 1U : 0U));
        const uint8_t     index      = netif_get_index(&route->netif);
        const uint32_t    generation = route->netif.ww_generation;
        ww_lwip_engine_t *engine     = route->engine;
        ptcTunnelOnWorkerStop(fixtures[i].ptc, wid, context);
        CHECK(lineIsAlive(tunnelchainGetWorkerPacketLine(fixtures[i].chain, wid)));
        ww_lwip_engine_t *previous;
        CHECK(wwLwipEngineEnter(engine, &previous));
        for (struct udp_pcb *pcb = udp_pcbs; pcb != NULL; pcb = pcb->next)
            CHECK(pcb->netif_idx != index || pcb->netif_generation != generation);
        wwLwipEngineLeave(engine, previous);
    }
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
    if (packettunnelTrustedChecksumsActive(f->ptc))
    {
        /* This variant models TUN-assured partial input, including an alignment
         * copy, without asking an intervening transform to repair the bytes. */
        const uint32_t length = sbufGetLength(buf);
        uint8_t       *bytes  = sbufGetMutablePtr(buf);
        PUT_BE16(bytes + (bytes[9] == 6 ? 36 : 26), 0x1234);
        bytes[10] ^= 1;
        sbuf_t *shifted = sbufCreate(length + 1);
        sbufSetLength(shifted, length + 1);
        sbufShiftRight(shifted, 1);
        memcpy(sbufGetMutablePtr(shifted), bytes, length);
        lineReuseBuffer(line, buf);
        ptcTunnelUpStreamPayload(f->ptc, line, shifted);
        return;
    }
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

static void shiftedRequestedInput(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    const uint32_t length = sbufGetLength(buf);
    const uint8_t *bytes  = sbufGetRawPtr(buf);
    const unsigned proto  = bytes[9] == IP_PROTO_TCP ? 0 : 1;
    probe_t       *probe  = &probes[lineGetWID(line)];
    sbuf_t        *copy   = sbufCreate(length + 1);
    sbufSetLength(copy, length + 1);
    sbufShiftRight(copy, 1);
    uint8_t *shifted = sbufGetMutablePtr(copy);
    memcpy(shifted, bytes, length);
    shifted[10] ^= 1;
    shifted[proto == 0 ? 36 : 26] ^= 1;
    CHECK(inet_chksum(shifted, 20) != 0);
    CHECK(((uintptr_t) shifted % MEM_ALIGNMENT) != 0);
    sbufSetRecalculateChecksum(copy, true);
    ++probe->requested_alignment_copies[proto];
    if (probe->tcp_input[1] == buf)
        probe->tcp_input[1] = NULL;
    lineReuseBuffer(line, buf);
    ptcTunnelUpStreamPayload(t, line, copy);
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
        sbuf_t *input = packet(line, 6, destination, TCP_ACK | TCP_PSH, ack, "hello", 5);
        if (! packettunnelTrustedChecksumsActive(f->ptc))
            probe->tcp_input[f - fixtures] = input;
        inject(f, line, input);
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
    CHECK(wwLwipEngineCurrent() == NULL && currentThreadOwnsWorker(lineGetWID(line)));
    CHECK(strcmp(lineGetDestinationAddressContext(line)->domain, "shared.test") == 0);
    const unsigned port = lineGetDestinationAddressContext(line)->port;
    if (port >= kUdpLengthFirstPort && port < kUdpLengthFirstPort + kUdpLengthInputs)
    {
        const unsigned input = port - kUdpLengthFirstPort;
        CHECK(udp_length_cases[input / 2].delivered >= 0);
        CHECK(++probes[lineGetWID(line)].udp_length_init[fixtureFor(t) - fixtures][input] == 1);
        tunnelPrevDownStreamEst(t, line);
        return;
    }
    ++probes[lineGetWID(line)].init;
    tunnelPrevDownStreamEst(t, line);
}
static void payload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    CHECK(wwLwipEngineCurrent() == NULL);
    CHECK(! sbufGetRecalculateChecksum(buf));
    const unsigned port = lineGetDestinationAddressContext(line)->port;
    if (port >= kUdpLengthFirstPort && port < kUdpLengthFirstPort + kUdpLengthInputs)
    {
        const unsigned           input = port - kUdpLengthFirstPort;
        const udp_length_case_t *row   = &udp_length_cases[input / 2];
        CHECK(row->delivered >= 0 && sbufGetLength(buf) == (unsigned) row->delivered);
        CHECK(memcmp(sbufGetRawPtr(buf), udp_length_payload, (unsigned) row->delivered) == 0);
        CHECK(++probes[lineGetWID(line)].udp_length_payload[fixtureFor(t) - fixtures][input] == 1);
        fixture_t  *fixture = fixtureFor(t);
        const wid_t wid     = lineGetWID(line);
        lineReuseBuffer(line, buf);
        lineRef(line);
        tunnelPrevDownStreamFinish(t, line);
        CHECK(! lineIsAlive(line));
        lineUnref(line);
        udpLengthMatrix(fixture, tunnelchainGetWorkerPacketLine(fixture->chain, wid));
        return;
    }
    if (lineGetDestinationAddressContext(line)->proto_tcp)
    {
        sbuf_t **input = &probes[lineGetWID(line)].tcp_input[fixtureFor(t) - fixtures];
        if (*input != NULL)
        {
            CHECK(buf == *input);
            *input = NULL;
        }
    }
    const bool  close        = lineGetDestinationAddressContext(line)->proto_tcp || fixtureFor(t) == &fixtures[1];
    const bool  start_matrix = ! lineGetDestinationAddressContext(line)->proto_tcp && fixtureFor(t) == &fixtures[1];
    const wid_t wid          = lineGetWID(line);
    lineRef(line);
    tunnelPrevDownStreamPayload(t, line, buf);
    if (close)
    {
        tunnelPrevDownStreamFinish(t, line);
        CHECK(! lineIsAlive(line));
    }
    lineUnref(line);
    if (start_matrix)
        udpLengthMatrix(&fixtures[0], tunnelchainGetWorkerPacketLine(fixtures[0].chain, wid));
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
    if (packettunnelTrustedReceiveChecksumsActive(t))
    {
        PUT_BE16(p + 26, 0x1234);
        p[10] ^= 1;
    }
    ptc_fake_dns_result_t r =
        ptcFakeDnsHandleIpv4UdpPacket(t, line, buf, (struct ip_hdr *) p, (struct udp_hdr *) (p + 20));
    CHECK(r.handled && r.response);
    const uint8_t *out = sbufGetRawPtr(r.response);
    CHECK(GET_BE16(out + 8 + 6) == 1);
    if (packettunnelTrustedChecksumsActive(t))
        CHECK(GET_BE16(out + 6) == 0);
    uint32_t answer;
    memcpy(&answer, out + sbufGetLength(r.response) - 4, 4);
    lineReuseBuffer(line, r.response);
    return answer;
}
static void finishTimer(wtimer_t *timer)
{
    wid_t    wid = getLoopWorkerWID(weventGetLoop(timer));
    probe_t *p   = &probes[wid];
    CHECK(p->tcp == 2 && p->udp == 2 && p->init == 4);
    CHECK(p->requested_alignment_copies[0] > 0 && p->requested_alignment_copies[1] > 0);
    for (unsigned fixture = 0; fixture < 2; ++fixture)
    {
        for (unsigned input = 0; input < kUdpLengthInputs; ++input)
        {
            const unsigned expected = udp_length_cases[input / 2].delivered >= 0 ? 1U : 0U;
            CHECK(p->udp_length_init[fixture][input] == expected);
            CHECK(p->udp_length_payload[fixture][input] == expected);
        }
        interface_route_context_t *route     = ((ptc_tstate_t *) tunnelGetState(fixtures[fixture].ptc))->routes_v4[wid];
        const unsigned             remaining = fixture == 0 ? 1U : 0U;
        CHECK(ptc_udp_flow_map_t_size(&route->udp_flows) == remaining);
        CHECK(routeChildCount(route) == remaining + p->undelivered_udp[fixture]);
        CHECK(ownedLineCount(fixtures[fixture].ptc, wid) == remaining);
        CHECK(p->udp_length_next[fixture] == kUdpLengthInputs);
    }
    if (p->undelivered_udp[0] == 0)
        stageUndeliveredChild(wid);
    atomicStoreExplicit(&finished[wid], true, memory_order_release);
    if (wid == 0 && ! atomicLoadExplicit(&finished[1], memory_order_acquire))
    {
        CHECK(wtimerReset(timer, 10));
        return;
    }
    CHECK((wid == 0 ? workerInstallApplicationQuiesceRequest(getWorker(wid), wwLifecycleProcessShutdown())
                    : workerRequestQuiesceResult(getWorker(wid))) != kWorkerQuiesceRequestUnavailable);
}

static void acceptUndeliveredChild(void *argument, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *address,
                                   u16_t port)
{
    interface_route_context_t *route = argument;
    ptcUdpAccept(route, pcb, p, address, port);
    CHECK(pcb->recv == ptcUdpReceived);
    /* Model an accepted child whose initial delivery never acquires a line.
     * The raw UDP dispatcher frees this datagram when no receiver is installed. */
    udp_recv(pcb, NULL, NULL);
    unsigned fixture = route->tunnel == fixtures[0].ptc ? 0 : 1;
    ++probes[route->packet_wid].undelivered_udp[fixture];
}

static void stageUndeliveredChild(wid_t wid)
{
    fixture_t                 *fixture    = &fixtures[0];
    line_t                    *line       = tunnelchainGetWorkerPacketLine(fixture->chain, wid);
    interface_route_context_t *route      = ((ptc_tstate_t *) tunnelGetState(fixture->ptc))->routes_v4[wid];
    const isize_t              flow_count = ptc_udp_flow_map_t_size(&route->udp_flows);
    ww_lwip_engine_t          *previous;
    CHECK(wwLwipEngineEnter(route->engine, &previous));
    udp_recv(route->udp_pcb, acceptUndeliveredChild, route);
    wwLwipEngineLeave(route->engine, previous);
    sbuf_t *undelivered = packet(line, 17, fake_address, 0, 0, "world", 5);
    PUT_BE16(sbufGetMutablePtr(undelivered) + 22, 82);
    CHECK(calcFullPacketChecksum(sbufGetMutablePtr(undelivered), sbufGetLength(undelivered)));
    inject(fixture, line, undelivered);
    CHECK(probes[wid].undelivered_udp[0] == 1);
    CHECK(ptc_udp_flow_map_t_size(&route->udp_flows) == flow_count);
    CHECK(wwLwipEngineEnter(route->engine, &previous));
    udp_recv(route->udp_pcb, ptcUdpAccept, route);
    wwLwipEngineLeave(route->engine, previous);
}

static unsigned ownedLineCount(tunnel_t *t, wid_t wid)
{
    ptc_tstate_t *state = tunnelGetState(t);
    unsigned      count = 0;
    CHECK(currentThreadOwnsWorker(wid));
    for (line_t *line = state->owned_lines[wid]; line != NULL;)
    {
        ++count;
        ptc_lstate_t *ls = lineGetState(line, t);
        line             = ls->owned_next;
    }
    return count;
}

static unsigned routeChildCount(interface_route_context_t *route)
{
    unsigned          count = 0;
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(route->engine, &previous));
    for (struct udp_pcb *pcb = udp_pcbs; pcb != NULL; pcb = pcb->next)
        if (pcb != route->udp_pcb && pcb->netif_idx == netif_get_index(&route->netif) &&
            pcb->netif_generation == route->netif.ww_generation)
            ++count;
    wwLwipEngineLeave(route->engine, previous);
    return count;
}

static void udpLengthMatrix(fixture_t *fixture, line_t *packet_line)
{
    const wid_t                wid   = lineGetWID(packet_line);
    interface_route_context_t *route = ((ptc_tstate_t *) tunnelGetState(fixture->ptc))->routes_v4[wid];
    unsigned                  *next  = &probes[wid].udp_length_next[fixture - fixtures];
    while (*next < kUdpLengthInputs)
    {
        const unsigned           input    = (*next)++;
        const udp_length_case_t *row      = &udp_length_cases[input / 2];
        const unsigned           added    = row->delivered >= 0 ? 1U : 0U;
        const isize_t            flows    = ptc_udp_flow_map_t_size(&route->udp_flows);
        const unsigned           children = routeChildCount(route);
        const unsigned           owned    = ownedLineCount(fixture->ptc, wid);
        sbuf_t  *buf   = packet(packet_line, 17, fake_address, 0, 0, udp_length_payload, row->available - 8);
        uint8_t *bytes = sbufGetMutablePtr(buf);
        PUT_BE16(bytes + 22, kUdpLengthFirstPort + input);
        udpLengthSetHeader(bytes, input);
        /* Direct ingress preserves our declared-span checksum. The ordinary
         * fixture's tuple rewriter intentionally recalculates whole packets. */
        ptcTunnelUpStreamPayload(fixture->ptc, packet_line, buf);
        CHECK(lineIsAlive(packet_line));
        CHECK(ptc_udp_flow_map_t_size(&route->udp_flows) == flows + added);
        CHECK(routeChildCount(route) == children + added);
        CHECK(ownedLineCount(fixture->ptc, wid) == owned + added);
        /* The bounded engine fixture has only eight shared UDP PCBs. Retire
         * each accepted test flow in its real delivery callback before the
         * next packet, keeping room for both workers' original roundtrips. */
        if (added != 0)
            return;
    }
    if (fixture == &fixtures[0])
        udpLengthMatrix(&fixtures[1], tunnelchainGetWorkerPacketLine(fixtures[1].chain, wid));
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
        const bool trusted         = packettunnelTrustedChecksumsActive(fixtures[i].ptc);
        const bool trusted_receive = packettunnelTrustedReceiveChecksumsActive(fixtures[i].ptc);
        CHECK((route->netif.ww_partial_transport_checksum != 0) == trusted);
        CHECK((route->netif.ww_trusted_receive_checksums != 0) == trusted_receive);
        CHECK(((route->netif.chksum_flags & NETIF_CHECKSUM_CHECK_TCP) == 0) == trusted_receive);
        CHECK(((route->netif.chksum_flags & NETIF_CHECKSUM_CHECK_IP) == 0) == trusted_receive);
        CHECK((route->netif.chksum_flags & NETIF_CHECKSUM_GEN_IP) != 0);
    }
    CHECK(wtimerAdd(getWorkerLoop(wid), finishTimer, 1000, 1));
}
int main(void)
{
    testCaseSet("lwip_ptc_engine_test");
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
        nodes[i].node_settings_json = cJSON_Parse("{\"fake-dns\":{\"cache-size\":2,\"ttl\":0}}");
        f->ptc                      = ptcTunnelCreate(&nodes[i]);
        CHECK(f->ptc);
        if (i == 1)
            f->ptc->fnPayloadU = shiftedRequestedInput;
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
#ifdef PTC_TRUSTED_FIXTURE
        /* Publication may occur after PTC onStart; routes must read it lazily. */
        if (i == 0)
            nodes[i].flags |= kNodeFlagTrustedPacketChecksumsActive;
        else
            nodes[i].flags |= kNodeFlagTrustedPacketReceiveChecksumsActive;
#endif
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
