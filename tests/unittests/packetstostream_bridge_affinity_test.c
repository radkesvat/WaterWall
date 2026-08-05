/*
 * PacketsToStream receive-side inner-flow affinity.
 *
 * A peer that spreads one source's flows across several stream lines may return
 * any inner flow on any of them, so the outer stream line's worker says nothing
 * about which worker owns the decoded packet. The decoder must hash the inner
 * tuple and deliver the packet to that flow's own worker packet line, both when
 * that worker is the current one and when the packet has to be queued across
 * workers.
 *
 * The fixture deliberately uses an outer stream line on worker 0 and flows whose
 * affinity worker is not 0: a same-WID-only fixture cannot see this defect.
 */
#include "PacketsToStream/structure.h"

#include "devices/device_flow_affinity.h"
#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kTestWorkers         = 4,
    kTestLargeBufferSize = 8192,
    kTestSmallBufferSize = kMaxAllowedPacketLength,
    kTestPacketLength    = 40
};

typedef struct affinity_fixture_s
{
    tos_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *p2s;
    tunnel_t        *prev;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *packet_lines[kTestWorkers];
    line_t          *stream_line;
} affinity_fixture_t;

static affinity_fixture_t g_fixture;

static line_t  *g_last_prev_line;
static wid_t    g_last_prev_wid;
static uint32_t g_prev_payload_count;

// Set by the re-entrant-death case: the first delivered packet tears the output
// stream line down from inside the extraction loop, which is what a packet chain
// that closes the connection does.
static bool     g_close_stream_line_on_payload;
static uint32_t g_stream_line_refcount_during_payload;

static void recordPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    g_last_prev_line = l;
    // The right packet line on the wrong thread is still a defect: everything
    // downstream of here is written assuming it runs as that line's worker.
    g_last_prev_wid = getWID();
    ++g_prev_payload_count;
    lineReuseBuffer(l, buf);

    if (g_close_stream_line_on_payload)
    {
        g_close_stream_line_on_payload = false;

        // Read before the close: the loop must be holding its own reference, or
        // the line could be freed underneath it by a callback like this one.
        g_stream_line_refcount_during_payload = twfLineRefCount(g_fixture.stream_line);

        packetstostream_lstate_t *ls = lineGetState(g_fixture.packet_lines[0], g_fixture.p2s);
        ls->line                     = NULL;
        g_fixture.stream_line->alive = false;
    }
}

static void recordNextInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static line_t *lineCreateOnWorker(uint32_t lstate_size, wid_t wid)
{
    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + lstate_size);

    twfRequire(l != NULL, "failed to allocate a test line");
    atomic_init(&l->refc, 1);
    l->alive = true;
    l->wid   = wid;
    return l;
}

static void fixtureSetup(void)
{
    memoryZero(&g_fixture, sizeof(g_fixture));
    g_last_prev_line                      = NULL;
    g_last_prev_wid                       = kInvalidWID;
    g_prev_payload_count                  = 0;
    g_close_stream_line_on_payload        = false;
    g_stream_line_refcount_during_payload = 0;

    tosWorkerEnvSetup(&g_fixture.env, kTestWorkers, kTestLargeBufferSize, kTestSmallBufferSize);

    g_fixture.p2s = tunnelCreate(NULL, sizeof(packetstostream_tstate_t), sizeof(packetstostream_lstate_t));
    twfRequire(g_fixture.p2s != NULL, "failed to create the PacketsToStream tunnel");

    g_fixture.prev = twfCreatePrevTunnel(&g_fixture.trace);
    g_fixture.next = twfCreateNextTunnel(&g_fixture.trace);
    tunnelBind(g_fixture.prev, g_fixture.p2s);
    tunnelBind(g_fixture.p2s, g_fixture.next);

    g_fixture.prev->fnPayloadD = recordPrevPayload;
    g_fixture.next->fnInitU    = recordNextInit;

    packetstostream_tstate_t *ts = tunnelGetState(g_fixture.p2s);
    ts->packet_validation_level  = kPacketsToStreamPacketValidationNone;
    ts->sensitive_mode           = false;

    g_fixture.chain = memoryAllocateZero(sizeof(tunnel_chain_t) + (sizeof(generic_pool_t *) * kTestWorkers));
    twfRequire(g_fixture.chain != NULL, "failed to allocate the test chain");
    g_fixture.chain->workers_count = kTestWorkers;
    g_fixture.chain->packet_lines  = g_fixture.packet_lines;
    g_fixture.p2s->chain           = g_fixture.chain;

    for (wid_t wi = 0; wi < kTestWorkers; ++wi)
    {
        g_fixture.packet_lines[wi] = lineCreateOnWorker(g_fixture.p2s->lstate_size, wi);
    }

    // One output stream line on worker 0, exactly as this tunnel's own send side
    // would have created it, so the decoder's state lookup succeeds.
    g_fixture.stream_line = lineCreateOnWorker(g_fixture.p2s->lstate_size, 0);

    packetstostream_lstate_t *ls = lineGetState(g_fixture.packet_lines[0], g_fixture.p2s);
    packetstostreamLinestateInitialize(ls, lineGetBufferPool(g_fixture.packet_lines[0]));
    ls->line = g_fixture.stream_line;
}

static void fixtureTeardown(void)
{
    packetstostream_lstate_t *ls = lineGetState(g_fixture.packet_lines[0], g_fixture.p2s);

    packetstostreamLinestateDestroy(ls);

    twfLineDestroy(g_fixture.stream_line);
    for (wid_t wi = 0; wi < kTestWorkers; ++wi)
    {
        twfLineDestroy(g_fixture.packet_lines[wi]);
    }

    memoryFree(g_fixture.chain);
    tunnelDestroy(g_fixture.next);
    tunnelDestroy(g_fixture.prev);
    tunnelDestroy(g_fixture.p2s);
    tosWorkerEnvTeardown(&g_fixture.env);
}

static void buildIpv4(uint8_t *raw, uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
    memoryZero(raw, kTestPacketLength);

    struct ip_hdr *ip = (struct ip_hdr *) raw;
    IPH_VHL_SET(ip, 4, IP_HLEN / 4);
    IPH_LEN_SET(ip, lwip_htons((uint16_t) kTestPacketLength));
    IPH_TTL_SET(ip, 64);
    IPH_PROTO_SET(ip, IP_PROTO_TCP);
    PUT_BE32(raw + 12, src);
    PUT_BE32(raw + 16, dst);
    PUT_BE16(raw + 20, src_port);
    PUT_BE16(raw + 22, dst_port);
}

static wid_t affinityWidOf(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
    uint8_t  raw[kTestPacketLength];
    uint64_t hash = 0;

    buildIpv4(raw, src, src_port, dst, dst_port);
    twfRequire(deviceFlowAffinityHash(raw, sizeof(raw), &hash), "the test packet was not hashable");
    return (wid_t) (hash % kTestWorkers);
}

/*
 * Finds a source port whose flow belongs to @p wanted, so the test can name the
 * same-worker and cross-worker cases explicitly instead of hoping for them.
 */
static uint16_t portForAffinityWid(wid_t wanted)
{
    for (uint16_t port = 1024; port < 4096U + 1024U; ++port)
    {
        if (affinityWidOf(0x0A000001U, port, 0xC0000201U, 443) == wanted)
        {
            return port;
        }
    }

    twfRequire(false, "no test flow maps to the requested worker");
    return 0;
}

// Feeds one complete framed packet into the decoder on the stream line's worker.
static void feedDownstreamPacket(uint16_t src_port)
{
    const wid_t previous = tosSetCurrentWorker(0);
    sbuf_t     *buf      = bufferpoolGetSmallBuffer(lineGetBufferPool(g_fixture.stream_line));

    twfRequire(sbufGetMaximumWriteableSize(buf) >= kTestPacketLength, "the test buffer is too small");
    sbufSetLength(buf, kTestPacketLength);
    buildIpv4(sbufGetMutablePtr(buf), 0x0A000001U, src_port, 0xC0000201U, 443);

    packetstostreamTunnelDownStreamPayload(g_fixture.p2s, g_fixture.stream_line, buf);
    discard tosSetCurrentWorker(previous);
}

// Two complete packets in one read, so the extraction loop has a second packet
// left to decode after the first one's delivery callback returns.
static void feedTwoDownstreamPackets(uint16_t first_port, uint16_t second_port)
{
    const wid_t previous = tosSetCurrentWorker(0);
    sbuf_t     *buf      = bufferpoolGetSmallBuffer(lineGetBufferPool(g_fixture.stream_line));

    twfRequire(sbufGetMaximumWriteableSize(buf) >= (kTestPacketLength * 2U), "the test buffer is too small");
    sbufSetLength(buf, kTestPacketLength * 2U);

    uint8_t *raw = sbufGetMutablePtr(buf);
    buildIpv4(raw, 0x0A000001U, first_port, 0xC0000201U, 443);
    buildIpv4(raw + kTestPacketLength, 0x0A000001U, second_port, 0xC0000201U, 443);

    packetstostreamTunnelDownStreamPayload(g_fixture.p2s, g_fixture.stream_line, buf);
    discard tosSetCurrentWorker(previous);
}

static void pumpAllWorkers(void)
{
    for (wid_t wi = 0; wi < kTestWorkers; ++wi)
    {
        tosPumpWorker(&g_fixture.env, wi);
    }
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

static void caseCrossWorkerDecodeReachesTheFlowWorker(void)
{
    twfSetCase("a decoded return packet reaches its own flow worker's packet line");
    tosResetProcessApi(true);
    fixtureSetup();

    const uint16_t port = portForAffinityWid(2);

    twfRequire(lineGetWID(g_fixture.stream_line) == 0, "the outer line must not already be on the flow worker");
    twfRequire(affinityWidOf(0x0A000001U, port, 0xC0000201U, 443) == 2, "the fixture flow lost its target worker");

    feedDownstreamPacket(port);

    // Nothing may be delivered before the target worker runs the queued message.
    twfRequireEqualU32(g_prev_payload_count, 0, "a cross-worker packet was delivered on the wrong worker");

    pumpAllWorkers();

    twfRequireEqualU32(g_prev_payload_count, 1, "the queued packet was never delivered");
    twfRequire(g_last_prev_line == g_fixture.packet_lines[2],
               "the decoded packet did not reach the packet line of its flow worker");
    twfRequireEqualU32(g_last_prev_wid, 2, "the queued packet was delivered on the wrong worker");
    twfRequireNoLeakedBuffers();

    fixtureTeardown();
}

static void caseSameWorkerDecodeIsDirect(void)
{
    twfSetCase("a decoded packet whose flow worker is the current one is forwarded directly");
    tosResetProcessApi(true);
    fixtureSetup();

    const uint16_t port = portForAffinityWid(0);

    feedDownstreamPacket(port);

    twfRequireEqualU32(g_prev_payload_count, 1, "the same-worker packet was not forwarded directly");
    twfRequire(g_last_prev_line == g_fixture.packet_lines[0], "the same-worker packet used the wrong packet line");
    twfRequireEqualU32(g_last_prev_wid, 0, "the same-worker packet was delivered on the wrong worker");

    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 1, "the same-worker packet was delivered twice");
    twfRequireNoLeakedBuffers();

    fixtureTeardown();
}

static void caseEveryFlowWorkerIsReachable(void)
{
    twfSetCase("every flow worker is reachable from one outer stream line");
    tosResetProcessApi(true);
    fixtureSetup();

    for (wid_t wanted = 0; wanted < kTestWorkers; ++wanted)
    {
        const uint16_t port = portForAffinityWid(wanted);

        g_prev_payload_count = 0;
        g_last_prev_line     = NULL;
        g_last_prev_wid      = kInvalidWID;

        feedDownstreamPacket(port);
        pumpAllWorkers();

        twfRequireEqualU32(g_prev_payload_count, 1, "a decoded packet was lost or duplicated");
        twfRequire(g_last_prev_line == g_fixture.packet_lines[wanted],
                   "a decoded packet reached the wrong flow worker");
        twfRequireEqualU32(g_last_prev_wid, wanted, "a decoded packet was delivered on the wrong worker thread");
    }

    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

/*
 * Application shutdown drops queued worker messages through the cleanup callback
 * instead of the normal one. The buffer must still be released exactly once, and
 * the packet line's temporary reference released with it.
 */
static void caseDroppedCrossWorkerMessageReleasesItsBuffer(void)
{
    twfSetCase("a dropped cross-worker message releases its buffer and line reference");
    tosResetProcessApi(true);
    fixtureSetup();

    const uint16_t port = portForAffinityWid(3);

    feedDownstreamPacket(port);
    twfRequireEqualU32(g_prev_payload_count, 0, "a cross-worker packet must not be delivered before its worker runs");

    // Never pump worker 3: dropping its queue is what the shutdown path does.
    workerMessagesCleanupPending(&g_fixture.env.workers[3]);

    twfRequireEqualU32(g_prev_payload_count, 0, "a dropped message must not be delivered");
    twfRequireNoLeakedBuffers();
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&g_fixture.packet_lines[3]->refc),
                       1,
                       "a dropped message leaked its packet-line reference");

    fixtureTeardown();
}

/*
 * Delivering a decoded packet runs an inter-tunnel callback, and that callback
 * may close the outer stream line before the loop has finished decoding the
 * read. The loop must hold its own reference across the callback and stop as
 * soon as the line is gone, instead of reading parser state that no longer has
 * an owner.
 */
static void caseReentrantStreamLineDeathStopsExtraction(void)
{
    twfSetCase("a stream line closed inside a decoded-packet callback stops extraction");
    tosResetProcessApi(true);
    fixtureSetup();

    // Both flows belong to worker 0, so the first delivery is direct and its
    // callback runs re-entrantly inside the extraction loop.
    const uint16_t port = portForAffinityWid(0);

    // Baseline first: without a close, one read of two packets really does
    // deliver two. Otherwise the assertion below would hold for the wrong reason.
    feedTwoDownstreamPackets(port, port);
    twfRequireEqualU32(g_prev_payload_count, 2, "the fixture did not put two decodable packets in one read");

    g_prev_payload_count = 0;

    g_close_stream_line_on_payload = true;
    feedTwoDownstreamPackets(port, port);

    twfRequireEqualU32(g_prev_payload_count, 1, "extraction continued after the stream line was closed");
    twfRequire(g_stream_line_refcount_during_payload >= 2,
               "the extraction loop did not hold a reference across the delivery callback");

    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 1, "a packet was still delivered after the stream line was closed");

    // The undecoded second packet is released with the parser, so leaks are only
    // meaningful once the fixture's line state is destroyed.
    fixtureTeardown();
    twfRequireNoLeakedBuffers();
}

int main(void)
{
    caseCrossWorkerDecodeReachesTheFlowWorker();
    caseSameWorkerDecodeIsDirect();
    caseEveryFlowWorkerIsReachable();
    caseDroppedCrossWorkerMessageReleasesItsBuffer();
    caseReentrantStreamLineDeathStopsExtraction();

    printf("packetstostream_bridge_affinity_test: all cases passed\n");
    return 0;
}
