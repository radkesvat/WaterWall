/*
 * StreamToPackets active-source ownership and per-flow return-line selection.
 *
 * The tunnel is owned globally by one concrete source IP. Any number of
 * validated stream lines from that IP may be active together, return packets are
 * spread across them by rendezvous hashing over the full symmetric flow hash, and
 * a validated line from a different IP takes the whole instance over and closes
 * every old-source line on its own worker.
 *
 * The fixture publishes four real event workers so a takeover, a cross-worker
 * return write and a stale-generation drop are all reachable the way the runtime
 * reaches them.
 */
#include "StreamToPackets/structure.h"

#include "devices/device_flow_affinity.h"
#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kTestWorkers         = 4,
    kTestLargeBufferSize = 8192,
    kTestSmallBufferSize = kMaxAllowedPacketLength,
    kTestPacketLength    = 40
};

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

typedef struct ownership_fixture_s
{
    tos_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *s2p;
    tunnel_t        *prev;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *packet_lines[kTestWorkers];
} ownership_fixture_t;

static ownership_fixture_t g_fixture;

static void fixtureTeardown(void);
static void pumpAllWorkers(void);

// Records which packet line each next-side payload arrived on, which is the
// whole point of restoring inner-flow affinity, and which worker thread ran the
// callback: the right line pointer on the wrong worker is still a defect.
static line_t  *g_last_next_line;
static wid_t    g_last_next_wid;
static uint32_t g_last_next_source;
static uint32_t g_next_payload_count;
static line_t  *g_last_prev_line;
static wid_t    g_last_prev_wid;
static uint32_t g_prev_payload_count;
static uint32_t g_prev_finish_count;
static line_t  *g_last_prev_finish_line;

static void recordNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    g_last_next_line = l;
    g_last_next_wid  = getWID();
    // Which epoch's traffic this was: a takeover must strand the older one.
    g_last_next_source = sbufGetLength(buf) >= 16U ? GET_BE32((const uint8_t *) sbufGetRawPtr(buf) + 12) : 0;
    ++g_next_payload_count;
    lineReuseBuffer(l, buf);
}

static void recordPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    g_last_prev_line = l;
    g_last_prev_wid  = getWID();
    ++g_prev_payload_count;
    lineReuseBuffer(l, buf);
}

static void recordPrevFinish(tunnel_t *t, line_t *l)
{
    discard t;
    g_last_prev_finish_line = l;
    ++g_prev_finish_count;
}

static void recordPrevEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void resetObservations(void)
{
    g_last_next_line        = NULL;
    g_last_next_wid         = kInvalidWID;
    g_last_next_source      = 0;
    g_next_payload_count    = 0;
    g_last_prev_line        = NULL;
    g_last_prev_wid         = kInvalidWID;
    g_prev_payload_count    = 0;
    g_prev_finish_count     = 0;
    g_last_prev_finish_line = NULL;
}

// ---------------------------------------------------------------------------
// injected worker-message rejection
// ---------------------------------------------------------------------------
//
// Posting a worker message can fail for reasons other than shutdown - an
// exhausted message pool, a loop that refuses a wakeup - and the eviction path
// has to keep its "every old-source line is closed" promise across that.

static bool     g_force_queue_fails;
static uint32_t g_force_queue_failures;
static int32_t  g_force_queue_fail_at = -1;
static uint32_t g_force_queue_attempts;

worker_message_submit_result_e __real_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback cb,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    const uint32_t attempt = g_force_queue_attempts++;
    if (LIKELY(! g_force_queue_fails && (g_force_queue_fail_at < 0 || attempt != (uint32_t) g_force_queue_fail_at)))
    {
        return __real_sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
    }

    // The real entry point runs the cleanup callback on the calling thread before
    // it reports a rejection, and every caller depends on that.
    ++g_force_queue_failures;
    if (cleanup != NULL)
    {
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelEnqueueFailure);
    }
    return false;
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

static void lineSetSourceIpv4(line_t *l, const char *ip)
{
    twfRequire(addresscontextSetIpAddress(lineGetSourceAddressContext(l), ip), "failed to set a test source IP");
}

static void fixtureSetup(void)
{
    memoryZero(&g_fixture, sizeof(g_fixture));
    resetObservations();
    g_force_queue_fail_at  = -1;
    g_force_queue_attempts = 0;

    tosWorkerEnvSetup(&g_fixture.env, kTestWorkers, kTestLargeBufferSize, kTestSmallBufferSize);

    g_fixture.s2p = tunnelCreate(NULL, sizeof(streamtopackets_tstate_t), sizeof(streamtopackets_lstate_t));
    twfRequire(g_fixture.s2p != NULL, "failed to create the StreamToPackets tunnel");

    g_fixture.prev = twfCreatePrevTunnel(&g_fixture.trace);
    g_fixture.next = twfCreateNextTunnel(&g_fixture.trace);
    tunnelBind(g_fixture.prev, g_fixture.s2p);
    tunnelBind(g_fixture.s2p, g_fixture.next);

    g_fixture.next->fnPayloadU = recordNextPayload;
    g_fixture.prev->fnPayloadD = recordPrevPayload;
    g_fixture.prev->fnFinD     = recordPrevFinish;
    g_fixture.prev->fnEstD     = recordPrevEst;

    streamtopackets_tstate_t *ts = tunnelGetState(g_fixture.s2p);
    ts->packet_validation_level  = kStreamToPacketsPacketValidationNone;
    ts->sensitive_mode           = false;
    streamtopacketsOwnershipInitialize(ts);

    g_fixture.chain = memoryAllocateZero(sizeof(tunnel_chain_t) + (sizeof(generic_pool_t *) * kTestWorkers));
    twfRequire(g_fixture.chain != NULL, "failed to allocate the test chain");
    g_fixture.chain->workers_count = kTestWorkers;
    g_fixture.chain->packet_lines  = g_fixture.packet_lines;
    g_fixture.s2p->chain           = g_fixture.chain;

    for (wid_t wi = 0; wi < kTestWorkers; ++wi)
    {
        g_fixture.packet_lines[wi] = lineCreateOnWorker(g_fixture.s2p->lstate_size, wi);
    }
}

static void streamToPacketsStartupRefusal(uint32_t failure_position)
{
    fixtureSetup();
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    g_force_queue_fail_at = (int32_t) failure_position;
    streamtopacketsTunnelOnStart(g_fixture.s2p);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(! wwStartupSucceeded(result), "StreamToPackets did not propagate the startup admission failure");
    twfRequireEqualU32((uint32_t) result.exit_code, 1, "StreamToPackets propagated the wrong startup status");
    fixtureTeardown();
}

static void caseStartupAdmissionIsCheckedForEveryWorker(void)
{
    const char *failure_modes[] = {"deque-growth", "wakeup-post"};
    for (uint32_t mode = 0; mode < ARRAY_SIZE(failure_modes); ++mode)
    {
        for (uint32_t position = 0; position < kTestWorkers; ++position)
        {
            char test_name[160];
            snprintf(test_name,
                     sizeof(test_name),
                     "StreamToPackets packet Init %s refusal at worker %u fails startup",
                     failure_modes[mode],
                     (unsigned int) position);
            twfSetCase(test_name);
            streamToPacketsStartupRefusal(position);
        }
    }

    twfSetCase("StreamToPackets admits every packet Init before deferred execution");
    fixtureSetup();
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    streamtopacketsTunnelOnStart(g_fixture.s2p);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    twfRequire(wwStartupSucceeded(result), "StreamToPackets reported failure after admitting every packet Init");
    twfRequireEqualU32(
        g_force_queue_attempts, kTestWorkers, "StreamToPackets did not admit exactly one packet Init per worker");
    twfRequireEqualU32(g_fixture.trace.next_init, 0, "StreamToPackets ran a queued packet Init during startup");
    pumpAllWorkers();
    twfRequireEqualU32(
        g_fixture.trace.next_init, kTestWorkers, "StreamToPackets omitted or duplicated a worker packet Init");
    fixtureTeardown();
}

static void fixtureTeardown(void)
{
    streamtopacketsOwnershipDestroy(g_fixture.s2p);

    for (wid_t wi = 0; wi < kTestWorkers; ++wi)
    {
        twfLineDestroy(g_fixture.packet_lines[wi]);
    }

    memoryFree(g_fixture.chain);
    tunnelDestroy(g_fixture.next);
    tunnelDestroy(g_fixture.prev);
    tunnelDestroy(g_fixture.s2p);
    tosWorkerEnvTeardown(&g_fixture.env);
}

// ---------------------------------------------------------------------------
// synthetic packets
// ---------------------------------------------------------------------------

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

static uint64_t flowHashOf(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
    uint8_t  raw[kTestPacketLength];
    uint64_t hash = 0;

    buildIpv4(raw, src, src_port, dst, dst_port);
    twfRequire(deviceFlowAffinityHash(raw, sizeof(raw), &hash), "the test packet was not hashable");
    return hash;
}

// Pushes one complete IPv4 packet into a stream line the way a transport would.
static void feedPacket(line_t *stream_line, uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stream_line));

    twfRequire(sbufGetMaximumWriteableSize(buf) >= kTestPacketLength, "the test buffer is too small");
    sbufSetLength(buf, kTestPacketLength);
    buildIpv4(sbufGetMutablePtr(buf), src, src_port, dst, dst_port);

    streamtopacketsTunnelUpStreamPayload(g_fixture.s2p, stream_line, buf);
}

/*
 * Builds a heartbeat-shaped frame with @p fill_byte as its payload. The ping
 * fill byte is protocol proof and must be able to establish or take over a
 * source; any other fill byte is just an ordinary packet.
 */
static void feedHeartbeat(line_t *stream_line, uint8_t fill_byte)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stream_line));

    twfRequire(sbufGetMaximumWriteableSize(buf) >= kHeartbeatPacketSize, "the test buffer is too small");
    sbufSetLength(buf, kHeartbeatPacketSize);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, IP_HLEN);

    struct ip_hdr *ip = (struct ip_hdr *) raw;
    IPH_VHL_SET(ip, 4, IP_HLEN / 4);
    IPH_LEN_SET(ip, lwip_htons((uint16_t) kHeartbeatPacketSize));
    IPH_TTL_SET(ip, 64);
    IPH_PROTO_SET(ip, kHeartbeatProtocol);
    memorySet(raw + IP_HLEN, fill_byte, kSensitivePayloadSize);

    streamtopacketsTunnelUpStreamPayload(g_fixture.s2p, stream_line, buf);
}

static void feedGarbage(line_t *stream_line)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stream_line));

    // Version nibble zero can never begin an IPv4 packet, so the parser
    // re-synchronizes past it and nothing is ever validated.
    sbufSetLength(buf, 64);
    memoryZero(sbufGetMutablePtr(buf), 64);

    streamtopacketsTunnelUpStreamPayload(g_fixture.s2p, stream_line, buf);
}

// Delivers one return packet to the packet line of its own flow worker.
static void feedReturnPacket(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
    const uint64_t hash        = flowHashOf(src, src_port, dst, dst_port);
    const wid_t    wid         = (wid_t) (hash % kTestWorkers);
    line_t        *packet_line = g_fixture.packet_lines[wid];
    const wid_t    previous    = tosSetCurrentWorker(wid);
    sbuf_t        *buf         = bufferpoolGetSmallBuffer(lineGetBufferPool(packet_line));

    twfRequire(sbufGetMaximumWriteableSize(buf) >= kTestPacketLength, "the test buffer is too small");
    sbufSetLength(buf, kTestPacketLength);
    buildIpv4(sbufGetMutablePtr(buf), src, src_port, dst, dst_port);

    streamtopacketsTunnelDownStreamPayload(g_fixture.s2p, packet_line, buf);
    discard tosSetCurrentWorker(previous);
}

static void pumpAllWorkers(void)
{
    for (wid_t wi = 0; wi < kTestWorkers; ++wi)
    {
        tosPumpWorker(&g_fixture.env, wi);
    }
}

static line_t *openStreamLine(const char *source_ip, wid_t wid)
{
    line_t     *l        = lineCreateOnWorker(g_fixture.s2p->lstate_size, wid);
    const wid_t previous = tosSetCurrentWorker(wid);

    lineSetSourceIpv4(l, source_ip);
    streamtopacketsTunnelUpStreamInit(g_fixture.s2p, l);
    discard tosSetCurrentWorker(previous);
    return l;
}

// The natural upstream Finish, on the line's own worker. The allocation is kept
// so a test can still hold a reference the way a queued write does.
static void finishStreamLine(line_t *l)
{
    const wid_t previous = tosSetCurrentWorker(lineGetWID(l));

    streamtopacketsTunnelUpStreamFinish(g_fixture.s2p, l);
    discard tosSetCurrentWorker(previous);
}

static void closeStreamLine(line_t *l)
{
    finishStreamLine(l);
    twfLineDestroy(l);
}

static bool lineIsTracked(const line_t *l)
{
    const streamtopackets_lstate_t *ls = lineGetState((line_t *) (uintptr_t) l, g_fixture.s2p);

    return ls->tracked;
}

static bool lineIsActive(const line_t *l)
{
    const streamtopackets_lstate_t *ls = lineGetState((line_t *) (uintptr_t) l, g_fixture.s2p);

    return ls->active;
}

static uint64_t lineGeneration(const line_t *l)
{
    const streamtopackets_lstate_t *ls = lineGetState((line_t *) (uintptr_t) l, g_fixture.s2p);

    return ls->source_generation;
}

// Drives one validated packet through a stream line on that line's own worker.
static void validateLine(line_t *l, uint16_t src_port)
{
    const wid_t previous = tosSetCurrentWorker(lineGetWID(l));

    feedPacket(l, 0x0A000001U, src_port, 0xC0000201U, 443);
    discard tosSetCurrentWorker(previous);
    pumpAllWorkers();
}

// The worker that owns the inner flow of a packet, which is what decides whether
// a decoded packet is delivered directly or has to be queued.
static wid_t flowWorkerOf(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port)
{
    return (wid_t) (flowHashOf(src, src_port, dst, dst_port) % kTestWorkers);
}

/*
 * Finds a source port whose inner flow belongs to @p wanted, so a test can name
 * the same-worker and cross-worker cases instead of hoping for them.
 */
static uint16_t sourcePortForFlowWorker(uint32_t src, uint32_t dst, wid_t wanted)
{
    for (uint32_t port = 40000; port < 45000U; ++port)
    {
        if (flowWorkerOf(src, (uint16_t) port, dst, 443) == wanted)
        {
            return (uint16_t) port;
        }
    }

    twfRequire(false, "no test flow maps to the requested worker");
    return 0;
}

// ---------------------------------------------------------------------------
// candidates, promotion and multi-line join
// ---------------------------------------------------------------------------

static void caseCandidateIsNotSelectable(void)
{
    twfSetCase("a registered candidate cannot carry return traffic");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);

    twfRequire(lineIsTracked(a1), "upstream Init must register the line as a candidate");
    twfRequire(! lineIsActive(a1), "registration alone must not activate a line");

    const uint32_t recycles_before = twfRecycleCount();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);

    twfRequireEqualU32(g_prev_payload_count, 0, "a candidate must never receive a return packet");
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the undeliverable packet must be recycled once");
    twfRequireNoLeakedBuffers();

    closeStreamLine(a1);
    fixtureTeardown();
}

static void caseFirstValidLineEstablishesTheSource(void)
{
    twfSetCase("the first validated line establishes source generation 1");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);

    validateLine(a1, 40000);

    twfRequire(lineIsActive(a1), "a validated candidate must become active");
    twfRequireEqualU32((uint32_t) lineGeneration(a1), 1, "the first epoch must be generation 1");
    twfRequireEqualU32(g_next_payload_count, 1, "the decoded packet must reach the packet chain exactly once");

    // The outer line lives on worker 0, so a packet whose flow belongs elsewhere
    // proves affinity is restored rather than inherited. The callback must also
    // have run as that worker: the right line on the wrong thread is still wrong.
    const wid_t expected_wid = flowWorkerOf(0x0A000001U, 40000, 0xC0000201U, 443);
    twfRequire(g_last_next_line == g_fixture.packet_lines[expected_wid],
               "the decoded packet did not reach its own flow worker's packet line");
    twfRequireEqualU32(g_last_next_wid, expected_wid, "the decoded packet was delivered on the wrong worker");

    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();

    twfRequireEqualU32(g_prev_payload_count, 1, "the return packet must reach the only active line");
    twfRequire(g_last_prev_line == a1, "the return packet went to the wrong line");
    twfRequireEqualU32(g_last_prev_wid, lineGetWID(a1), "the return packet was written on the wrong worker");
    twfRequireNoLeakedBuffers();

    closeStreamLine(a1);
    fixtureTeardown();
}

static void caseSameSourceLinesJoinOneGeneration(void)
{
    twfSetCase("several validated lines from one source share a generation");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);
    line_t *a2 = openStreamLine("10.0.0.1", 1);
    line_t *a3 = openStreamLine("10.0.0.1", 3);

    validateLine(a1, 40000);
    validateLine(a2, 40001);
    validateLine(a3, 40002);

    twfRequire(lineIsActive(a1) && lineIsActive(a2) && lineIsActive(a3), "every same-source line must become active");
    twfRequire(lineGeneration(a1) == 1 && lineGeneration(a2) == 1 && lineGeneration(a3) == 1,
               "a same-source join must not allocate a new generation");

    // Enough distinct flows to show the pool is really shared, not a single
    // winner: rendezvous hashing must place traffic on more than one line.
    bool seen_a1 = false;
    bool seen_a2 = false;
    bool seen_a3 = false;

    for (uint16_t flow = 0; flow < 64; ++flow)
    {
        resetObservations();
        feedReturnPacket(0xC0000201U, (uint16_t) (1000U + flow), 0x0A000001U, 443);
        pumpAllWorkers();

        twfRequireEqualU32(g_prev_payload_count, 1, "every return packet must reach exactly one active line");
        seen_a1 = seen_a1 || (g_last_prev_line == a1);
        seen_a2 = seen_a2 || (g_last_prev_line == a2);
        seen_a3 = seen_a3 || (g_last_prev_line == a3);
    }

    twfRequire(seen_a1 && seen_a2 && seen_a3, "rendezvous selection never used part of the active pool");
    twfRequireNoLeakedBuffers();

    closeStreamLine(a1);
    closeStreamLine(a2);
    closeStreamLine(a3);
    fixtureTeardown();
}

// ---------------------------------------------------------------------------
// per-flow selection properties
// ---------------------------------------------------------------------------

static void caseSelectionIsStableSymmetricAndPauseAware(void)
{
    twfSetCase("selection is stable, symmetric and excludes paused lines");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);
    line_t *a2 = openStreamLine("10.0.0.1", 2);

    validateLine(a1, 40000);
    validateLine(a2, 40001);

    // Stability: the same flow keeps its carrier while the pool is unchanged.
    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    line_t *first_choice = g_last_prev_line;
    twfRequire(first_choice != NULL, "the first return packet was not delivered");

    for (int repeat = 0; repeat < 8; ++repeat)
    {
        resetObservations();
        feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
        pumpAllWorkers();
        twfRequire(g_last_prev_line == first_choice, "one flow changed carrier while the pool was stable");
    }

    // Symmetry: the reverse tuple is the same flow, so it must select the same line.
    resetObservations();
    feedReturnPacket(0x0A000001U, 40000, 0xC0000201U, 443);
    pumpAllWorkers();
    twfRequire(g_last_prev_line == first_choice, "the reverse tuple selected a different carrier");

    // A paused line is excluded, and the flow moves to the remaining one.
    line_t     *other = (first_choice == a1) ? a2 : a1;
    const wid_t prev  = tosSetCurrentWorker(lineGetWID(first_choice));
    streamtopacketsTunnelUpStreamPause(g_fixture.s2p, first_choice);
    discard tosSetCurrentWorker(prev);

    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 1, "a paused carrier must not stop delivery to the rest of the pool");
    twfRequire(g_last_prev_line == other, "a paused line was still selected");

    // With every line paused the packet is dropped rather than queued globally.
    const wid_t prev_other = tosSetCurrentWorker(lineGetWID(other));
    streamtopacketsTunnelUpStreamPause(g_fixture.s2p, other);
    discard tosSetCurrentWorker(prev_other);

    resetObservations();
    const uint32_t recycles_before = twfRecycleCount();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 0, "an all-paused pool must not deliver");
    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the dropped packet must be recycled once");

    // Resume restores the original carrier for that flow.
    const wid_t prev_resume = tosSetCurrentWorker(lineGetWID(first_choice));
    streamtopacketsTunnelUpStreamResume(g_fixture.s2p, first_choice);
    discard     tosSetCurrentWorker(prev_resume);
    const wid_t prev_resume_other = tosSetCurrentWorker(lineGetWID(other));
    streamtopacketsTunnelUpStreamResume(g_fixture.s2p, other);
    discard tosSetCurrentWorker(prev_resume_other);

    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    twfRequire(g_last_prev_line == first_choice, "resume did not restore the original rendezvous winner");
    twfRequireNoLeakedBuffers();

    closeStreamLine(a1);
    closeStreamLine(a2);
    fixtureTeardown();
}

/*
 * Rendezvous hashing's whole reason for being here: a membership change must
 * remap only the flows whose winner actually disappeared, and adding a line back
 * must leave most of the others where they were. Per-packet round-robin would
 * fail both halves.
 */
static void caseMembershipChangeRemapsOnlyAffectedFlows(void)
{
    enum
    {
        kProbeFlows = 128
    };

    twfSetCase("a membership change remaps only the flows it has to");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);
    line_t *a2 = openStreamLine("10.0.0.1", 1);
    line_t *a3 = openStreamLine("10.0.0.1", 2);

    validateLine(a1, 40000);
    validateLine(a2, 40001);
    validateLine(a3, 40002);

    line_t *before[kProbeFlows];

    for (uint16_t flow = 0; flow < kProbeFlows; ++flow)
    {
        streamtopackets_selected_line_t selected;

        twfRequire(streamtopacketsSelectReturnLine(
                       g_fixture.s2p, flowHashOf(0xC0000201U, (uint16_t) (2000U + flow), 0x0A000001U, 443), &selected),
                   "selection failed on a three-line pool");
        before[flow] = selected.line;
        lineUnlock(selected.line);
    }

    // Removing one line may only move the flows that line was carrying.
    closeStreamLine(a2);

    uint32_t moved_from_a2 = 0;

    for (uint16_t flow = 0; flow < kProbeFlows; ++flow)
    {
        streamtopackets_selected_line_t selected;

        twfRequire(streamtopacketsSelectReturnLine(
                       g_fixture.s2p, flowHashOf(0xC0000201U, (uint16_t) (2000U + flow), 0x0A000001U, 443), &selected),
                   "selection failed after a line was removed");
        lineUnlock(selected.line);

        if (before[flow] == a2)
        {
            ++moved_from_a2;
            twfRequire(selected.line != a2, "a removed line was still selected");
            continue;
        }

        twfRequire(selected.line == before[flow], "removing one line remapped an unrelated flow");
    }

    twfRequire(moved_from_a2 > 0, "the fixture never exercised the removed line");

    // Adding a line back takes over some flows, but must leave a clear majority
    // of the others on their previous winner.
    line_t *a4 = openStreamLine("10.0.0.1", 3);
    validateLine(a4, 40003);

    uint32_t kept = 0;

    for (uint16_t flow = 0; flow < kProbeFlows; ++flow)
    {
        streamtopackets_selected_line_t selected;

        twfRequire(streamtopacketsSelectReturnLine(
                       g_fixture.s2p, flowHashOf(0xC0000201U, (uint16_t) (2000U + flow), 0x0A000001U, 443), &selected),
                   "selection failed after a line was added");
        lineUnlock(selected.line);

        if (before[flow] != a2 && selected.line == before[flow])
        {
            ++kept;
        }
    }

    // Three surviving carriers plus one new one: roughly a quarter of the flows
    // should move, so a simple majority staying put is a safe, stable bound.
    twfRequire(kept > (kProbeFlows - moved_from_a2) / 2, "adding one line remapped far more flows than it should");

    closeStreamLine(a1);
    closeStreamLine(a3);
    closeStreamLine(a4);
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

static void caseRendezvousScoreIgnoresOrderAndPointers(void)
{
    twfSetCase("the rendezvous score depends only on the flow hash and line id");

    // Pure function: two different registration orders that produce the same
    // {flow, line_id} pairs must produce the same winner.
    const uint64_t flow = UINT64_C(0x0123456789ABCDEF);

    twfRequire(streamtopacketsRendezvousScore(flow, 1) == streamtopacketsRendezvousScore(flow, 1),
               "the rendezvous score is not deterministic");
    twfRequire(streamtopacketsRendezvousScore(flow, 1) != streamtopacketsRendezvousScore(flow, 2),
               "two line ids collapsed to one score");
    twfRequire(streamtopacketsRendezvousScore(flow, 1) != streamtopacketsRendezvousScore(flow + 1U, 1),
               "two flows collapsed to one score");
}

// ---------------------------------------------------------------------------
// takeover
// ---------------------------------------------------------------------------

static void caseInvalidSecondSourceCannotTakeOver(void)
{
    twfSetCase("malformed traffic from a second source cannot take over");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);
    validateLine(a1, 40000);

    line_t     *b1       = openStreamLine("10.0.0.9", 1);
    const wid_t previous = tosSetCurrentWorker(1);
    feedGarbage(b1);
    discard tosSetCurrentWorker(previous);
    pumpAllWorkers();

    twfRequire(! lineIsActive(b1), "malformed bytes must never activate a candidate");
    twfRequire(lineIsActive(a1), "malformed bytes from another source must not evict the owner");
    twfRequireEqualU32(g_prev_finish_count, 0, "a rejected takeover must not close anything");

    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    twfRequire(g_last_prev_line == a1, "return traffic left the still-owning source");

    closeStreamLine(a1);
    closeStreamLine(b1);

    // Only checked after both parsers are destroyed: the rejected garbage leaves
    // a legitimate partial-header remainder buffered until then.
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

static void caseValidatedSecondSourceTakesOver(void)
{
    twfSetCase("a validated second source replaces the owner and closes every old line");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1     = openStreamLine("10.0.0.1", 0);
    line_t *a2     = openStreamLine("10.0.0.1", 2);
    line_t *a_idle = openStreamLine("10.0.0.1", 3);
    line_t *b1     = openStreamLine("10.0.0.9", 1);

    validateLine(a1, 40000);
    validateLine(a2, 40001);

    twfRequire(lineIsActive(a1) && lineIsActive(a2), "the first source did not establish itself");
    twfRequire(lineIsTracked(a_idle) && ! lineIsActive(a_idle), "the idle line must stay a tracked candidate");

    resetObservations();

    // One valid packet from the second source is the whole takeover trigger.
    const wid_t previous = tosSetCurrentWorker(1);
    feedPacket(b1, 0x0A00000AU, 41000, 0xC0000202U, 443);
    discard tosSetCurrentWorker(previous);

    twfRequire(lineIsActive(b1), "the validated new source did not activate");
    twfRequireEqualU32((uint32_t) lineGeneration(b1), 2, "a takeover must publish a new generation");

    // An old-source line that is already inside a payload callback cannot promote
    // itself back: its registry entry was detached at the linearization point.
    const wid_t on_a1 = tosSetCurrentWorker(0);
    twfRequireEqualU32((uint32_t) streamtopacketsAuthorizeLine(g_fixture.s2p, a1),
                       0,
                       "an evicted line was allowed to authorize traffic again");
    discard tosSetCurrentWorker(on_a1);

    pumpAllWorkers();

    // Every old-source line, including the idle candidate, is closed through the
    // previous side on its own worker.
    twfRequireEqualU32(g_prev_finish_count, 3, "every old-source line and candidate must be closed exactly once");
    twfRequire(! lineIsTracked(a1) && ! lineIsTracked(a2) && ! lineIsTracked(a_idle),
               "an evicted line stayed tracked after its close task ran");

    resetObservations();
    feedReturnPacket(0xC0000202U, 443, 0x0A00000AU, 41000);
    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 1, "the new source must receive return traffic");
    twfRequire(g_last_prev_line == b1, "return traffic did not follow the new source");
    twfRequireNoLeakedBuffers();

    closeStreamLine(b1);
    twfLineDestroy(a1);
    twfLineDestroy(a2);
    twfLineDestroy(a_idle);
    fixtureTeardown();
}

static void caseFinalLineFinishClearsSelection(void)
{
    twfSetCase("the last active line's finish clears selection and stales queued work");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);
    line_t *a2 = openStreamLine("10.0.0.1", 2);

    validateLine(a1, 40000);
    validateLine(a2, 40001);

    closeStreamLine(a1);

    // One line left: the epoch survives and still carries traffic.
    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 1, "a surviving line must keep carrying return traffic");
    twfRequire(g_last_prev_line == a2, "return traffic did not move to the surviving line");

    /*
     * A write selected against the live pool must be rejected when the epoch ends
     * before the target worker runs it. The selection holds a reference, so the
     * line stays readable and alive here: what rejects the write is the published
     * generation, not a dead line.
     */
    streamtopackets_selected_line_t selected;
    const uint64_t                  flow = flowHashOf(0xC0000201U, 443, 0x0A000001U, 40000);
    twfRequire(streamtopacketsSelectReturnLine(g_fixture.s2p, flow, &selected), "selection failed on a live pool");
    twfRequire(selected.line == a2, "selection did not pick the only remaining line");

    finishStreamLine(a2);

    resetObservations();
    sbuf_t *stale = bufferpoolGetSmallBuffer(getWorkerBufferPool(0));
    sbufSetLength(stale, kTestPacketLength);
    buildIpv4(sbufGetMutablePtr(stale), 0xC0000201U, 443, 0x0A000001U, 40000);

    streamtopacketsQueueSelectedWrite(g_fixture.s2p, &selected, stale);
    pumpAllWorkers();

    twfRequireEqualU32(g_prev_payload_count, 0, "a write from a cleared generation must not be delivered");

    /*
     * Membership rather than a recycle delta: queueing a worker message also wakes
     * the target loop, and that wakeup read borrows a pooled buffer of its own in
     * debug builds. The ledger still fails hard on a second recycle of this exact
     * buffer, and the leak check below covers the opposite mistake.
     */
    twfRequire(twfLedgerContains(g_twf_buffers.recycled, g_twf_buffers.recycled_count, stale),
               "the stale write did not release its buffer");

    // Selection now finds nothing at all.
    twfRequire(! streamtopacketsSelectReturnLine(g_fixture.s2p, flow, &selected),
               "selection succeeded with no active line");

    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 0, "an ownerless tunnel must drop return traffic");
    twfRequireNoLeakedBuffers();

    // The rejected write released the selection's reference, so nothing points at
    // this line any more.
    twfRequireEqualU32(twfLineRefCount(a2), 1, "the rejected write did not release its line reference");
    twfLineDestroy(a2);
    fixtureTeardown();
}

/*
 * A decoded packet that is already sitting in another worker's queue when a
 * takeover linearizes belongs to an epoch that no longer owns the tunnel. The
 * target worker must reject it when it finally runs, or the new owner's device
 * sees traffic from the source it replaced.
 */
static void caseQueuedPacketFromAnEvictedSourceIsDropped(void)
{
    twfSetCase("a queued packet from a superseded source is dropped by its target worker");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);
    line_t *b1 = openStreamLine("10.0.0.9", 0);

    validateLine(a1, 40000);
    resetObservations();

    // A flow that does not belong to worker 0, so the packet is really queued.
    const uint16_t queued_port = sourcePortForFlowWorker(0x0A000001U, 0xC0000201U, 2);
    const wid_t    previous    = tosSetCurrentWorker(0);
    feedPacket(a1, 0x0A000001U, queued_port, 0xC0000201U, 443);
    discard tosSetCurrentWorker(previous);

    twfRequireEqualU32(g_next_payload_count, 0, "the fixture delivered the packet instead of queueing it");

    /*
     * The takeover runs on worker 0 while worker 2 still holds the old packet.
     * Its own flow is chosen to belong to worker 0 so the new owner's traffic is
     * delivered directly and cannot be confused with the queued one.
     */
    const uint16_t direct_port = sourcePortForFlowWorker(0x0A00000AU, 0xC0000202U, 0);
    const wid_t    on_takeover = tosSetCurrentWorker(0);
    feedPacket(b1, 0x0A00000AU, direct_port, 0xC0000202U, 443);
    discard tosSetCurrentWorker(on_takeover);

    twfRequire(lineIsActive(b1), "the second source did not take over");
    twfRequireEqualU32(g_next_payload_count, 1, "the new owner's own packet was not delivered directly");
    twfRequireEqualU32(g_last_next_source, 0x0A00000AU, "the delivered packet did not come from the new owner");

    pumpAllWorkers();

    twfRequireEqualU32(g_next_payload_count, 1, "a queued packet from the evicted source reached the packet chain");
    twfRequireNoLeakedBuffers();

    closeStreamLine(b1);
    twfLineDestroy(a1);
    fixtureTeardown();
}

/*
 * "Every old-source line is closed" has to survive a worker message that cannot
 * be posted. When the evicted line belongs to the worker running the takeover,
 * the close is simply performed there and nothing else changes.
 */
static void caseEvictionCloseFailureIsRecoveredOnItsOwnWorker(void)
{
    twfSetCase("an eviction close that cannot be queued is performed on the takeover's own worker");
    tosResetProcessApi(true);
    fixtureSetup();

    // Both on worker 0, which is where the takeover runs.
    line_t *a1 = openStreamLine("10.0.0.1", 0);
    line_t *b1 = openStreamLine("10.0.0.9", 0);

    validateLine(a1, 40000);
    resetObservations();

    g_force_queue_failures = 0;
    g_force_queue_fails    = true;

    const uint16_t direct_port = sourcePortForFlowWorker(0x0A00000AU, 0xC0000202U, 0);
    const wid_t    previous    = tosSetCurrentWorker(0);
    feedPacket(b1, 0x0A00000AU, direct_port, 0xC0000202U, 443);
    discard tosSetCurrentWorker(previous);

    g_force_queue_fails = false;

    twfRequire(g_force_queue_failures > 0, "the fixture never rejected a worker message");
    twfRequire(lineIsActive(b1), "a rejected eviction close must not abandon the takeover itself");

    // Closed exactly once, through the previous side, without touching the
    // process: a locally recoverable failure is not a reason to shut anything
    // down.
    twfRequire(! lineIsTracked(a1), "an evicted line on the takeover's own worker was not closed");
    twfRequireEqualU32(g_prev_finish_count, 1, "the recoverable line must have been closed exactly once");
    twfRequire(g_last_prev_finish_line == a1, "the wrong line was closed on the caller");
    tosRequireNoProcessApiCall();

    resetObservations();
    feedReturnPacket(0xC0000202U, 443, 0x0A00000AU, direct_port);
    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 1, "the new owner stopped receiving return traffic");
    twfRequire(g_last_prev_line == b1, "return traffic reached a line that no longer owns the source");

    closeStreamLine(b1);
    twfLineDestroy(a1);
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

/*
 * The same failure for a line on another worker has no local recovery: nothing
 * but that worker may touch its state, and the one channel to it just failed for
 * a reason that is not shutdown. Leaving an old-source connection and its parser
 * running is not an option, so this fails closed instead of degrading quietly.
 */
static void caseEvictionCloseFailureOnAnotherWorkerFailsClosed(void)
{
    twfSetCase("an eviction close that cannot be delivered to another worker fails closed");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a_remote = openStreamLine("10.0.0.1", 2);
    line_t *b1       = openStreamLine("10.0.0.9", 0);

    validateLine(a_remote, 40000);
    resetObservations();

    g_force_queue_failures = 0;
    g_force_queue_fails    = true;

    const uint16_t direct_port = sourcePortForFlowWorker(0x0A00000AU, 0xC0000202U, 0);
    const wid_t    previous    = tosSetCurrentWorker(0);
    feedPacket(b1, 0x0A00000AU, direct_port, 0xC0000202U, 443);
    discard tosSetCurrentWorker(previous);

    g_force_queue_fails = false;

    twfRequire(g_force_queue_failures > 0, "the fixture never rejected a worker message");
    tosRequireAcceptedRequest(1);

    // No local close was possible, and the line is still out of the registry, so
    // it cannot carry traffic while the shutdown it asked for runs.
    const wid_t on_remote = tosSetCurrentWorker(2);
    twfRequireEqualU32((uint32_t) streamtopacketsAuthorizeLine(g_fixture.s2p, a_remote),
                       0,
                       "a line whose close could not be delivered could still authorize traffic");
    discard tosSetCurrentWorker(on_remote);
    twfRequireEqualU32(g_prev_finish_count, 0, "no line on another worker may be closed from here");

    closeStreamLine(a_remote);
    closeStreamLine(b1);
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

// The child body for the case below; it must not return.
static void evictionCloseFailureRefusedHandoffBody(void *argument)
{
    discard argument;

    fixtureSetup();

    line_t *a_remote = openStreamLine("10.0.0.1", 2);
    line_t *b1       = openStreamLine("10.0.0.9", 0);

    validateLine(a_remote, 40000);

    g_force_queue_fails = true;

    const wid_t previous = tosSetCurrentWorker(0);
    feedPacket(b1, 0x0A00000AU, sourcePortForFlowWorker(0x0A00000AU, 0xC0000202U, 0), 0xC0000202U, 443);
    discard tosSetCurrentWorker(previous);
}

/*
 * When worker 0 will not take the orderly shutdown handoff, the fallback is the
 * hard abort. Reaching it needs its own process, because it must not return.
 */
static void caseEvictionCloseFailureAbortsWhenShutdownIsRefused(void)
{
    twfSetCase("a refused shutdown handoff after a lost eviction close hard-aborts");
    tosResetProcessApi(false);

    tosRequireChildExit(
        "the lost eviction close", evictionCloseFailureRefusedHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

/*
 * onStop only refuses new registrations, which is not enough: a candidate that
 * registered a moment earlier could otherwise validate afterwards and start a
 * takeover, queueing close work onto workers that are already shutting down.
 */
static void caseStoppingRefusesPromotionButLetsOwnersDrain(void)
{
    twfSetCase("stopping refuses promotion while an established owner keeps draining");
    tosResetProcessApi(true);
    fixtureSetup();

    line_t *a1 = openStreamLine("10.0.0.1", 0);

    validateLine(a1, 40000);

    // Both registered before onStop, so only the promotion rule can reject them.
    line_t *a2 = openStreamLine("10.0.0.1", 1);
    line_t *b1 = openStreamLine("10.0.0.9", 2);

    streamtopacketsTunnelOnQuiesceRequest(g_fixture.s2p, wwLifecycleStartupRollback());
    resetObservations();

    validateLine(a2, 40001);
    twfRequire(! lineIsActive(a2), "a same-source candidate was promoted after onStop");

    const wid_t previous = tosSetCurrentWorker(2);
    feedPacket(b1, 0x0A00000AU, 41000, 0xC0000202U, 443);
    discard tosSetCurrentWorker(previous);
    pumpAllWorkers();

    twfRequire(! lineIsActive(b1), "a second source took ownership after onStop");
    twfRequire(lineIsActive(a1), "an already-active line must keep draining while stopping");
    twfRequireEqualU32((uint32_t) lineGeneration(a1), 1, "a refused takeover must not change the generation");
    twfRequireEqualU32(g_prev_finish_count, 0, "a refused takeover must not close anything");

    // The established owner still carries return traffic while the node drains.
    resetObservations();
    feedReturnPacket(0xC0000201U, 443, 0x0A000001U, 40000);
    pumpAllWorkers();
    twfRequireEqualU32(g_prev_payload_count, 1, "the surviving owner stopped receiving return traffic");
    twfRequire(g_last_prev_line == a1, "return traffic left the still-owning line");

    // A line arriving after onStop is refused outright and closed.
    resetObservations();
    line_t     *late    = lineCreateOnWorker(g_fixture.s2p->lstate_size, 3);
    const wid_t on_late = tosSetCurrentWorker(3);
    lineSetSourceIpv4(late, "10.0.0.1");
    streamtopacketsTunnelUpStreamInit(g_fixture.s2p, late);
    discard tosSetCurrentWorker(on_late);

    twfRequire(! lineIsTracked(late), "a line registered after onStop must not be tracked");
    twfRequireEqualU32(g_prev_finish_count, 1, "a refused registration must close its line");
    twfRequire(g_last_prev_finish_line == late, "the wrong line was closed after a refused registration");
    twfLineDestroy(late);

    twfRequireNoLeakedBuffers();

    closeStreamLine(a1);
    closeStreamLine(a2);
    closeStreamLine(b1);
    fixtureTeardown();
}

// ---------------------------------------------------------------------------
// sensitive-mode heartbeats
// ---------------------------------------------------------------------------

/*
 * A valid heartbeat is the other kind of protocol proof, so it has to be worth
 * exactly as much as a packet: it establishes a source, it can take one over,
 * and anything that only resembles one is worth nothing.
 */
static void caseHeartbeatsEstablishAndTakeOverOwnership(void)
{
    twfSetCase("a valid heartbeat establishes and can take over a source");
    tosResetProcessApi(true);
    fixtureSetup();

    streamtopackets_tstate_t *ts = tunnelGetState(g_fixture.s2p);
    ts->sensitive_mode           = true;

    line_t *a1 = openStreamLine("10.0.0.1", 0);
    line_t *b1 = openStreamLine("10.0.0.9", 1);

    // Establishment: the ping activates the candidate and is answered with a pong
    // on the same line. Control traffic never reaches the packet chain.
    resetObservations();
    const wid_t on_a1 = tosSetCurrentWorker(0);
    feedHeartbeat(a1, kSensitivePingByte);
    discard tosSetCurrentWorker(on_a1);

    twfRequire(lineIsActive(a1), "a valid heartbeat did not establish the source");
    twfRequireEqualU32((uint32_t) lineGeneration(a1), 1, "the first heartbeat epoch must be generation 1");
    twfRequireEqualU32(g_prev_payload_count, 1, "a valid heartbeat was not answered with exactly one pong");
    twfRequire(g_last_prev_line == a1, "the pong went to the wrong line");
    twfRequireEqualU32(g_next_payload_count, 0, "a heartbeat must never reach the packet chain");

    // A heartbeat-shaped frame with the wrong fill byte is not a ping: it is just
    // an ordinary packet, so it is forwarded and never answered.
    resetObservations();
    const wid_t on_a1_again = tosSetCurrentWorker(0);
    feedHeartbeat(a1, 0xAB);
    discard tosSetCurrentWorker(on_a1_again);
    pumpAllWorkers();

    twfRequireEqualU32(g_prev_payload_count, 0, "a frame that is not a ping was answered with a pong");
    twfRequireEqualU32(g_next_payload_count, 1, "a non-ping frame was not treated as an ordinary packet");

    // Bytes that never frame prove nothing, so they neither answer nor promote.
    resetObservations();
    const wid_t on_b1 = tosSetCurrentWorker(1);
    feedGarbage(b1);
    discard tosSetCurrentWorker(on_b1);
    pumpAllWorkers();

    twfRequire(! lineIsActive(b1), "malformed bytes activated a candidate in sensitive mode");
    twfRequireEqualU32(g_prev_payload_count, 0, "malformed bytes produced a pong");
    twfRequire(lineIsActive(a1), "malformed bytes from another source evicted the owner");

    // Takeover on a heartbeat alone, with the old line closed the usual way.
    resetObservations();
    const wid_t on_b1_ping = tosSetCurrentWorker(1);
    feedHeartbeat(b1, kSensitivePingByte);
    discard tosSetCurrentWorker(on_b1_ping);
    pumpAllWorkers();

    twfRequire(lineIsActive(b1), "a valid heartbeat from a new source did not take over");
    twfRequireEqualU32((uint32_t) lineGeneration(b1), 2, "a heartbeat takeover must publish a new generation");
    twfRequire(! lineIsTracked(a1), "the old owner was not closed by a heartbeat takeover");
    twfRequireEqualU32(g_prev_finish_count, 1, "the old owner must be closed exactly once");
    twfRequireEqualU32(g_prev_payload_count, 1, "the new owner's heartbeat was not answered");
    twfRequire(g_last_prev_line == b1, "the pong went to the evicted line");

    twfRequireNoLeakedBuffers();

    closeStreamLine(b1);
    twfLineDestroy(a1);
    fixtureTeardown();
}

// ---------------------------------------------------------------------------
// anonymous peers
// ---------------------------------------------------------------------------

static void caseAnonymousLinesShareOneIdentity(void)
{
    twfSetCase("lines without a concrete source IP share the anonymous identity");
    tosResetProcessApi(true);
    fixtureSetup();

    // A directly composed in-process bridge has no peer address on either line.
    line_t *first  = lineCreateOnWorker(g_fixture.s2p->lstate_size, 0);
    line_t *second = lineCreateOnWorker(g_fixture.s2p->lstate_size, 1);

    const wid_t on_zero = tosSetCurrentWorker(0);
    streamtopacketsTunnelUpStreamInit(g_fixture.s2p, first);
    discard tosSetCurrentWorker(on_zero);

    const wid_t on_one = tosSetCurrentWorker(1);
    streamtopacketsTunnelUpStreamInit(g_fixture.s2p, second);
    discard tosSetCurrentWorker(on_one);

    validateLine(first, 40000);
    validateLine(second, 40001);

    twfRequire(lineIsActive(first) && lineIsActive(second), "anonymous lines must be able to coexist");
    twfRequire(lineGeneration(first) == lineGeneration(second),
               "anonymous lines must share one source identity and generation");
    twfRequireEqualU32(g_prev_finish_count, 0, "an anonymous join must not evict anything");
    twfRequireNoLeakedBuffers();

    closeStreamLine(first);
    closeStreamLine(second);
    fixtureTeardown();
}

int main(void)
{
    caseStartupAdmissionIsCheckedForEveryWorker();
    caseCandidateIsNotSelectable();
    caseFirstValidLineEstablishesTheSource();
    caseSameSourceLinesJoinOneGeneration();
    caseSelectionIsStableSymmetricAndPauseAware();
    caseMembershipChangeRemapsOnlyAffectedFlows();
    caseRendezvousScoreIgnoresOrderAndPointers();
    caseInvalidSecondSourceCannotTakeOver();
    caseValidatedSecondSourceTakesOver();
    caseQueuedPacketFromAnEvictedSourceIsDropped();
    caseEvictionCloseFailureIsRecoveredOnItsOwnWorker();
    caseEvictionCloseFailureOnAnotherWorkerFailsClosed();
    caseEvictionCloseFailureAbortsWhenShutdownIsRefused();
    caseStoppingRefusesPromotionButLetsOwnersDrain();
    caseHeartbeatsEstablishAndTakeOverOwnership();
    caseFinalLineFinishClearsSelection();
    caseAnonymousLinesShareOneIdentity();

    printf("streamtopackets_ownership_test: all cases passed\n");
    return 0;
}
