/*
 * Covers: decoded TCP/UDP worker ownership, checksum requests and packet lifetime.
 * Setup: real worker queues, packet-line identities and shared fragment table.
 * Cases: cross/same/single-worker delivery; opaque and normal-line pass-through;
 * admission refusal, foreign cancellation, dead target, late fragments and shutdown.
 * Limits: kernel queue selection and decoder wire formats have separate coverage.
 * CTest: waterwall.packet_affinity_unit
 */
#include "devices/device_flow_affinity.h"
#include "devices/device_packet_checksum_internal.h"
#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#include "packet_affinity.h"
#include "packet_batch.h"
#include "wloop_internal.h"

typedef struct affinity_fixture_s
{
    tos_worker_env_t           env;
    tunnel_t                  *tunnel;
    tunnel_chain_t            *chain;
    line_t                    *lines[kTosMaxWorkers];
    packet_affinity_t         *affinity;
    unsigned                   delivered;
    wid_t                      last_wid;
    bool                       requested;
    bool                       requests[1024];
    uint16_t                   fragments[1024];
    uint16_t                   ids[1024];
    bool                       receiving;
    bool                       close_after_first;
    packet_batch_participant_t participant;
    unsigned                   batch_begins;
    unsigned                   batch_ends;
    sbuf_t                    *retained;
    sbuf_t                    *nested;
    bool                       check_fragment_checksum;
} affinity_fixture_t;

typedef struct forward_call_s
{
    packet_affinity_t *affinity;
    line_t            *line;
    sbuf_t            *buf;
} forward_call_t;

static void forwardRoot(void *arg)
{
    forward_call_t *call = arg;
    packetAffinityForward(call->affinity, call->line, call->buf);
}

static void forwardPacket(packet_affinity_t *affinity, line_t *line, sbuf_t *buf)
{
    forward_call_t call = {.affinity = affinity, .line = line, .buf = buf};
    twfRequire(wloopInvokeNormalCallback(getCurrentWorkerLoop(), forwardRoot, &call), "test callback admission closed");
}

static unsigned                posts;
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
    ++posts;
    return __real_sendWorkerMessageForceQueueWithCleanup(wid, cb, cleanup, arg1, arg2, arg3);
}

static void beginBatch(void *context)
{
    ++((affinity_fixture_t *) context)->batch_begins;
}

static void endBatch(void *context)
{
    ++((affinity_fixture_t *) context)->batch_ends;
}

static void receivePacket(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    affinity_fixture_t *fixture = *(affinity_fixture_t **) tunnelGetState(t);
    twfRequire(lineIsOnCurrentWorker(line), "decoded packet ran on another line's worker");
    twfRequire(fixture->delivered < 1024, "too many decoded packets");
    twfRequire(! fixture->receiving, "nested packet bypassed the destination FIFO");
    fixture->receiving = true;
    discard        packetBatchJoin(&fixture->participant);
    const unsigned index      = fixture->delivered++;
    fixture->fragments[index] = GET_BE16((const uint8_t *) sbufGetRawPtr(buf) + 6);
    fixture->last_wid         = lineGetWID(line);
    fixture->ids[index]       = GET_BE16((const uint8_t *) sbufGetRawPtr(buf) + 4);
    fixture->requested        = packettunnelTakeChecksumRequest(buf);
    fixture->requests[index]  = fixture->requested;
    if (fixture->check_fragment_checksum)
    {
        const uint8_t *bytes = sbufGetRawPtr(buf);
        uint32_t       sum   = 0;
        for (unsigned i = 0; i < 20; i += 2)
            sum += GET_BE16(bytes + i);
        while (sum >> 16)
            sum = (sum & UINT32_C(0xffff)) + (sum >> 16);
        twfRequire(sum == UINT32_C(0xffff), "staged fragment reached delivery without header repair");
    }
    if (fixture->retained != NULL)
        twfRequire(sbufGetRecalculateChecksum(fixture->retained), "another packet consumed retained intent");
    if (fixture->nested != NULL)
    {
        sbuf_t *nested  = fixture->nested;
        fixture->nested = NULL;
        forwardPacket(fixture->affinity, line, nested);
        twfRequire(! sbufGetRecalculateChecksum(buf), "nested delivery resurrected consumed intent");
    }
    if (fixture->close_after_first && fixture->delivered == 1)
        discard wloopCloseNormalAdmission(getCurrentWorkerLoop());
    fixture->receiving = false;
    lineReuseBuffer(line, buf);
}

static void setup(affinity_fixture_t *fixture, wid_t workers)
{
    memoryZero(fixture, sizeof(*fixture));
    posts                = 0;
    fixture->participant = (packet_batch_participant_t) {.begin = beginBatch, .end = endBatch, .context = fixture};
    tosWorkerEnvSetup(&fixture->env, workers, 8192, 2048);
    fixture->tunnel = tunnelCreate(NULL, sizeof(affinity_fixture_t *), 0);
    twfRequire(fixture->tunnel != NULL, "could not create decoder fixture");
    *(affinity_fixture_t **) tunnelGetState(fixture->tunnel) = fixture;
    fixture->chain                                           = tunnelchainCreate(workers);
    fixture->chain->packet_lines                             = fixture->lines;
    fixture->tunnel->chain                                   = fixture->chain;
    for (wid_t wid = 0; wid < workers; ++wid)
    {
        fixture->lines[wid]      = twfLineCreate(0);
        fixture->lines[wid]->wid = wid;
    }
    fixture->affinity = packetAffinityCreate(fixture->tunnel, receivePacket);
    twfRequire(fixture->affinity != NULL, "could not create packet affinity");
}

static void teardown(affinity_fixture_t *fixture)
{
    packetAffinityDestroy(fixture->affinity);
    for (wid_t wid = 0; wid < fixture->env.count; ++wid)
    {
        twfRequire(twfLineRefCount(fixture->lines[wid]) == 1, "queued packet retained its target line");
        twfLineDestroy(fixture->lines[wid]);
    }
    twfRequire(g_twf_buffers.live_count == 0, "decoded packet was neither delivered nor discarded");
    tunnelDestroy(fixture->tunnel);
    memoryFree(fixture->chain);
    tosWorkerEnvTeardown(&fixture->env);
}

static sbuf_t *makePacket(uint8_t protocol, wid_t target, bool fragmented, bool tail)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(getCurrentWorkerBufferPool());
    sbufSetLength(buf, 36);
    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, 36);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = protocol;
    PUT_BE16(packet + 2, 36);
    PUT_BE16(packet + 4, 123);
    PUT_BE32(packet + 12, UINT32_C(0xC0000201));
    PUT_BE32(packet + 16, UINT32_C(0xC6336401));
    PUT_BE16(packet + 22, 443);
    for (uint32_t port = 1000;; ++port)
    {
        twfRequire(port <= UINT16_MAX, "could not find desired test worker");
        PUT_BE16(packet + 20, (uint16_t) port);
        wid_t wid;
        twfRequire(deviceFlowAffineWID(packet, 36, &wid), "test packet was not hashable");
        if (wid == target || (protocol != 6 && protocol != 17))
            break;
    }
    if (fragmented)
        PUT_BE16(packet + 6, tail ? 2 : 0x2000);
    PUT_BE16(packet + 10, deviceIpv4HeaderChecksum(packet, 20));
    return buf;
}

static void caseWorkerSelection(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    for (uint8_t protocol = 6; protocol <= 17; protocol += 11)
    {
        sbuf_t *packet = makePacket(protocol, 2, false, false);
        sbufSetRecalculateChecksum(packet, true);
        forwardPacket(fixture.affinity, fixture.lines[0], packet);
        const unsigned before = fixture.delivered;
        tosPumpWorker(&fixture.env, 2);
        twfRequire(fixture.delivered == before + 1 && fixture.last_wid == 2 && fixture.requested,
                   "decoded TCP/UDP packet or checksum request reached the wrong worker");
    }
    const unsigned before = fixture.delivered;
    forwardPacket(fixture.affinity, fixture.lines[0], makePacket(17, 0, false, false));
    twfRequire(fixture.delivered == before + 1 && fixture.last_wid == 0, "same-worker delivery was queued");
    forwardPacket(fixture.affinity, fixture.lines[0], makePacket(50, 0, false, false));
    twfRequire(fixture.delivered == before + 2 && fixture.last_wid == 0, "opaque input was redistributed");
    line_t *normal = twfLineCreate(0);
    forwardPacket(fixture.affinity, normal, makePacket(17, 3, false, false));
    twfRequire(fixture.delivered == before + 3 && fixture.last_wid == 0, "normal line escaped its owner");
    twfLineDestroy(normal);
    teardown(&fixture);
}

static void caseFragmentFlow(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    fixture.check_fragment_checksum = true;
    sbuf_t *tail                    = makePacket(17, 2, true, true);
    ((uint8_t *) sbufGetMutablePtr(tail))[10] ^= 0xff;
    sbufSetRecalculateChecksum(tail, true);
    forwardPacket(fixture.affinity, fixture.lines[0], tail);
    twfRequire(fixture.delivered == 0 && g_twf_buffers.live_count == 1, "tail was not staged pending ports");
    testWorkerBindWID(1);
    sbuf_t *head = makePacket(17, 2, true, false);
    ((uint8_t *) sbufGetMutablePtr(head))[10] ^= 0xff;
    sbufSetRecalculateChecksum(head, true);
    forwardPacket(fixture.affinity, fixture.lines[1], head);
    twfRequire(fixture.delivered == 0, "fragments ran on a reader instead of the flow owner");
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 2 && fixture.last_wid == 2 && fixture.fragments[0] == 2 &&
                   fixture.fragments[1] == 0x2000,
               "fragment handoff changed affinity, boundaries or release order");
    twfRequire(! fixture.requests[0] && ! fixture.requests[1], "fragment staging did not settle repair requests");
    forwardPacket(fixture.affinity, fixture.lines[1], makePacket(17, 2, false, false));
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 3 && fixture.last_wid == 2, "complete flow and fragments split workers");
    forwardPacket(fixture.affinity, fixture.lines[1], makePacket(17, 2, true, true));
    teardown(&fixture); /* Destroy must release the new incomplete datagram. */
}

static void caseSettlement(unsigned mode)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    if (mode == 0)
        workerMessagesCloseAdmission(&fixture.env.workers[2]);
    sbuf_t *packet = makePacket(6, 2, false, false);
    sbufSetRecalculateChecksum(packet, true);
    forwardPacket(fixture.affinity, fixture.lines[0], packet);
    if (mode == 1)
    {
        /* Admission closes before execution; cleanup runs on a foreign thread
         * identity and must not invoke the decoder or borrow either pool. */
        workerMessagesCloseAdmission(&fixture.env.workers[2]);
        testWorkerUnbindWID();
        workerMessagesCleanupPending(&fixture.env.workers[2]);
        testWorkerBindWID(0);
    }
    else if (mode == 2)
    {
        fixture.lines[2]->alive = false;
        tosPumpWorker(&fixture.env, 2);
    }
    twfRequire(fixture.delivered == 0, "refused/canceled/dead-target packet reached a continuation");
    teardown(&fixture);
}

static void caseSingleWorker(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 1);
    sbuf_t *packet = makePacket(6, 0, false, false);
    sbufSetRecalculateChecksum(packet, true);
    forwardPacket(fixture.affinity, fixture.lines[0], packet);
    twfRequire(fixture.delivered == 1 && fixture.requested, "single-worker fast path changed checksum metadata");
    forwardPacket(fixture.affinity, fixture.lines[0], makePacket(6, 0, false, false));
    twfRequire(fixture.delivered == 2 && ! fixture.requested, "single-worker packet inherited a request");
    teardown(&fixture);
}

static void caseIndependentPackets(bool queued)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    fixture.retained = makePacket(17, 0, false, false);
    sbufSetRecalculateChecksum(fixture.retained, true);
    fixture.nested = makePacket(17, queued ? 2 : 0, false, false);
    sbuf_t *marked = makePacket(17, queued ? 2 : 0, false, false);
    sbufSetRecalculateChecksum(marked, true);
    forwardPacket(fixture.affinity, fixture.lines[0], marked);
    forwardPacket(fixture.affinity, fixture.lines[0], makePacket(17, queued ? 2 : 0, false, false));
    if (queued)
        tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 3 && fixture.requests[0] && ! fixture.requests[1] && ! fixture.requests[2],
               "mixed or nested packets changed independent checksum requests");
    twfRequire(sbufGetRecalculateChecksum(fixture.retained), "delivery changed a retained packet");
    sbufDestroy(fixture.retained);
    fixture.retained = NULL;
    teardown(&fixture);
}

static sbuf_t *identifiedPacket(wid_t target, uint16_t id)
{
    sbuf_t *buf = makePacket(17, target, false, false);
    PUT_BE16((uint8_t *) sbufGetMutablePtr(buf) + 4, id);
    return buf;
}

static void caseDestinationFIFO(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    forwardPacket(fixture.affinity, fixture.lines[0], identifiedPacket(2, 1));
    testWorkerBindWID(1);
    forwardPacket(fixture.affinity, fixture.lines[1], identifiedPacket(2, 2));
    testWorkerBindWID(2);
    forwardPacket(fixture.affinity, fixture.lines[2], identifiedPacket(2, 3));
    fixture.nested = identifiedPacket(2, 4);
    twfRequire(fixture.delivered == 0 && posts == 1, "local packet bypassed older queued input or duplicated wakeup");
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 4 && posts == 1, "destination FIFO failed to coalesce delivery");
    for (unsigned i = 0; i < 4; ++i)
        twfRequire(fixture.ids[i] == i + 1, "different producers or reentrant input overtook accepted packets");
    twfRequire(fixture.batch_begins == 1 && fixture.batch_ends == 1, "queued delivery lost its packet batch");
    teardown(&fixture);
}

static void caseBoundsAndQuantum(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    for (unsigned i = 0; i < 513; ++i)
        forwardPacket(fixture.affinity, fixture.lines[0], identifiedPacket(2, (uint16_t) i));
    twfRequire(g_twf_buffers.live_count == 512 && posts == 1, "packet admission exceeded its aggregate bound");
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 512 && posts == 2, "drain did not yield after its packet quantum");
    twfRequire(fixture.batch_begins == 2 && fixture.batch_ends == 2, "each quantum needs its own packet batch");
    for (unsigned i = 0; i < 512; ++i)
        twfRequire(fixture.ids[i] == i, "yield reordered accepted packets");
    teardown(&fixture);

    setup(&fixture, 4);
    for (unsigned i = 0; i < 8; ++i)
    {
        sbuf_t *small = identifiedPacket(2, (uint16_t) i);
        sbuf_t *large = bufferpoolGetBestFit(getCurrentWorkerBufferPool(), 1024 * 1024, 0);
        memoryCopy(sbufGetMutablePtr(large), sbufGetRawPtr(small), sbufGetLength(small));
        sbufSetLength(large, sbufGetLength(small));
        lineReuseBuffer(fixture.lines[0], small);
        forwardPacket(fixture.affinity, fixture.lines[0], large);
    }
    twfRequire(g_twf_buffers.live_count == 7, "allocation charge bound counted payload bytes instead of storage");
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 7, "allocation-bound refusal changed accepted delivery");
    forwardPacket(fixture.affinity, fixture.lines[0], identifiedPacket(2, 9));
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 8, "drained allocation budget was not released");
    teardown(&fixture);
}

static void caseInheritedBatch(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    packet_batch_t batch;
    packetBatchBegin(&batch);
    forwardPacket(fixture.affinity, fixture.lines[0], identifiedPacket(0, 1));
    forwardPacket(fixture.affinity, fixture.lines[0], identifiedPacket(0, 2));
    twfRequire(fixture.batch_begins == 1 && fixture.batch_ends == 0, "local delivery nested or lost reader batch");
    packetBatchEnd(&batch);
    twfRequire(fixture.batch_ends == 1, "reader batch failed to flush");
    teardown(&fixture);
}

static void caseSameWorkerClosed(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    workerMessagesCloseAdmission(&fixture.env.workers[0]);
    packetAffinityForward(fixture.affinity, fixture.lines[0], identifiedPacket(0, 1));
    twfRequire(fixture.delivered == 0 && g_twf_buffers.live_count == 0,
               "worker identity reopened delivery after admission closed");
    teardown(&fixture);
}

static void caseQuiesceDuringDrain(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    fixture.close_after_first = true;
    forwardPacket(fixture.affinity, fixture.lines[0], identifiedPacket(2, 1));
    forwardPacket(fixture.affinity, fixture.lines[0], identifiedPacket(2, 2));
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 1, "drain continued normal delivery after quiescence");
    /* Closing loop admission stops dispatch; the runtime then cancels messages
     * accepted before worker-message admission closed, including the remainder
     * token coalesced into the already-running worker wakeup. */
    workerMessagesCloseAdmission(&fixture.env.workers[2]);
    testWorkerUnbindWID();
    workerMessagesCleanupPending(&fixture.env.workers[2]);
    testWorkerBindWID(0);
    twfRequire(g_twf_buffers.live_count == 0, "quiescence cancellation leaked queued packet");
    twfRequire(fixture.batch_begins == 1 && fixture.batch_ends == 1, "quiescence failed to flush active batch");
    teardown(&fixture);
}

static unsigned finishes;
static void     receiveFinish(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequire(lineIsOnCurrentWorker(line), "helper Finish changed its worker");
    ++finishes;
}

static void caseDirectionalTunnel(flow_affinity_direction_t direction)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    tunnel_t *helper = flowAffinityTunnelCreate(direction);
    twfRequire(helper != NULL && helper->node->layer_group == kNodeLayer3 && helper->lstate_size == 0,
               "internal helper has incorrect packet metadata");
    tunnel_t *previous = tunnelCreate(NULL, sizeof(affinity_fixture_t *), 0);
    twfRequire(previous != NULL, "could not create opposite-direction observer");
    *(affinity_fixture_t **) tunnelGetState(previous) = &fixture;
    previous->fnPayloadD                              = receivePacket;
    fixture.tunnel->fnPayloadU                        = receivePacket;
    helper->chain                                     = fixture.chain;
    helper->prev                                      = previous;
    helper->next                                      = fixture.tunnel;
    previous->next                                    = helper;
    fixture.tunnel->prev                              = helper;
    if (direction == kFlowAffinityUpstream)
    {
        tunnelUpStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 1));
        tunnelDownStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 2));
    }
    else
    {
        tunnelDownStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 1));
        tunnelUpStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 2));
    }
    twfRequire(fixture.delivered == 1 && fixture.last_wid == 0 && fixture.ids[0] == 2,
               "opposite helper direction did not pass through on its original worker");
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 2 && fixture.last_wid == 2 && fixture.ids[1] == 1,
               "selected helper direction did not establish flow ownership");
    /* A terminal packet neighbor may finish this worker lane while an older
     * payload is queued. Nothing may arrive toward that side afterwards. */
    finishes               = 0;
    previous->fnFinD       = receiveFinish;
    fixture.tunnel->fnFinU = receiveFinish;
    if (direction == kFlowAffinityUpstream)
        tunnelUpStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 3));
    else
        tunnelDownStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 3));
    testWorkerBindWID(2);
    if (direction == kFlowAffinityUpstream)
        tunnelDownStreamFin(helper, fixture.lines[2]);
    else
        tunnelUpStreamFin(helper, fixture.lines[2]);
    twfRequire(finishes == 1, "helper did not forward Finish exactly once");
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 2 && g_twf_buffers.live_count == 0,
               "queued helper payload outlived its worker lane's Finish");
    testWorkerBindWID(0);
    if (direction == kFlowAffinityUpstream)
        tunnelUpStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 4));
    else
        tunnelDownStreamPayload(helper, fixture.lines[0], identifiedPacket(2, 4));
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 2 && g_twf_buffers.live_count == 0, "finished helper lane reopened admission");
    tunnelOwnedChildDestroy(helper);
    tunnelDestroy(previous);
    teardown(&fixture);
}

int main(void)
{
    testCaseSet("packet affinity quiescence during a drain");
    caseQuiesceDuringDrain();
    testCaseSet("packet affinity directional internal tunnel");
    caseDirectionalTunnel(kFlowAffinityUpstream);
    caseDirectionalTunnel(kFlowAffinityDownstream);
    testCaseSet("packet affinity destination FIFO and reentry");
    caseDestinationFIFO();
    testCaseSet("packet affinity bounded storage and fair quanta");
    caseBoundsAndQuantum();
    testCaseSet("packet affinity inherited batch");
    caseInheritedBatch();
    testCaseSet("packet affinity same-worker closed admission");
    caseSameWorkerClosed();
    testCaseSet("packet affinity worker selection");
    caseWorkerSelection();
    testCaseSet("packet affinity fragments");
    caseFragmentFlow();
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        testCaseSet("packet affinity settlement");
        caseSettlement(mode);
    }
    testCaseSet("packet affinity one worker");
    caseSingleWorker();
    testCaseSet("packet affinity independent intent and nested delivery");
    caseIndependentPackets(false);
    caseIndependentPackets(true);
    return 0;
}
