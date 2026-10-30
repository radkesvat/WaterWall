/*
 * Covers: consumer-owned IpManipulator packet affinity in both directions.
 * Setup: Real transforms, conditional stateful packet-affinity continuations;
 * deterministic worker-message delivery over four real worker packet lines.
 * Cases: Stateful TCP/UDP tuple selection and restored ghost ports, native
 * stateful input, stateless relay, same/single-worker paths, local ProtoSwap
 * encoding/restoration, fragment preservation, and stateful cancellation.
 * Limits: Does not measure kernel capture distribution or TCP throughput.
 * CTest: waterwall.ipmanipulator_affinity_unit
 */
#include "IpManipulator/structure.h"
#include "devices/device_flow_affinity.h"
#include "fixtures/failure/buffer_disposal_probe.h"
#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"
#include "tricks/portghost/trick.h"
#include "tricks/protoswap/trick.h"
#include "wloop_internal.h"
#include "worker_messages.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kWorkers    = 4,
    kMessages   = 256,
    kCaptures   = 16,
    kPacketSize = 64
};

typedef struct message_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *args[3];
    bool                         settled;
} message_t;

typedef struct capture_s
{
    wid_t    wid;
    bool     upstream;
    bool     checksum_requested;
    uint32_t length;
    uint8_t  bytes[256];
} capture_t;

typedef struct fixture_s
{
    test_worker_registry_t     registry;
    master_pool_t             *large;
    master_pool_t             *medium;
    master_pool_t             *small;
    master_pool_t             *wios;
    buffer_pool_t             *pools[kWorkers];
    threadsafe_generic_pool_t *wio_pools[kWorkers];
    wloop_t                   *loops[kWorkers];
    tunnel_chain_t            *chain;
    tunnel_t                  *tunnel;
    tunnel_t                  *next;
    tunnel_t                  *prev;
    node_t                     node;
    cJSON                     *settings;
    message_t                  messages[kMessages];
    unsigned                   message_count;
    capture_t                  captures[kCaptures];
    unsigned                   capture_count;
    unsigned                   stateful_calls;
    wid_t                      stateful_wid;
    bool                       reject;
} fixture_t;

static fixture_t fixture;

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3);
bool                           __wrap_firstsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
bool __wrap_smugglefintrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *arg1, void *arg2, void *arg3)
{
    require(wid < getWorkersCount() && callback != NULL && cleanup != NULL, "handoff lacks owner or cleanup");
    if (fixture.reject)
    {
        cleanup(arg1, arg2, arg3, kWorkerMessageCancelAdmissionClosed);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    require(fixture.message_count < kMessages, "message fixture overflow");
    fixture.messages[fixture.message_count++] =
        (message_t) {.wid = wid, .callback = callback, .cleanup = cleanup, .args = {arg1, arg2, arg3}};
    return kWorkerMessageSubmitAccepted;
}

static bool observeStatefulPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    require(lineIsOnCurrentWorker(l) && GET_BE16((const uint8_t *) sbufGetRawPtr(buf) + 20) == 12345,
            "stateful continuation ran before tuple restoration");
    ++fixture.stateful_calls;
    fixture.stateful_wid = lineGetWID(l);
    return false;
}

bool __wrap_firstsnitrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    return observeStatefulPayload(t, l, buf);
}

bool __wrap_smugglefintrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    return observeStatefulPayload(t, l, buf);
}

static line_t *packetLine(wid_t wid)
{
    return tunnelchainGetWorkerPacketLine(fixture.chain, wid);
}

static void capturePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    require(t == fixture.next || t == fixture.prev, "continuation forwarded to the wrong neighbour");
    require(lineIsOnCurrentWorker(l) && l == packetLine(lineGetWID(l)), "handoff reused a foreign packet line");
    require(fixture.capture_count < kCaptures && sbufGetLength(buf) <= sizeof(fixture.captures[0].bytes),
            "capture fixture overflow");
    capture_t *capture = &fixture.captures[fixture.capture_count++];
    *capture           = (capture_t) {.wid                = lineGetWID(l),
                                      .upstream           = t == fixture.next,
                                      .checksum_requested = packettunnelTakeChecksumRequest(buf),
                                      .length             = sbufGetLength(buf)};
    memoryCopy(capture->bytes, sbufGetRawPtr(buf), capture->length);
    lineReuseBuffer(l, buf);
}

static void invokeMessage(void *context)
{
    message_t *message = context;
    message->callback(getCurrentWorker(), message->args[0], message->args[1], message->args[2]);
}

static void runMessages(void)
{
    for (unsigned i = 0; i < fixture.message_count; ++i)
    {
        message_t *message = &fixture.messages[i];
        if (message->settled)
            continue;
        message->settled = true;
        testWorkerBindWID(message->wid);
        require(wloopInvokeNormalCallback(fixture.loops[message->wid], invokeMessage, message),
                "worker refused admitted handoff callback");
    }
    testWorkerBindWID(0);
}

static void cancelMessages(void)
{
    testWorkerUnbindWID();
    for (unsigned i = 0; i < fixture.message_count; ++i)
    {
        message_t *message = &fixture.messages[i];
        if (message->settled)
            continue;
        message->settled = true;
        message->cleanup(message->args[0], message->args[1], message->args[2], kWorkerMessageCancelQuiesced);
    }
    testWorkerBindWID(0);
}

static void fixtureSetupConfigured(wid_t workers, const char *settings)
{
    static char node_name[] = "affinity-test";
    memoryZero(&fixture, sizeof(fixture));
    fixture.large                         = masterpoolCreateWithCapacity(16);
    fixture.medium                        = masterpoolCreateWithCapacity(16);
    fixture.small                         = masterpoolCreateWithCapacity(16);
    fixture.wios                          = masterpoolCreateWithCapacity(16);
    GSTATE.masterpool_buffer_pools_large  = fixture.large;
    GSTATE.masterpool_buffer_pools_medium = fixture.medium;
    GSTATE.masterpool_buffer_pools_small  = fixture.small;
    GSTATE.workers_count                  = workers;
    GSTATE.ram_profile                    = 1;
    testWorkerRegistryInstall(&fixture.registry);
    GSTATE.shortcut_buffer_pools = fixture.pools;
    GSTATE.shortcut_wios_pools   = fixture.wio_pools;
    GSTATE.shortcut_loops        = fixture.loops;
    for (wid_t wid = 0; wid < workers; ++wid)
    {
        testWorkerBindWID(wid);
        fixture.pools[wid] = bufferpoolCreate(
            fixture.large, fixture.medium, fixture.small, 16, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 4096, 8192, 8192);
        fixture.loops[wid] = wloopCreate(WLOOP_FLAG_RUN_ONCE, fixture.pools[wid], wid);
        require(fixture.loops[wid] != NULL, "worker loop creation failed");
        fixture.wio_pools[wid] =
            threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(fixture.wios, sizeof(wio_t), 8);
        GSTATE.workers[wid].buffer_pool = fixture.pools[wid];
        GSTATE.workers[wid].loop        = fixture.loops[wid];
        GSTATE.workers[wid].wios_pool   = fixture.wio_pools[wid];
    }
    testWorkerBindWID(0);
    fixture.chain                       = tunnelchainCreate(workers);
    fixture.chain->contains_packet_node = true;
    tunnelchainFinalize(fixture.chain);
    require(fixture.chain->finalized, "packet chain finalization failed");
    fixture.settings = cJSON_Parse(settings);
    fixture.node     = (node_t) {.name = node_name, .node_settings_json = fixture.settings};
    fixture.tunnel   = ipmanipulatorCreate(&fixture.node);
    require(fixture.tunnel != NULL, "IpManipulator creation failed");
    fixture.next = tunnelCreate(NULL, 0, 0);
    fixture.prev = tunnelCreate(NULL, 0, 0);
    require(fixture.next != NULL && fixture.prev != NULL, "neighbour creation failed");
    fixture.next->chain      = fixture.chain;
    fixture.next->fnPayloadU = capturePacket;
    fixture.prev->chain      = fixture.chain;
    fixture.prev->fnPayloadD = capturePacket;
    fixture.tunnel->chain    = fixture.chain;
    fixture.tunnel->next     = fixture.next;
    fixture.tunnel->prev     = fixture.prev;
}

static void fixtureSetup(wid_t workers)
{
    fixtureSetupConfigured(workers, "{\"protoswap-tcp\":143,\"protoswap-udp\":144}");
}

static void fixtureTeardown(void)
{
    cancelMessages();
    ipmanipulatorDestroy(fixture.tunnel, wwLifecycleStartupRollback());
    tunnelDestroy(fixture.next);
    tunnelDestroy(fixture.prev);
    tunnelchainDestroy(fixture.chain);
    cJSON_Delete(fixture.settings);
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        testWorkerBindWID(wid);
        wloopDestroy(&fixture.loops[wid]);
        threadsafegenericpoolDestroy(fixture.wio_pools[wid]);
        bufferpoolDestroy(fixture.pools[wid]);
    }
    testWorkerUnbindWID();
    testWorkerRegistryRestore(&fixture.registry);
    GSTATE.workers_count                  = 0;
    GSTATE.shortcut_buffer_pools          = NULL;
    GSTATE.shortcut_wios_pools            = NULL;
    GSTATE.shortcut_loops                 = NULL;
    GSTATE.masterpool_buffer_pools_large  = NULL;
    GSTATE.masterpool_buffer_pools_medium = NULL;
    GSTATE.masterpool_buffer_pools_small  = NULL;
    master_pool_t *masters[]              = {fixture.large, fixture.medium, fixture.small, fixture.wios};
    for (unsigned i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

static sbuf_t *makePacket(uint8_t protocol, uint16_t source_port, bool reverse)
{
    sbuf_t *buf = sbufCreateWithPadding(256, 64);
    sbufSetLength(buf, kPacketSize);
    uint8_t *bytes = sbufGetMutablePtr(buf);
    memoryZero(bytes, kPacketSize);
    bytes[0] = 0x45;
    PUT_BE16(bytes + 2, kPacketSize);
    PUT_BE16(bytes + 4, source_port);
    bytes[8] = 64;
    bytes[9] = protocol;
    PUT_BE32(bytes + 12, reverse ? 0x0a000002 : 0x0a000001);
    PUT_BE32(bytes + 16, reverse ? 0x0a000001 : 0x0a000002);
    PUT_BE16(bytes + 20, reverse ? 443 : source_port);
    PUT_BE16(bytes + 22, reverse ? source_port : 443);
    if (protocol == IPPROTO_TCP)
    {
        bytes[32] = 0x50;
        bytes[33] = TCP_ACK;
    }
    else
        PUT_BE16(bytes + 24, kPacketSize - 20);
    require(calcFullPacketChecksum(bytes, kPacketSize), "packet checksum construction failed");
    return buf;
}

static wid_t flowWorker(sbuf_t *buf)
{
    wid_t wid;
    require(deviceFlowAffineWID(sbufGetRawPtr(buf), sbufGetLength(buf), &wid), "native tuple has no affinity");
    return wid;
}

static void encodePacket(sbuf_t **buf, wid_t source, bool ghost)
{
    testWorkerBindWID(source);
    line_t *line = packetLine(source);
    if (ghost)
    {
        require(portghosttrickApply(fixture.tunnel, line, buf), "portghost fixture encoding failed");
        sbufSetRecalculateChecksum(*buf, true);
    }
    require(protoswapApply(fixture.tunnel, line, *buf), "protocol fixture encoding failed");
}

typedef struct submission_s
{
    sbuf_t *buf;
    wid_t   source;
    bool    upstream;
} submission_t;

static void invokeSubmission(void *context)
{
    submission_t *submission = context;
    if (submission->upstream)
        ipmanipulatorUpStreamPayload(fixture.tunnel, packetLine(submission->source), submission->buf);
    else
        ipmanipulatorDownStreamPayload(fixture.tunnel, packetLine(submission->source), submission->buf);
}

static void submit(sbuf_t *buf, wid_t source, bool upstream)
{
    testWorkerBindWID(source);
    submission_t submission = {.buf = buf, .source = source, .upstream = upstream};
    require(wloopInvokeNormalCallback(fixture.loops[source], invokeSubmission, &submission),
            "worker refused packet input callback");
}

static void testPlainDecodedTuplesStayLocal(void)
{
    fixtureSetup(kWorkers);
    ipmanipulator_tstate_t *state = tunnelGetState(fixture.tunnel);
    require(state->upstream_affinity == NULL && state->downstream_affinity == NULL,
            "plain ProtoSwap acquired mandatory flow affinity");
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        for (unsigned transport = 0; transport < 2; ++transport)
        {
            unsigned workers_seen     = 0;
            unsigned foreign_arrivals = 0;
            for (uint16_t port = 10000; port < 10016; ++port)
            {
                const uint8_t protocol = transport ? IPPROTO_UDP : IPPROTO_TCP;
                sbuf_t       *buf      = makePacket(protocol, port, false);
                const wid_t   target   = flowWorker(buf);
                sbuf_t       *reverse  = makePacket(protocol, port, true);
                require(flowWorker(reverse) == target, "endpoint reversal changed decoded flow affinity");
                sbufDestroy(reverse);
                /* Exercise every arrival worker explicitly. A small set of
                 * native tuples need not hash to every worker. */
                const wid_t source = (wid_t) ((port - 10000) % kWorkers);
                foreign_arrivals += source != target;
                uint8_t original[kPacketSize];
                memoryCopy(original, sbufGetRawPtr(buf), sizeof(original));
                encodePacket(&buf, source, false);
                fixture.capture_count = 0;
                submit(buf, source, direction != 0);
                require(fixture.capture_count == 1 && fixture.captures[0].wid == source &&
                            fixture.captures[0].upstream == (direction != 0) && fixture.message_count == 0,
                        "plain decoding changed the arrival worker or forwarding direction");
                require(fixture.captures[0].length == sizeof(original) &&
                            memoryEqual(fixture.captures[0].bytes, original, sizeof(original)),
                        "plain decoding repeated a transform or changed the native packet");
                workers_seen |= 1U << source;
            }
            require(workers_seen == (1U << kWorkers) - 1U && foreign_arrivals != 0,
                    "plain decoding did not exercise every arrival worker and a foreign native owner");
        }
    }
    fixtureTeardown();
}

static void testSameAndSingleWorker(void)
{
    for (unsigned single = 0; single < 2; ++single)
    {
        fixtureSetup(single ? 1 : kWorkers);
        for (unsigned direction = 0; direction < 2; ++direction)
        {
            sbuf_t *buf    = makePacket(IPPROTO_TCP, 12345, false);
            wid_t   source = flowWorker(buf);
            encodePacket(&buf, source, false);
            fixture.capture_count = 0;
            submit(buf, source, direction != 0);
            require(fixture.capture_count == 1 && fixture.captures[0].wid == source && fixture.message_count == 0,
                    "same-worker decode needlessly queued or changed owner");
        }
        fixtureTeardown();
    }
}

static void testMixedChecksumRequests(void)
{
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        fixtureSetup(mode == 0 ? 1 : kWorkers);
        for (unsigned requested = 0; requested < 2; ++requested)
        {
            sbuf_t *buf    = makePacket(IPPROTO_TCP, 12345, false);
            wid_t   target = flowWorker(buf);
            wid_t   source = mode == 2 ? (wid_t) ((target + 1) % kWorkers) : target;
            encodePacket(&buf, source, false);
            sbufSetRecalculateChecksum(buf, requested != 0);
            submit(buf, source, false);
        }
        require(fixture.capture_count == 2 && ! fixture.captures[0].checksum_requested &&
                    fixture.captures[1].checksum_requested && fixture.message_count == 0,
                "decoded mixed packets lost their independent requests");
        fixtureTeardown();
    }
}

static void testRestorationBeforeStatefulWork(void)
{
    for (unsigned protoswap = 0; protoswap < 2; ++protoswap)
    {
        fixtureSetupConfigured(kWorkers,
                               protoswap ? "{\"first-sni\":\"example.test\",\"protoswap-tcp\":143}"
                                         : "{\"first-sni\":\"example.test\"}");
        ipmanipulator_tstate_t *state  = tunnelGetState(fixture.tunnel);
        state->trick_source_port_ghost = true;
        state->trick_dest_port_ghost   = true;
        state->trick_smuggle_fin       = true;
        sbuf_t     *buf                = makePacket(IPPROTO_TCP, 12345, false);
        const wid_t target             = flowWorker(buf);
        const wid_t source             = (wid_t) ((target + 1) % kWorkers);
        if (protoswap)
            encodePacket(&buf, source, true);
        else
        {
            testWorkerBindWID(source);
            require(portghosttrickApply(fixture.tunnel, packetLine(source), &buf), "port ghost encoding failed");
            sbufSetRecalculateChecksum(buf, true);
        }
        submit(buf, source, false);
        require(fixture.stateful_calls == 0, "stateful processing preceded worker handoff");
        runMessages();
        require(fixture.stateful_calls == 1 && fixture.stateful_wid == target,
                "stateful processing used encoded tuple owner");
        require(fixture.capture_count == 1 && fixture.captures[0].length == kPacketSize &&
                    GET_BE16(fixture.captures[0].bytes + 20) == 12345 &&
                    GET_BE16(fixture.captures[0].bytes + 22) == 443 && fixture.captures[0].checksum_requested,
                "restoration repeated or checksum metadata was lost across handoff");
        state->trick_smuggle_fin = false;
        fixtureTeardown();
    }
}

static void testNativeStatefulAffinity(void)
{
    fixtureSetupConfigured(kWorkers, "{\"first-sni\":\"example.test\"}");
    ipmanipulator_tstate_t *state = tunnelGetState(fixture.tunnel);
    require(state->upstream_affinity != NULL && state->downstream_affinity != NULL,
            "native stateful node did not install its own affinity boundaries");
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        /* The downstream wrapper observes the boundary without a FIN exchange. */
        state->trick_smuggle_fin = direction == 0;
        for (unsigned transport = 0; transport < 2; ++transport)
        {
            sbuf_t     *buf    = makePacket(transport ? IPPROTO_UDP : IPPROTO_TCP, 12345, false);
            const wid_t target = flowWorker(buf);
            const wid_t source = (wid_t) ((target + 1) % kWorkers);
            uint8_t     original[kPacketSize];
            memoryCopy(original, sbufGetRawPtr(buf), sizeof(original));
            fixture.capture_count  = 0;
            fixture.stateful_calls = 0;
            submit(buf, source, direction != 0);
            require(fixture.capture_count == 0 && fixture.stateful_calls == 0,
                    "native stateful input ran on the arbitrary receive worker");
            runMessages();
            require(fixture.stateful_calls == 1 && fixture.stateful_wid == target && fixture.capture_count == 1 &&
                        fixture.captures[0].wid == target && fixture.captures[0].upstream == (direction != 0),
                    "native stateful processing missed its flow worker");
            require(fixture.captures[0].length == sizeof(original) &&
                        memoryEqual(fixture.captures[0].bytes, original, sizeof(original)),
                    "native worker handoff transformed the packet");
        }
    }
    state->trick_smuggle_fin = false;
    fixtureTeardown();
}

static void testStatelessAndOpaqueStayLocal(void)
{
    fixtureSetupConfigured(kWorkers, "{\"up-tcp-bit-cwr\":\"toggle\"}");
    ipmanipulator_tstate_t *state = tunnelGetState(fixture.tunnel);
    require(state->upstream_affinity == NULL && state->downstream_affinity == NULL,
            "stateless transform acquired mandatory flow affinity");
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        sbuf_t     *buf       = makePacket(IPPROTO_TCP, 12345, false);
        const wid_t source    = (wid_t) ((flowWorker(buf) + 1) % kWorkers);
        fixture.capture_count = 0;
        submit(buf, source, direction != 0);
        require(fixture.capture_count == 1 && fixture.captures[0].wid == source && fixture.message_count == 0,
                "stateless transform redistributed traffic");
    }
    fixtureTeardown();

    fixtureSetupConfigured(kWorkers, "{\"first-sni\":\"example.test\"}");
    for (wid_t source = 0; source < kWorkers; ++source)
    {
        sbuf_t *buf                             = makePacket(IPPROTO_TCP, 12345, false);
        ((uint8_t *) sbufGetMutablePtr(buf))[9] = 50;
        require(calcIpv4HeaderChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
                "opaque packet checksum construction failed");
        fixture.capture_count = 0;
        submit(buf, source, true);
        require(fixture.capture_count == 1 && fixture.captures[0].wid == source && fixture.message_count == 0,
                "opaque traffic collapsed onto a coarse peer-pair worker");
    }
    fixtureTeardown();
}

static void testEncodingStaysLocal(void)
{
    fixtureSetup(kWorkers);
    ipmanipulator_tstate_t *state         = tunnelGetState(fixture.tunnel);
    const int               mappings[][2] = {{143, 144}, {17, 6}, {6, 17}};
    for (unsigned mapping = 0; mapping < ARRAY_SIZE(mappings); ++mapping)
    {
        state->trick_proto_swap_tcp_number = mappings[mapping][0];
        state->trick_proto_swap_udp_number = mappings[mapping][1];
        for (unsigned direction = 0; direction < 2; ++direction)
        {
            for (unsigned transport = 0; transport < 2; ++transport)
            {
                sbuf_t     *buf       = makePacket(transport ? IPPROTO_UDP : IPPROTO_TCP, 12345, false);
                const wid_t source    = (wid_t) ((flowWorker(buf) + 1) % kWorkers);
                fixture.capture_count = 0;
                submit(buf, source, direction != 0);
                require(fixture.capture_count == 1 && fixture.captures[0].wid == source && fixture.message_count == 0,
                        "protocol encoding redistributed native traffic");
                require(fixture.captures[0].bytes[9] == mappings[mapping][transport], "encoding mapped twice");
            }
        }
    }
    fixtureTeardown();
}

static sbuf_t *fragmentPacket(const sbuf_t *whole, uint16_t offset, uint16_t payload_length, bool more)
{
    sbuf_t *fragment = sbufCreateWithPadding(128, 64);
    sbufSetLength(fragment, 20U + payload_length);
    uint8_t *bytes = sbufGetMutablePtr(fragment);
    memoryCopy(bytes, sbufGetRawPtr(whole), 20);
    memoryCopy(bytes + 20, (const uint8_t *) sbufGetRawPtr(whole) + 20 + offset, payload_length);
    PUT_BE16(bytes + 2, (uint16_t) (20 + payload_length));
    PUT_BE16(bytes + 6, (uint16_t) (offset / 8U | (more ? IP_MF : 0)));
    require(calcIpv4HeaderChecksum(bytes, sbufGetLength(fragment)), "fragment checksum construction failed");
    return fragment;
}

static void testPlainFragmentsStayLocal(void)
{
    fixtureSetup(kWorkers);
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        for (unsigned transport = 0; transport < 2; ++transport)
        {
            sbuf_t *whole = makePacket(
                transport ? IPPROTO_UDP : IPPROTO_TCP, (uint16_t) (14000 + direction * 2 + transport), false);
            const wid_t target = flowWorker(whole);
            const wid_t source = (wid_t) ((target + 1) % kWorkers);
            const wid_t zero_source   = (wid_t) ((source + 1) % kWorkers);
            sbuf_t     *expected_zero = fragmentPacket(whole, 0, 24, true);
            sbuf_t     *expected_tail = fragmentPacket(whole, 24, kPacketSize - 20 - 24, false);
            encodePacket(&whole, source, false);
            sbuf_t *zero = fragmentPacket(whole, 0, 24, true);
            sbuf_t *tail = fragmentPacket(whole, 24, kPacketSize - 20 - 24, false);
            sbufDestroy(whole);
            fixture.capture_count   = 0;
            submit(tail, source, direction != 0);
            require(fixture.capture_count == 1 && fixture.captures[0].wid == source && fixture.message_count == 0,
                    "plain decoding staged or moved a tail without its first fragment");
            submit(zero, zero_source, direction != 0);
            require(fixture.capture_count == 2 && fixture.captures[1].wid == zero_source && fixture.message_count == 0,
                    "plain decoding reassigned a fragment's worker");
            require(
                fixture.captures[0].length == sbufGetLength(expected_tail) &&
                    fixture.captures[1].length == sbufGetLength(expected_zero) &&
                    memoryEqual(
                        fixture.captures[0].bytes, sbufGetRawPtr(expected_tail), sbufGetLength(expected_tail)) &&
                    memoryEqual(fixture.captures[1].bytes, sbufGetRawPtr(expected_zero), sbufGetLength(expected_zero)),
                "plain decoding changed preserved fragment bytes or boundaries");
            sbufDestroy(expected_zero);
            sbufDestroy(expected_tail);
        }
    }
    fixtureTeardown();
}

static void testCancelledHandoff(void)
{
    fixtureSetupConfigured(kWorkers, "{\"first-sni\":\"example.test\"}");
    for (unsigned rejection = 0; rejection < 2; ++rejection)
    {
        sbuf_t     *buf    = makePacket(IPPROTO_TCP, (uint16_t) (16000 + rejection), false);
        const wid_t target = flowWorker(buf);
        const wid_t source = (wid_t) ((target + 1) % kWorkers);
        atomic_uint disposals;
        atomic_init(&disposals, 0);
        watchBufferDisposal(buf, &disposals);
        fixture.reject = rejection != 0;
        submit(buf, source, rejection != 0);
        cancelMessages();
        require(atomicLoadRelaxed(&disposals) == 1 && fixture.capture_count == 0,
                "canceled stateful handoff leaked, duplicated, or delivered its packet");
        require(atomicLoadU32Relaxed(&packetLine(target)->refc) == 1, "handoff leaked a packet-line reference");
    }
    fixture.reject = false;
    fixtureTeardown();
}

int main(void)
{
    testCaseSet("ipmanipulator_affinity_test");
    CORE_DEFAULT_MTU = 1500;
    require(globalstateInitializeSecureRandom(), "secure random initialization failed");
    require(frandGlobalInit(), "random initialization failed");
    frandInit();
    checkSumInit();
    testPlainDecodedTuplesStayLocal();
    testSameAndSingleWorker();
    testMixedChecksumRequests();
    testRestorationBeforeStatefulWork();
    testNativeStatefulAffinity();
    testStatelessAndOpaqueStayLocal();
    testEncodingStaysLocal();
    testPlainFragmentsStayLocal();
    testCancelledHandoff();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
