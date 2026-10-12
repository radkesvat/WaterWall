/*
 * Covers: permanent per-line tunnel bypass across all flow events and both directions.
 * Setup: A 64-tunnel chain with shuffled link order, real line pools, and one bound
 * logical worker. The fixture owns normal lines; the chain owns its packet line.
 * Checks: default/explicit/context dispatch, consecutive skips including bits 0/63,
 * line isolation and reuse, reentrant disable, repeatable Est and advisory Pause/Resume, Finish destruction, packet
 * publication and the certified packet enqueue boundary. Nonempty line state must be zero, including padding, before
 * bypass; Debug rejects dirty state. No network or concurrency claim. CTest: waterwall.tunnel_bypass_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#if defined(OS_LINUX) && defined(DEBUG)
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kInit,
    kEst,
    kFin,
    kPause,
    kResume,
    kPayload
};

static tunnel_t *expected_tunnel;
static line_t   *expected_line;
static sbuf_t   *expected_payload;
static unsigned  expected_event;
static bool      expected_upstream;
static unsigned  deliveries;

static void record(tunnel_t *t, line_t *line, unsigned event, bool upstream)
{
    require(t == expected_tunnel, "dispatch reached the wrong tunnel");
    require(line == expected_line, "dispatch changed the line");
    require(event == expected_event && upstream == expected_upstream, "dispatch changed the event or direction");
    require(++deliveries == 1, "event was delivered more than once");
}

#define RECORD_EVENT(name, event, upstream)                                                                            \
    static void name(tunnel_t *t, line_t *line)                                                                        \
    {                                                                                                                  \
        record(t, line, event, upstream);                                                                              \
    }

RECORD_EVENT(recordInitU, kInit, true)
RECORD_EVENT(recordInitD, kInit, false)
RECORD_EVENT(recordEstU, kEst, true)
RECORD_EVENT(recordEstD, kEst, false)
RECORD_EVENT(recordFinU, kFin, true)
RECORD_EVENT(recordFinD, kFin, false)
RECORD_EVENT(recordPauseU, kPause, true)
RECORD_EVENT(recordPauseD, kPause, false)
RECORD_EVENT(recordResumeU, kResume, true)
RECORD_EVENT(recordResumeD, kResume, false)

static void recordPayload(tunnel_t *t, line_t *line, sbuf_t *buf, bool upstream)
{
    record(t, line, kPayload, upstream);
    require(buf == expected_payload && sbufGetLength(buf) == 1 && ((const uint8_t *) sbufGetRawPtr(buf))[0] == 0xA5,
            "dispatch changed the payload identity or contents");
    sbufDestroy(buf);
}

static void recordPayloadU(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    recordPayload(t, line, buf, true);
}

static void recordPayloadD(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    recordPayload(t, line, buf, false);
}

static void installRecorders(tunnel_t *t)
{
    t->fnInitU    = recordInitU;
    t->fnInitD    = recordInitD;
    t->fnEstU     = recordEstU;
    t->fnEstD     = recordEstD;
    t->fnFinU     = recordFinU;
    t->fnFinD     = recordFinD;
    t->fnPauseU   = recordPauseU;
    t->fnPauseD   = recordPauseD;
    t->fnResumeU  = recordResumeU;
    t->fnResumeD  = recordResumeD;
    t->fnPayloadU = recordPayloadU;
    t->fnPayloadD = recordPayloadD;
}

static sbuf_t *makePayload(void)
{
    sbuf_t *buf = sbufCreate(1);
    sbufSetLength(buf, 1);
    sbufGetMutablePtr(buf)[0] = 0xA5;
    expected_payload          = buf;
    return buf;
}

static void testDispatch(line_t *line, tunnel_t **path, unsigned disabled)
{
    const struct
    {
        TunnelFlowRoutineInit direct[2];
        TunnelFlowRoutineInit neighbor[2];
        TunnelFlowRoutineInit defaults[2];
    } events[] = {
        {{tunnelDownStreamInit, tunnelUpStreamInit},
         {tunnelPrevDownStreamInit, tunnelNextUpStreamInit},
         {NULL, tunnelDefaultUpStreamInit}},
        {{tunnelDownStreamEst, tunnelUpStreamEst},
         {tunnelPrevDownStreamEst, tunnelNextUpStreamEst},
         {tunnelDefaultDownStreamEst, NULL}},
        {{tunnelDownStreamFin, tunnelUpStreamFin},
         {tunnelPrevDownStreamFinish, tunnelNextUpStreamFinish},
         {tunnelDefaultDownStreamFinish, tunnelDefaultUpStreamFin}},
        {{tunnelDownStreamPause, tunnelUpStreamPause},
         {tunnelPrevDownStreamPause, tunnelNextUpStreamPause},
         {tunnelDefaultDownStreamPause, tunnelDefaultUpStreamPause}},
        {{tunnelDownStreamResume, tunnelUpStreamResume},
         {tunnelPrevDownStreamResume, tunnelNextUpStreamResume},
         {tunnelDefaultDownStreamResume, tunnelDefaultUpStreamResume}},
    };
    expected_line = line;
    for (unsigned up = 0; up < 2; ++up)
    {
        tunnel_t *sender  = path[up ? 0 : 3];
        tunnel_t *initial = path[up ? 1 : 2];
        expected_tunnel   = up ? path[disabled + 1] : path[disabled == 2 ? 0 : 2];
        expected_upstream = up != 0;
        for (unsigned event = 0; event <= kPayload; ++event)
        {
            expected_event = event;
            for (unsigned mode = 0; mode < 4; ++mode)
            {
                deliveries = 0;
                if (event == kPayload)
                {
                    sbuf_t *buf = makePayload();
                    if (mode == 0)
                        (up ? tunnelUpStreamPayload : tunnelDownStreamPayload)(initial, line, buf);
                    else if (mode == 1)
                        (up ? tunnelNextUpStreamPayload : tunnelPrevDownStreamPayload)(sender, line, buf);
                    else if (mode == 2)
                        (up ? tunnelDefaultUpStreamPayload : tunnelDefaultDownStreamPayload)(sender, line, buf);
                    else
                    {
                        context_t context = {.line = line, .payload = buf};
                        (up ? contextApplyOnTunnelU : contextApplyOnTunnelD)(&context, initial);
                        require(context.payload == NULL, "context retained transferred payload ownership");
                    }
                }
                else if (mode == 0)
                    events[event].direct[up](initial, line);
                else if (mode == 1)
                    events[event].neighbor[up](sender, line);
                else if (mode == 2)
                {
                    if (events[event].defaults[up] == NULL)
                        continue; // These two stream defaults intentionally reject the callback.
                    events[event].defaults[up](sender, line);
                }
                else
                {
                    context_t context = {.line   = line,
                                         .init   = event == kInit,
                                         .est    = event == kEst,
                                         .fin    = event == kFin,
                                         .pause  = event == kPause,
                                         .resume = event == kResume};
                    (up ? contextApplyOnTunnelU : contextApplyOnTunnelD)(&context, initial);
                }
                require(deliveries == 1, "event was not delivered");
            }
        }
    }
}

static void bypassDuringInit(tunnel_t *t, line_t *line)
{
    tunnelBypassLine(t, line);
    tunnelNextUpStreamInit(t, line);
}

static void establishDuringInit(tunnel_t *t, line_t *line)
{
    tunnelPrevDownStreamEst(t, line);
}

static void destroyOnFinish(tunnel_t *t, line_t *line)
{
    record(t, line, kFin, false);
    lineDestroy(line); // This callback represents the fixture's normal-line owner.
}

static void markEstablished(tunnel_t *t, line_t *line)
{
    record(t, line, kEst, false);
    lineMarkEstablished(line);
}

static void testRepeatedEst(tunnel_chain_t *chain, tunnel_t **path)
{
    line_t *line = lineCreate(chain->line_pools, 0);
    require(! lineIsEstablished(line), "new line was already established");
    path[0]->fnEstD   = markEstablished; // Model a listener consuming transport notifications.
    path[1]->fnEstD   = tunnelDefaultDownStreamEst;
    expected_tunnel   = path[0];
    expected_line     = line;
    expected_event    = kEst;
    expected_upstream = false;

    for (unsigned notification = 0; notification < 3; ++notification)
    {
        if (notification == 2)
            tunnelBypassLine(path[1], line);
        deliveries = 0;
        tunnelPrevDownStreamEst(path[2], line);
        require(deliveries == 1 && lineIsEstablished(line), "repeated Est was lost or changed establishment");
    }

    lineDestroy(line);
    installRecorders(path[0]);
    installRecorders(path[1]);
}

static void testAdvisoryPauseResume(tunnel_chain_t *chain, tunnel_t **path)
{
    line_t *line = lineCreate(chain->line_pools, 0);
    for (unsigned i = 1; i <= 2; ++i)
    {
        path[i]->fnPauseU   = tunnelDefaultUpStreamPause;
        path[i]->fnPauseD   = tunnelDefaultDownStreamPause;
        path[i]->fnResumeU  = tunnelDefaultUpStreamResume;
        path[i]->fnResumeD  = tunnelDefaultDownStreamResume;
        path[i]->fnPayloadU = tunnelDefaultUpStreamPayload;
        path[i]->fnPayloadD = tunnelDefaultDownStreamPayload;
    }

    // Resume need not follow Pause, repeats reach the receiver, and Pause is no payload gate.
    const unsigned events[] = {kResume, kResume, kPause, kPause, kPayload, kResume, kResume, kPayload};
    expected_line           = line;
    for (unsigned up = 0; up < 2; ++up)
    {
        for (unsigned i = 0; i < ARRAY_SIZE(events); ++i)
        {
            expected_event = events[i];
            // Pressure runs opposite to the payload it asks the source to stop producing.
            expected_upstream = events[i] == kPayload ? up == 0 : up != 0;
            expected_tunnel   = path[expected_upstream ? 3 : 0];
            tunnel_t *sender  = path[expected_upstream ? 0 : 3];
            deliveries        = 0;
            if (events[i] == kPayload)
                (expected_upstream ? tunnelNextUpStreamPayload
                                   : tunnelPrevDownStreamPayload)(sender, line, makePayload());
            else if (events[i] == kPause)
                (up ? tunnelNextUpStreamPause : tunnelPrevDownStreamPause)(sender, line);
            else
                (up ? tunnelNextUpStreamResume : tunnelPrevDownStreamResume)(sender, line);
            require(deliveries == 1, "transparent defaults lost an advisory signal or payload");
        }
    }

    require(line->active_tunnels_mask == UINT64_MAX, "transparent notification forwarding bypassed an active tunnel");
    lineDestroy(line);
    installRecorders(path[1]);
    installRecorders(path[2]);
}

static void testBypassRequiresDestroyedState(tunnel_chain_t *chain, tunnel_t *t)
{
    line_t  *line  = lineCreate(chain->line_pools, 0);
    uint8_t *state = lineGetState(line, t);
    require(t->lstate_offset != 0 && t->lstate_size == 64, "fixture must exercise an offset and aligned padding");

#if defined(OS_LINUX) && defined(DEBUG)
    const uint32_t dirty_bytes[] = {0, t->lstate_size - 1};
    for (size_t i = 0; i < ARRAY_SIZE(dirty_bytes); ++i)
    {
        state[dirty_bytes[i]] = 0xA5;
        pid_t child           = fork();
        require(child >= 0, "failed to fork dirty line-state case");
        if (child == 0)
        {
            const struct rlimit no_core = {0, 0};
            require(setrlimit(RLIMIT_CORE, &no_core) == 0, "failed to disable core dumps for expected assertion");
            tunnelBypassLine(t, line);
            _Exit(0);
        }
        int status;
        require(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
                "bypass accepted nonzero line state or padding");
        state[dirty_bytes[i]] = 0;
    }
#endif

    // This fixture's line state contains only inline bytes, so its destruction is zeroing the full slot.
    memorySet(state, 0xA5, t->lstate_size);
    memoryZeroAligned32(state, t->lstate_size);
    tunnelBypassLine(t, line);
    require(! tunnelIsActiveForLine(t, line), "destroyed line state could not be bypassed");
    lineDestroy(line);
}

static void testPacketDispatch(tunnel_chain_t *chain, tunnel_t **path)
{
    line_t *packet    = tunnelchainGetWorkerPacketLine(chain, 0);
    node_t  sink_node = {
         .type = (char *) "TestSink", .layer_group = kNodeLayer3, .flags = kNodeFlagPacketPayloadEnqueueOnly};
    node_t *original_node = path[2]->node;
    path[2]->node         = &sink_node;
    require(packettunnelCanEnqueueDownstreamInline(path[3], packet), "active certified sink was not eligible");
    tunnelBypassLine(path[2], packet);
    tunnelBypassLine(path[1], packet);
    require(! packettunnelCanEnqueueDownstreamInline(path[3], packet), "bypassed sink retained inline certification");
    path[2]->node = original_node;

    for (unsigned up = 0; up < 2; ++up)
    {
        tunnel_t *anchor = path[up ? 0 : 3];
        require(packettunnelConfigureLifecycleAnchor(anchor,
                                                     "test",
                                                     recordPayloadU,
                                                     up ? kPacketLifecycleAnchorPublishUpstream
                                                        : kPacketLifecycleAnchorPublishDownstream),
                "failed to configure packet publication");
        require(packettunnelLifecycleAnchorBind(anchor), "failed to bind packet publication");
        expected_tunnel   = path[up ? 3 : 0];
        expected_line     = packet;
        expected_event    = kPayload;
        expected_upstream = up != 0;
        deliveries        = 0;
        packettunnelLifecycleAnchorPublish(anchor, packet, makePayload());
        require(deliveries == 1 && lineIsAlive(packet), "packet publication failed or destroyed the packet line");
        installRecorders(anchor);
    }
}

int main(void)
{
    testCaseSet("tunnel_bypass_test");
    worker_t worker         = {.wid = 0, .has_event_loop = true};
    GSTATE.workers          = &worker;
    GSTATE.workers_count    = 1;
    GSTATE.flag_initialized = true;
    workerBindCurrentThread(&worker);

    node_t          node  = {.type = (char *) "TestTunnel"};
    tunnel_chain_t *chain = tunnelchainCreate(1);
    tunnel_t       *tunnels[kMaxChainLen];
    tunnel_t       *path[kMaxChainLen];
    uint32_t        offset = 0;
    for (uint16_t i = 0; i < kMaxChainLen; ++i)
    {
        const uint32_t lstate_size = i == 0 ? 1 : i == 63 ? 33 : 0;
        tunnels[i]                 = tunnelCreate(&node, sizeof(packet_lifecycle_anchor_t), lstate_size);
        require(tunnels[i] != NULL, "failed to create tunnel");
        tunnelchainInsert(chain, tunnels[i]);
        tunnels[i]->onIndex(tunnels[i], i, &offset);
        installRecorders(tunnels[i]);
    }
    path[0]       = tunnels[7];
    path[1]       = tunnels[63];
    path[2]       = tunnels[0];
    unsigned slot = 3;
    for (unsigned i = 1; i < 63; ++i)
        if (i != 7)
            path[slot++] = tunnels[i];
    require(slot == kMaxChainLen, "invalid shuffled path");
    for (unsigned i = 1; i < kMaxChainLen; ++i)
        tunnelBind(path[i - 1], path[i]);
    chain->contains_packet_node = true;
    chain->masterpool_line_pool = masterpoolCreateWithCapacity(4);
    uint32_t line_item_size;
    require(tunnelchainTryComputeLineItemSize(chain->sum_line_state_size, &line_item_size),
            "failed to compute line pool item size");
    chain->line_pools[0] =
        genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(chain->masterpool_line_pool, line_item_size, 4);
    require(chain->line_pools[0] != NULL, "failed to create line pool");
    chain->packet_lines    = memoryAllocate(sizeof(*chain->packet_lines));
    chain->packet_lines[0] = lineCreate(chain->line_pools, 0);

    testBypassRequiresDestroyedState(chain, path[1]);
    testRepeatedEst(chain, path);
    testAdvisoryPauseResume(chain, path);

    line_t *line  = lineCreate(chain->line_pools, 0);
    line_t *other = lineCreate(chain->line_pools, 0);
    require(line->active_tunnels_mask == UINT64_MAX, "new line did not enable every tunnel");
    testDispatch(line, path, 0);
    tunnelBypassLine(path[1], line);
    require(line->active_tunnels_mask == (UINT64_MAX & ~(UINT64_C(1) << 63)), "wrong bit cleared for index 63");
    testDispatch(line, path, 1);
    tunnelBypassLine(path[2], line);
    tunnelBypassLine(path[2], line);
    require(! tunnelIsActiveForLine(path[1], line) && ! tunnelIsActiveForLine(path[2], line),
            "bypass was not permanent/idempotent");
    testDispatch(line, path, 2);
    require(other->active_tunnels_mask == UINT64_MAX, "bypass affected another line");
    testDispatch(other, path, 0);
    line_t *retired = line;
    lineDestroy(line);
    line = lineCreate(chain->line_pools, 0);
#if BYPASS_GENERIC_POOL != 1
    require(line == retired, "fixture did not exercise pooled line reuse");
#endif
    discard retired;
    require(line->active_tunnels_mask == UINT64_MAX, "pooled line retained disabled tunnels");

    path[1]->fnInitU  = bypassDuringInit;
    path[2]->fnInitU  = establishDuringInit;
    expected_tunnel   = path[0];
    expected_line     = line;
    expected_event    = kEst;
    expected_upstream = false;
    deliveries        = 0;
    tunnelNextUpStreamInit(path[0], line);
    require(deliveries == 1, "reentrant callback did not observe bypass from Init");
    installRecorders(path[1]);
    installRecorders(path[2]);

    for (unsigned i = 1; i + 1 < kMaxChainLen; ++i)
        tunnelBypassLine(path[i], line);
    expected_tunnel   = path[kMaxChainLen - 1];
    expected_event    = kPayload;
    expected_upstream = true;
    deliveries        = 0;
    tunnelNextUpStreamPayload(path[0], line, makePayload());
    require(deliveries == 1, "long bypass run lost the payload");

    path[0]->fnFinD   = destroyOnFinish;
    expected_tunnel   = path[0];
    expected_event    = kFin;
    expected_upstream = false;
    deliveries        = 0;
    lineRef(line);
    tunnelPrevDownStreamFinish(path[kMaxChainLen - 1], line);
    require(deliveries == 1 && ! lineIsAlive(line), "Finish did not reach and destroy the owned normal line");
    lineUnref(line);
    installRecorders(path[0]);
    lineDestroy(other);

    testPacketDispatch(chain, path);
    tunnelchainDestroy(chain);
    for (unsigned i = 0; i < kMaxChainLen; ++i)
        tunnelDestroy(tunnels[i]);
    workerUnbindCurrentThread();
    GSTATE = (ww_global_state_t) {0};
    return 0;
}
