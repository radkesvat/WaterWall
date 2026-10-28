/*
 * Shared receive regressions for the two TcpOverUdp line-failure fixtures.
 * Real KCP input covers incomplete messages, exact-capacity/oversized assembly,
 * missing/unknown flags, control frames, and input nested in a close-frame flush.
 * The including fixture tracks buffers, timers, KCP/FEC handles and line references.
 * CTest: waterwall.tcpoverudp{client,server}_line_failure_test_unit.
 */
#pragma once

#if TEST_RECEIVE_SERVER
typedef tcpoverudpserver_lstate_t receive_state_t;
#define receiveDestroy tcpoverudpserverLinestateDestroy
#define receiveFinish  tcpoverudpserverTunnelDownStreamFinish
#else
typedef tcpoverudpclient_lstate_t receive_state_t;
#define receiveDestroy tcpoverudpclientLinestateDestroy
#define receiveFinish  tcpoverudpclientTunnelUpStreamFinish
#endif

enum
{
    kReceiveOversized,
    kReceiveUnknown,
    kReceiveMissingFlag,
    kReceiveExactCapacity,
    kReceiveControls,
    kReceiveClose,
    kReceiveCaseCount
};

static tcpoverudp_fixture_t *g_receive_fixture;
static unsigned              g_receive_case;
static uint32_t              g_receive_bytes, g_receive_payloads, g_receive_sequence;
static bool                  g_receive_closing, g_receive_injected;

static void receiveFeed(line_t *line, sbuf_t *packet)
{
#if TEST_RECEIVE_SERVER
    tunnelNextUpStreamPayload(g_receive_fixture->prev, line, packet);
#else
    tunnelPrevDownStreamPayload(g_receive_fixture->next, line, packet);
#endif
}

static void receiveAppendPush(sbuf_t *packet, uint32_t sequence, uint8_t fragments, uint32_t length, uint8_t first)
{
    uint32_t offset = sbufGetLength(packet);
    twfRequire(sbufGetTailCapacity(packet) >= 24U + length, "receive packet fixture exceeds its buffer");
    uint8_t *bytes = sbufGetMutablePtr(packet) + offset;
    memoryZero(bytes, 24);
    bytes[4] = 81; // KCP PUSH, conversation 0.
    bytes[5] = fragments;
    bytes[6] = 128;
    for (unsigned i = 0; i < 4; ++i)
    {
        bytes[12 + i] = (uint8_t) (sequence >> (8U * i));
        bytes[20 + i] = (uint8_t) (length >> (8U * i));
    }
    if (length != 0)
    {
        memset(bytes + 24, 0x5A, length);
        bytes[24] = first;
    }
    sbufSetLength(packet, offset + 24U + length);
}

static void receiveSendCase(line_t *line)
{
    buffer_pool_t *pool     = lineGetBufferPool(line);
    sbuf_t        *probe    = bufferpoolGetLargeBuffer(pool);
    const uint32_t capacity = sbufGetMaximumWriteableSize(probe);
    lineReuseBuffer(line, probe);
    const bool large     = g_receive_case == kReceiveOversized || g_receive_case == kReceiveExactCapacity;
    uint32_t   remaining = large ? capacity + (g_receive_case == kReceiveOversized) : 1U;
    if (g_receive_case == kReceiveMissingFlag)
        remaining = 0;
    uint32_t fragment = 0;
    do
    {
        const uint32_t length = min(remaining, 60000U);
        sbuf_t        *packet = bufferpoolGetLargeBuffer(pool);
        sbufSetLength(packet, 0);
        uint8_t first = fragment != 0 ? 0x5A : kFrameFlagData;
        if (g_receive_case == kReceiveUnknown)
            first = 0x7F;
        else if (g_receive_case == kReceiveClose)
            first = kFrameFlagClose;
        receiveAppendPush(
            packet, g_receive_sequence++, (uint8_t) ((remaining - length + 59999U) / 60000U), length, first);
        remaining -= length;
        if (remaining == 0)
        {
            if (g_receive_case == kReceiveControls)
                receiveAppendPush(packet, g_receive_sequence++, 0, 1, kFrameFlagPing);
            // A complete DATA message behind the tested head must not get stranded or escape rejection.
            receiveAppendPush(packet, g_receive_sequence++, 0, 2, kFrameFlagData);
        }
        receiveFeed(line, packet);
        if (remaining != 0)
        {
            twfRequire(lineIsAlive(line), "incomplete KCP message closed the line");
            twfRequireEqualU32(g_receive_payloads, 0, "incomplete KCP message was delivered");
            twfRequireEqualU32(g_receive_fixture->trace.next_finish + g_receive_fixture->trace.prev_finish,
                               0,
                               "incomplete KCP message emitted Finish");
        }
        ++fragment;
    } while (remaining != 0);
}

static void receiveWireOutput(tunnel_t *t, line_t *line, sbuf_t *packet)
{
    discard t;
    lineReuseBuffer(line, packet);
    if (g_receive_closing && ! g_receive_injected)
    {
        g_receive_injected = true;
        receiveSendCase(line);
        receive_state_t *ls = lineGetState(line, g_receive_fixture->kcp);
        twfRequire(lineIsAlive(line) && ls->k_handle != NULL, "nested receive retired an active close flush");
        twfRequireEqualU32(g_receive_fixture->trace.next_finish + g_receive_fixture->trace.prev_finish,
                           0,
                           "nested receive reflected Finish during a close flush");
    }
}

static void receiveDecoded(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    discard t;
    twfRequire(! g_receive_closing, "close flush delivered application bytes");
    const uint8_t *bytes = sbufGetRawPtr(payload);
    for (uint32_t i = 0; i < sbufGetLength(payload); ++i)
        twfRequire(bytes[i] == 0x5A, "KCP receive changed application bytes");
    g_receive_bytes += sbufGetLength(payload);
    ++g_receive_payloads;
    lineReuseBuffer(line, payload);
}

static void receiveNextFinish(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequireLineStateZeroed(line, g_receive_fixture->kcp, "Finish preceded KCP cleanup");
    ++g_receive_fixture->trace.next_finish;
}

static void receiveOwnerFinish(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequireLineStateZeroed(line, g_receive_fixture->kcp, "owner Finish preceded KCP cleanup");
    twfRequireEqualU32(g_receive_fixture->trace.next_finish,
                       g_receive_closing ? 0 : 1,
                       "malformed receive closed the owner before the borrowed next side");
    ++g_receive_fixture->trace.prev_finish;
    lineDestroy(line);
}

static void caseReceiveMessages(void)
{
    for (unsigned closing = 0; closing < 2; ++closing)
        for (unsigned kind = 0; kind < (closing ? kReceiveExactCapacity : kReceiveCaseCount); ++kind)
        {
            char label[96];
            snprintf(label, sizeof(label), "TcpOverUdp receive case %u, nested close=%u", kind, closing);
            twfSetCase(label);
            tcpoverudp_fixture_t fixture;
            fixtureSetup(&fixture, false);
#if TEST_RECEIVE_SERVER
            master_pool_t  *context_master = masterpoolCreateWithCapacity(8);
            generic_pool_t *contexts =
                genericpoolCreateWithDefaultAllocatorAndCapacity(context_master, sizeof(context_t), 8);
            GSTATE.shortcut_context_pools = &contexts;
#endif
            twf_line_pool_t line_pool;
            twfLinePoolSetup(&line_pool, fixture.kcp->lstate_size, 1);
            line_t *line = twfLinePoolCreateLine(&line_pool);
            lineRef(line); // Inspect state even when the owner closes synchronously.
            tunnelNextUpStreamInit(fixture.prev, line);
            g_receive_fixture  = &fixture;
            g_receive_case     = kind;
            g_receive_closing  = closing != 0;
            g_receive_injected = false;
            g_receive_bytes = g_receive_payloads = g_receive_sequence = 0;
            fixture.prev->fnFinD                                      = receiveOwnerFinish;
            fixture.next->fnFinU                                      = receiveNextFinish;
            fixture.prev->fnPayloadD = TEST_RECEIVE_SERVER ? receiveWireOutput : receiveDecoded;
            fixture.next->fnPayloadU = TEST_RECEIVE_SERVER ? receiveDecoded : receiveWireOutput;
            if (closing)
            {
                receiveFinish(fixture.kcp, line);
                twfRequire(g_receive_injected, "close flush did not exercise nested receive");
                twfRequireEqualU32(
                    fixture.trace.next_finish, TEST_RECEIVE_SERVER ? 0 : 1, "close forwarded wrong Finish");
                twfRequireEqualU32(fixture.trace.prev_finish, TEST_RECEIVE_SERVER ? 1 : 0, "close reflected Finish");
                if (lineIsAlive(line))
                    lineDestroy(line);
            }
            else
            {
                receiveSendCase(line);
                const bool accepted = kind == kReceiveExactCapacity || kind == kReceiveControls;
                if (accepted)
                {
                    twfRequire(lineIsAlive(line), "valid receive closed the line");
                    twfRequireEqualU32(
                        g_receive_payloads, kind == kReceiveExactCapacity ? 2 : 1, "valid receive stalled");
                    twfRequireEqualU32(g_receive_bytes,
                                       kind == kReceiveExactCapacity ? kTestLargeBufferSize : 1,
                                       "valid receive lost bytes at its capacity boundary");
                    receiveDestroy(lineGetState(line, fixture.kcp));
                    lineDestroy(line);
                }
                else
                {
                    twfRequire(! lineIsAlive(line), "invalid/close KCP message left the line stalled");
                    twfRequireEqualU32(fixture.trace.next_finish, 1, "next side did not close exactly once");
                    twfRequireEqualU32(fixture.trace.prev_finish, 1, "owner did not close exactly once");
                    twfRequireEqualU32(g_receive_payloads, 0, "data behind invalid/close message escaped");
                }
            }
            twfRequireLineStateZeroed(line, fixture.kcp, "receive cleanup left nonzero state");
            twfRequireEqualU32(twfLineRefCount(line), 1, "receive leaked a line reference");
            lineUnref(line);
            requireNoLiveKcpResources();
            twfRequireNoLeakedBuffers();
            twfLinePoolTeardown(&line_pool);
#if TEST_RECEIVE_SERVER
            GSTATE.shortcut_context_pools = NULL;
            genericpoolDestroy(contexts);
            masterpoolMakeEmpty(context_master);
            masterpoolDestroy(context_master);
#endif
            twfWorkerEnvTeardown(&fixture.env);
            fixtureTeardown(&fixture);
            g_receive_fixture = NULL;
        }
}

#undef receiveDestroy
#undef receiveFinish
#undef TEST_RECEIVE_SERVER
