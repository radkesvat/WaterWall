/*
 * Actual packet/stream bridge callbacks with real worker pools and pooled lines.
 * Covers large admitted batches, incomplete storage, FIFO reentry, nested limits
 * and callback-driven carrier close. Packet lines are released only by the chain.
 * CTest: waterwall.packetstostream_input_unit, waterwall.streamtopackets_input_unit
 */
#ifdef TEST_PACKETS_TO_STREAM
#include "PacketsToStream/structure.h"
typedef packetstostream_tstate_t bridge_tstate_t;
typedef packetstostream_lstate_t bridge_lstate_t;
#else
#include "StreamToPackets/structure.h"
typedef streamtopackets_tstate_t bridge_tstate_t;
typedef streamtopackets_lstate_t bridge_lstate_t;
#endif

#include "fixtures/failure/tunnel_line_failure_harness.h"

enum
{
    kPacketBytes = 64
};
typedef enum callback_action_e
{
    kActionNone,
    kActionInject,
    kActionByteOverflow,
    kActionChargeOverflow,
    kActionEntryOverflow,
    kActionActiveOverflow,
    kActionClose
} callback_action_t;

typedef struct input_fixture_s
{
    twf_worker_env_t  env;
    tunnel_t         *bridge;
    tunnel_t         *prev;
    tunnel_t         *next;
    tunnel_chain_t   *chain;
    line_t           *packet_line;
    line_t           *stream_line;
    uint32_t          delivered;
    uint32_t          finishes;
    uint32_t          depth;
    uint32_t          max_depth;
    uint32_t          nested_sequence;
    callback_action_t action;
    bool              active_overflow_armed;
} input_fixture_t;

static input_fixture_t f;

sbuf_t *__real_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);
sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second);

sbuf_t *__wrap_sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict first, sbuf_t *restrict second)
{
    sbuf_t *merged = __real_sbufAppendMerge(pool, first, second);
    /* buffer_pool.c recycles the second input inside its own translation unit,
     * bypassing GNU's reuse wrapper. Mirror that consumed ownership, as the
     * existing HalfDuplex and ConnectionFisher fixtures do. */
    twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, second);
    if (! twfLedgerContains(g_twf_buffers.recycled, g_twf_buffers.recycled_count, second))
        twfLedgerRemember(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, second, "too many merged buffers");
    if (merged != first)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, first);
        if (! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, merged))
            twfTrackAcquired(merged);
    }
    return merged;
}

static bridge_lstate_t *parserState(void)
{
#ifdef TEST_PACKETS_TO_STREAM
    return lineGetState(f.packet_line, f.bridge);
#else
    return lineGetState(f.stream_line, f.bridge);
#endif
}

static void receive(sbuf_t *buf)
{
#ifdef TEST_PACKETS_TO_STREAM
    packetstostreamTunnelDownStreamPayload(f.bridge, f.stream_line, buf);
#else
    streamtopacketsTunnelUpStreamPayload(f.bridge, f.stream_line, buf);
#endif
}

static void buildPacket(uint8_t *raw, uint32_t sequence)
{
    memoryZero(raw, kPacketBytes);
    raw[0] = 0x45;
    PUT_BE16(raw + 2, kPacketBytes);
    raw[8] = 64;
    raw[9] = 253;
    PUT_BE32(raw + IP_HLEN, sequence);
    for (uint32_t i = IP_HLEN + 4; i < kPacketBytes; ++i)
        raw[i] = (uint8_t) (sequence ^ i);
}

/* A slice of an ordered, infinite sequence of complete 64-byte IPv4 packets. */
static sbuf_t *makeInput(uint32_t first_sequence, uint32_t offset, uint32_t bytes)
{
    sbuf_t *buf = bufferpoolGetBestFit(f.env.pool, bytes, bufferpoolGetLargeBufferPadding(f.env.pool));
    sbufSetLength(buf, bytes);
    uint8_t *target = sbufGetMutablePtr(buf);
    for (uint32_t copied = 0; copied < bytes;)
    {
        uint8_t        packet[kPacketBytes];
        const uint32_t cursor = offset + copied;
        const uint32_t within = cursor % kPacketBytes;
        const uint32_t count  = min(bytes - copied, kPacketBytes - within);
        buildPacket(packet, first_sequence + cursor / kPacketBytes);
        memoryCopy(target + copied, packet + within, count);
        copied += count;
    }
    return buf;
}

static void closeCarrier(void)
{
#ifdef TEST_PACKETS_TO_STREAM
    packetstostreamTunnelDownStreamFinish(f.bridge, f.stream_line);
#else
    streamtopacketsTunnelUpStreamFinish(f.bridge, f.stream_line);
    lineDestroy(f.stream_line);
#endif
}

static void recordFinish(tunnel_t *t, line_t *line)
{
    discard t;
    twfRequire(line == f.stream_line && lineIsAlive(line), "Finish reached the wrong/dead carrier");
    ++f.finishes;
#ifndef TEST_PACKETS_TO_STREAM
    /* This fixture is the owner of StreamToPackets' borrowed normal line. */
    lineDestroy(line);
#endif
}

static void recordPacket(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    ++f.depth;
    f.max_depth = max(f.max_depth, f.depth);
    twfRequire(line == f.packet_line && lineIsOnCurrentWorker(line), "packet left on the wrong worker/line");
    uint8_t expected[kPacketBytes];
    buildPacket(expected, f.delivered);
    twfRequire(sbufGetLength(buf) == kPacketBytes && memoryEqual(sbufGetRawPtr(buf), expected, kPacketBytes),
               "decoded packet bytes or FIFO sequence changed");
    ++f.delivered;
    lineReuseBuffer(line, buf);

    const callback_action_t action = f.action;
    f.action                       = kActionNone;
    if (action == kActionInject)
    {
        receive(makeInput(f.nested_sequence, 0, 2 * kPacketBytes));
        twfRequire(f.delivered == 1, "nested input recursively delivered packets");
    }
    else if (action == kActionByteOverflow)
    {
        receive(makeInput(2, 0, kIpv4StreamNestedBytes));
        twfRequire(lineIsAlive(f.stream_line), "exact nested byte limit was rejected");
        receive(makeInput(2, kIpv4StreamNestedBytes, 1));
    }
    else if (action == kActionChargeOverflow)
    {
        sbuf_t *large = twfTrackAcquired(sbufCreate(kIpv4StreamNestedCharge));
        sbufSetLength(large, kPacketBytes);
        buildPacket(sbufGetMutablePtr(large), 2);
        receive(large);
    }
    else if (action == kActionEntryOverflow)
    {
        for (uint32_t i = 0; i < kIpv4StreamNestedEntries; ++i)
        {
            receive(makeInput(2, i, 1));
            twfRequire(lineIsAlive(f.stream_line), "nested entry limit rejected its equality boundary");
        }
        receive(makeInput(2, kIpv4StreamNestedEntries, 1));
    }
    else if (action == kActionActiveOverflow)
    {
        receive(makeInput(1, 0, kIpv4StreamNestedBytes));
        f.active_overflow_armed = true;
    }
    else if (f.active_overflow_armed)
    {
        f.active_overflow_armed = false;
        receive(makeInput(1, kIpv4StreamNestedBytes, 1));
    }
    else if (action == kActionClose)
        closeCarrier();
    --f.depth;
}

static void fixtureSetup(void)
{
    memoryZero(&f, sizeof(f));
    twfWorkerEnvSetupWithSmallBuffers(&f.env, 8192, kMaxAllowedPacketLength, 0);
    f.bridge = tunnelCreate(NULL, sizeof(bridge_tstate_t), sizeof(bridge_lstate_t));
    f.prev   = tunnelCreate(NULL, 0, 0);
    f.next   = tunnelCreate(NULL, 0, 0);
    twfRequire(f.bridge != NULL && f.prev != NULL && f.next != NULL, "failed to create fixture tunnels");
    tunnelBind(f.prev, f.bridge);
    tunnelBind(f.bridge, f.next);
    f.chain                       = tunnelchainCreate(1);
    f.chain->sum_line_state_size  = f.bridge->lstate_size;
    f.chain->contains_packet_node = true;
    tunnelchainFinalize(f.chain);
    f.bridge->chain = f.chain;
    f.prev->chain   = f.chain;
    f.next->chain   = f.chain;
    f.packet_line   = tunnelchainGetWorkerPacketLine(f.chain, 0);
    f.stream_line   = lineCreate(tunnelchainGetLinePools(f.chain), 0);
    lineRef(f.stream_line); /* Keep allocation valid for post-close assertions. */
#ifdef TEST_PACKETS_TO_STREAM
    f.prev->fnPayloadD = recordPacket;
    f.next->fnFinU     = recordFinish;
    packetstostreamLinestateInitialize(parserState(), f.env.pool);
    parserState()->line               = f.stream_line;
    parserState()->recreate_scheduled = true; /* This fixture owns no reconnect producer. */
#else
    f.next->fnPayloadU = recordPacket;
    f.prev->fnFinD     = recordFinish;
    twfRequire(streamtopacketsOwnershipInitialize(tunnelGetState(f.bridge)), "failed to initialize source registry");
    streamtopacketsLinestateInitialize(parserState(), f.env.pool);
    twfRequire(streamtopacketsRegisterCandidateLine(f.bridge, f.stream_line), "failed to register anonymous carrier");
#endif
}

static void fixtureTeardown(void)
{
    if (lineIsAlive(f.stream_line))
        closeCarrier();
    twfRequireLineStateZeroed(f.stream_line, f.bridge, "normal carrier retained node state after close");
    twfRequire(twfLineRefCount(f.stream_line) == 1, "carrier creator/reference ownership was not settled");
    lineUnref(f.stream_line);
#ifdef TEST_PACKETS_TO_STREAM
    packetstostreamLinestateDestroy(parserState());
#else
    streamtopacketsOwnershipDestroy(f.bridge);
#endif
    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(f.chain);
    tunnelDestroy(f.bridge);
    tunnelDestroy(f.prev);
    tunnelDestroy(f.next);
    twfWorkerEnvTeardown(&f.env);
}

static void testLargeBatch(uint32_t bytes)
{
    twfSetCase("large valid delivery drains every complete IPv4 packet");
    fixtureSetup();
    receive(makeInput(0, 0, bytes));
    twfRequireEqualU32(f.delivered, bytes / kPacketBytes, "large valid delivery was discarded or truncated");
    twfRequire(bufferstreamGetBufLen(&parserState()->read_stream) == 0, "complete delivery retained bytes");
    twfRequire(! parserState()->read_input.draining && lineIsAlive(f.stream_line), "complete batch left a drain/close");
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

static void testThresholdWithPartial(void)
{
    twfSetCase("128 KiB delivery completes an earlier partial packet before applying retention limits");
    fixtureSetup();
    receive(makeInput(0, 0, IP_HLEN));
    twfRequire(f.delivered == 0, "partial packet was delivered");
    receive(makeInput(0, IP_HLEN, 128U * 1024U));
    twfRequire(f.delivered == 2048 && bufferstreamGetBufLen(&parserState()->read_stream) == IP_HLEN,
               "combined threshold delivery lost complete packets or its tail");
    receive(makeInput(2048, IP_HLEN, kPacketBytes - IP_HLEN));
    twfRequireEqualU32(f.delivered, 2049, "threshold tail did not complete");
    fixtureTeardown();
}

static void testLargeTail(void)
{
    twfSetCase("a tiny incomplete suffix releases a large delivery allocation");
    fixtureSetup();
    receive(makeInput(0, 0, 1024U * 1024U + 3));
    twfRequire(f.delivered == 16384 && bufferstreamGetBufLen(&parserState()->read_stream) == 3,
               "large delivery lost packets or incomplete suffix");
    buffer_pool_fit_t fit;
    twfRequire(bufferpoolQueryBestFit(f.env.pool, 3, bufferpoolGetLargeBufferPadding(f.env.pool), &fit),
               "tiny incomplete allocation was unrepresentable");
    twfRequire(bufferstreamGetCharge(&parserState()->read_stream) <=
                   max((size_t) kIpv4StreamIncompleteCharge, fit.allocation_charge),
               "tiny suffix pinned the large input allocation");
    receive(makeInput(16384, 3, kPacketBytes - 3));
    twfRequireEqualU32(f.delivered, 16385, "compacted tail bytes did not complete the next packet");
    fixtureTeardown();
}

static void testNestedFifo(void)
{
    twfSetCase("nested input waits behind all older bytes without recursive packet callbacks");
    fixtureSetup();
    f.action          = kActionInject;
    f.nested_sequence = 4800;
    receive(makeInput(0, 0, 300U * 1024U));
    twfRequire(f.delivered == 4802 && f.max_depth == 1, "nested delivery reordered, recursed or disappeared");
    fixtureTeardown();
}

static void testNestedRefusal(callback_action_t action)
{
    twfSetCase("nested retention refusal closes only the carrier and settles pending ownership");
    fixtureSetup();
    f.action = action;
    receive(makeInput(0, 0, action == kActionActiveOverflow ? kPacketBytes : 2 * kPacketBytes));
    const uint32_t expected = action == kActionActiveOverflow ? 2 : 1;
    twfRequire(f.delivered == expected && f.max_depth == 1, "refused nested input allowed further packet callbacks");
    twfRequire(! lineIsAlive(f.stream_line) && f.finishes == 1,
               "nested refusal did not finish the carrier exactly once");
    twfRequire(lineIsAlive(f.packet_line), "nested refusal destroyed the persistent packet line");
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

static void testCloseDuringDelivery(void)
{
    twfSetCase("closing the carrier in the first packet callback stops the admitted batch");
    fixtureSetup();
    f.action = kActionClose;
    receive(makeInput(0, 0, 300U * 1024U));
    twfRequire(f.delivered == 1 && ! lineIsAlive(f.stream_line), "decode continued after carrier close");
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

static void testEmptyInput(void)
{
    twfSetCase("empty deliveries do not retain their allocations or parser entries");
    fixtureSetup();
    for (unsigned i = 0; i < 4; ++i)
    {
        sbuf_t *empty = bufferpoolGetBestFit(f.env.pool, 1024U * 1024U, 0);
        sbufSetLength(empty, 0);
        receive(empty);
    }
    twfRequire(f.delivered == 0 && bufferstreamGetEntryCount(&parserState()->read_stream) == 0 &&
                   bufferstreamGetCharge(&parserState()->read_stream) == 0 && ! parserState()->read_input.draining,
               "empty input retained state or emitted a packet");
    twfRequireNoLeakedBuffers();
    fixtureTeardown();
}

int main(void)
{
    testLargeBatch(300U * 1024U);
    testLargeBatch(1024U * 1024U);
    testLargeBatch(128U * 1024U);
    testThresholdWithPartial();
    testLargeTail();
    testNestedFifo();
    testNestedRefusal(kActionByteOverflow);
    testNestedRefusal(kActionChargeOverflow);
    testNestedRefusal(kActionEntryOverflow);
    testNestedRefusal(kActionActiveOverflow);
    testCloseDuringDelivery();
    testEmptyInput();
    puts("ipv4_stream_input_test: all checks passed");
    return 0;
}
