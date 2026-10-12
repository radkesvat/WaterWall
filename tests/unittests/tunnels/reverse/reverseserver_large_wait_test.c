/*
 * Covers: reverseserver large wait; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: runCase
 * Checks: Inclusive 2 MiB retention across pool profiles, overflow settlement, and uncapped ready
 * paired forwarding with exact application bytes.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.reverseserver_large_wait_unit
 */
#include "ReverseServer/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

static TunnelFlowRoutinePayload receiveApplication;
static bool                     activation_received;

static void stripActivation(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    if (! activation_received)
    {
        twfRequire(sbufGetLength(buf) >= 4 && reverseActivationReadSize(sbufGetRawPtr(buf)) == 4,
                   "missing one-time activation prefix");
        sbufShiftRight(buf, 4);
        activation_received = true;
    }
    receiveApplication(t, line, buf);
}

static void runCase(uint32_t large, uint32_t length, bool local_first, bool available)
{
    twf_worker_env_t env;
    twfWorkerEnvSetupWithBufferSizes(
        &env, min(large, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH), 4096, 64, SPLICE_PAYLOAD_LIMIT, large);
    twf_trace_t trace      = {0};
    uint8_t    *capture    = memoryAllocate(length + 128);
    trace.capture          = capture;
    trace.capture_capacity = length + 128;
    tunnel_t *prev = twfCreatePrevTunnel(&trace), *next = twfCreateNextTunnel(&trace);
    receiveApplication  = prev->fnPayloadD;
    activation_received = false;
    prev->fnPayloadD    = stripActivation;
    tunnel_t *reverse = tunnelCreate(
        NULL, sizeof(reverseserver_tstate_t) + sizeof(reverseserver_thread_box_t), sizeof(reverseserver_lstate_t));
    tunnelBind(prev, reverse);
    tunnelBind(reverse, next);
    reverseserver_tstate_t *ts          = tunnelGetState(reverse);
    uint8_t                 handshake[] = {1, 2, 3};
    ts->handshake_bytes                 = handshake;
    ts->handshake_length                = sizeof(handshake);
    ts->activation_min_size = ts->activation_max_size = 4;
    line_t *u = twfLineCreate(reverse->lstate_size), *d = twfLineCreate(reverse->lstate_size);
    reverseserverTunnelUpStreamInit(reverse, d);
    if (local_first)
        reverseserverTunnelDownStreamInit(reverse, u);
    const uint64_t limit = kReverseServerPendingBytes;
    if (available)
    {
        sbuf_t *hello = bufferpoolGetSmallBuffer(env.pool);
        sbufWrite(hello, handshake, sizeof(handshake));
        sbufSetLength(hello, sizeof(handshake));
        reverseserverTunnelUpStreamPayload(reverse, d, hello);
    }
    sbuf_t *buf     = bufferpoolGetLargeBuffer(env.pool);
    buf             = sbufReserveSpace(buf, length + (local_first ? 0 : sizeof(handshake)));
    uint8_t *bytes  = sbufGetMutablePtr(buf);
    uint32_t prefix = local_first ? 0 : sizeof(handshake);
    if (prefix)
        memoryCopy(bytes, handshake, prefix);
    for (uint32_t i = 0; i < length; ++i)
        bytes[prefix + i] = (uint8_t) i;
    sbufSetLength(buf, length + prefix);
    if (local_first)
        reverseserverTunnelDownStreamPayload(reverse, u, buf);
    else
        reverseserverTunnelUpStreamPayload(reverse, d, buf);
    if (! available && length > limit)
    {
        twfRequire(trace.next_finish + trace.prev_finish == 1, "waiting overflow did not close");
    }
    else
    {
        twfRequire(trace.next_finish + trace.prev_finish == 0, "valid waiting data closed");
        if (! available)
        {
            sbuf_t *peer = bufferpoolGetSmallBuffer(env.pool);
            if (local_first)
            {
                sbufWrite(peer, handshake, sizeof(handshake));
                sbufSetLength(peer, sizeof(handshake));
                reverseserverTunnelUpStreamPayload(reverse, d, peer);
            }
            else
            {
                lineReuseBuffer(u, peer);
                reverseserverTunnelDownStreamInit(reverse, u);
            }
        }
        twfRequire(trace.capture_len == length, "paired forwarding lost bytes");
        for (uint32_t i = 0; i < length; ++i)
            twfRequire(capture[i] == (uint8_t) i, "paired forwarding reordered bytes");
    }
    reverseserver_lstate_t *uls = lineGetState(u, reverse), *dls = lineGetState(d, reverse);
    if (dls->d)
        reverseserverTunnelUpStreamFinish(reverse, d);
    if (uls->u)
        reverseserverTunnelDownStreamFinish(reverse, u);
    twfRequireLineStateZeroed(u, reverse, "local cleanup leaked state");
    twfRequireLineStateZeroed(d, reverse, "reverse cleanup leaked state");
    twfLineDestroy(u);
    twfLineDestroy(d);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    tunnelDestroy(reverse);
    memoryFree(capture);
    twfWorkerEnvTeardown(&env);
}
int main(void)
{
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    const uint32_t sizes[] = {32768, 64 * 1024, SPLICE_PAYLOAD_LIMIT};
    for (unsigned i = 0; i < 2; ++i)
    {
        uint32_t limit = kReverseServerPendingBytes;
        for (unsigned side = 0; side < 2; ++side)
        {
            runCase(sizes[i], limit - 1, side, false);
            runCase(sizes[i], limit, side, false);
            runCase(sizes[i], limit + 1, side, false);
        }
        runCase(sizes[i], limit + 1, true, true);
    }
    runCase(SPLICE_PAYLOAD_LIMIT, kReverseServerPendingBytes, true, false);
    frandThreadCleanup();
    frandGlobalCleanup();
    return 0;
}
