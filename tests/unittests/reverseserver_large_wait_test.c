#include "ReverseServer/structure.h"
#include "tunnel_line_failure_harness.h"

static void runCase(uint32_t large, uint32_t length, bool local_first, bool available)
{
    twf_worker_env_t env;
    twfWorkerEnvSetupWithSmallBuffers(&env, large, 4096, 64);
    twf_trace_t trace      = {0};
    uint8_t    *capture    = memoryAllocate(length + 128);
    trace.capture          = capture;
    trace.capture_capacity = length + 128;
    tunnel_t *prev = twfCreatePrevTunnel(&trace), *next = twfCreateNextTunnel(&trace);
    tunnel_t *reverse = tunnelCreate(
        NULL, sizeof(reverseserver_tstate_t) + sizeof(reverseserver_thread_box_t), sizeof(reverseserver_lstate_t));
    tunnelBind(prev, reverse);
    tunnelBind(reverse, next);
    reverseserver_tstate_t *ts          = tunnelGetState(reverse);
    uint8_t                 handshake[] = {1, 2, 3};
    ts->handshake_bytes                 = handshake;
    ts->handshake_length                = sizeof(handshake);
    line_t *u = twfLineCreate(reverse->lstate_size), *d = twfLineCreate(reverse->lstate_size);
    reverseserverTunnelUpStreamInit(reverse, d);
    reverseserverTunnelDownStreamInit(reverse, u);
    const uint64_t limit = reverseserverWaitingLimit(u);
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
                sbufSetLength(peer, 0);
                reverseserverTunnelDownStreamPayload(reverse, u, peer);
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
    const uint32_t sizes[] = {32768, 512 * 1024};
    for (unsigned i = 0; i < 2; ++i)
    {
        uint32_t limit = 65535 * (sizes[i] / 32768);
        for (unsigned side = 0; side < 2; ++side)
        {
            runCase(sizes[i], limit - 1, side, false);
            runCase(sizes[i], limit, side, false);
            runCase(sizes[i], limit + 1, side, false);
        }
        runCase(sizes[i], limit + 1, true, true);
    }
    runCase(512 * 1024, 512 * 1024, true, false);
    return 0;
}
