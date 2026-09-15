#include "tunnel_line_failure_harness.h"

extern tunnel_t *bgp4clientTunnelCreate(node_t *node);
extern tunnel_t *bgp4serverTunnelCreate(node_t *node);

static unsigned  interruption;
static uint32_t  pool_size = 512 * 1024;
static tunnel_t *decoder;
static bool      decoder_receives_upstream;
static void      ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}
static sbuf_t  *wire;
static uint32_t received;
static uint32_t calls;
static bool     pause_on_delivery;
static uint8_t  pattern(uint32_t i)
{
    return (uint8_t) (i * 31 + 7);
}

static void captureWire(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    twfRequire(wire == NULL, "encoder emitted more than one callback");
    wire = buf;
}
static void receive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const uint8_t *p = sbufGetRawPtr(buf);
    for (uint32_t i = 0; i < sbufGetLength(buf); ++i)
        twfRequire(p[i] == pattern(received + i), "roundtrip changed stream bytes");
    received += sbufGetLength(buf);
    ++calls;
    lineReuseBuffer(l, buf);
    if (interruption == 1)
    {
        if (decoder_receives_upstream)
            decoder->fnFinD(decoder, l);
        else
            decoder->fnFinU(decoder, l);
        if (lineIsAlive(l))
            lineDestroy(l);
        return;
    }
    if (pause_on_delivery)
    {
        if (t->prev != NULL)
            tunnelPrevDownStreamPause(t, l);
        else
            tunnelNextUpStreamPause(t, l);
    }
}

static void runCase(bool reverse, uint32_t length, uint32_t fragment)
{
    twf_worker_env_t env;
    twfWorkerEnvSetupWithSmallBuffers(&env, pool_size, 4096, 128);
    cJSON      *settings = cJSON_CreateObject();
    node_t      node     = {.node_settings_json = settings};
    tunnel_t   *client   = bgp4clientTunnelCreate(&node);
    tunnel_t   *server   = bgp4serverTunnelCreate(&node);
    twf_trace_t trace    = {0};
    tunnel_t   *cp = twfCreatePrevTunnel(&trace), *cn = twfCreateNextTunnel(&trace);
    tunnel_t   *sp = twfCreatePrevTunnel(&trace), *sn = twfCreateNextTunnel(&trace);
    tunnelBind(cp, client);
    tunnelBind(client, cn);
    tunnelBind(sp, server);
    tunnelBind(server, sn);
    twf_line_pool_t lines;
    twfLinePoolSetup(&lines, max(client->lstate_size, server->lstate_size), 8);
    line_t *cl = twfLinePoolCreateLine(&lines), *sl = twfLinePoolCreateLine(&lines);
    lineRef(cl);
    lineRef(sl);
    cp->fnFinD                = ownerFinish;
    sp->fnFinD                = ownerFinish;
    decoder                   = reverse ? client : server;
    decoder_receives_upstream = ! reverse;
    client->fnInitU(client, cl);
    server->fnInitU(server, sl);
    cn->fnPayloadU = captureWire;
    sp->fnPayloadD = captureWire;
    cp->fnPayloadD = receive;
    sn->fnPayloadU = receive;
    for (unsigned delivery = 0; delivery < 2; ++delivery)
    {
        sbuf_t *input = bufferpoolGetLargeBuffer(env.pool);
        input         = sbufReserveSpace(input, length);
        sbufSetLength(input, length);
        for (uint32_t i = 0; i < length; ++i)
            sbufGetMutablePtr(input)[i] = pattern(i);
        if (reverse)
            server->fnPayloadD(server, sl, input);
        else
            client->fnPayloadU(client, cl, input);
        twfRequire(wire != NULL, "encoder dropped input");
        uint32_t       offset = 0, opens = 0;
        const uint8_t *p = sbufGetRawPtr(wire);
        while (offset < sbufGetLength(wire))
        {
            twfRequire(sbufGetLength(wire) - offset >= 19, "truncated frame header");
            for (unsigned i = 0; i < 16; ++i)
                twfRequire(p[offset + i] == 255, "invalid marker");
            uint32_t body = ((uint32_t) p[offset + 16] << 8) | p[offset + 17];
            twfRequire(body > 1 && body <= sbufGetLength(wire) - offset - 18, "invalid wire length");
            opens += p[offset + 18] == 1;
            offset += 18 + body;
        }
        twfRequire(opens == (! reverse && delivery == 0), "OPEN count is incorrect");
        received = calls  = 0;
        pause_on_delivery = fragment == 0;
        sbuf_t *encoded   = wire;
        wire              = NULL;
        if (interruption == 2)
            sbufGetMutablePtr(encoded)[0] = 0;
        if (fragment == 0)
        {
            if (reverse)
                client->fnPayloadD(client, cl, encoded);
            else
                server->fnPayloadU(server, sl, encoded);
            if (interruption == 1 || interruption == 2)
            {
                twfRequire(! lineIsAlive(reverse ? cl : sl), "decoder interruption did not close through owner");
                twfRequire(calls == (interruption == 1), "malformed frame escaped or close repeated delivery");
                break;
            }
            twfRequire(calls == 1, "decoder sent another callback after Pause");
            if (reverse)
                client->fnResumeU(client, cl);
            else
                server->fnResumeD(server, sl);
        }
        else
        {
            while (sbufGetLength(encoded) > 0)
            {
                uint32_t n    = min(fragment, sbufGetLength(encoded));
                sbuf_t  *part = sbufCreateWithPadding(n, 128);
                sbufMoveTo(part, encoded, n);
                if (reverse)
                    client->fnPayloadD(client, cl, part);
                else
                    server->fnPayloadU(server, sl, part);
            }
            lineReuseBuffer(cl, encoded);
        }
        twfRequire(received == length, "decoder lost stream bytes");
    }
    if (lineIsAlive(cl))
        client->fnFinU(client, cl);
    if (lineIsAlive(sl))
        server->fnFinU(server, sl);
    twfRequireLineStateZeroed(cl, client, "client retained state after Finish");
    twfRequireLineStateZeroed(sl, server, "server retained state after Finish");
    if (lineIsAlive(cl))
        lineDestroy(cl);
    if (lineIsAlive(sl))
        lineDestroy(sl);
    lineUnref(cl);
    lineUnref(sl);
    twfLinePoolTeardown(&lines);
    tunnelDestroy(cp);
    tunnelDestroy(cn);
    tunnelDestroy(sp);
    tunnelDestroy(sn);
    tunnelDestroy(client);
    tunnelDestroy(server);
    cJSON_Delete(settings);
    twfWorkerEnvTeardown(&env);
}
int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random initialization failed");
    twfRequire(frandGlobalInit(), "random initialization failed");
    const uint32_t lengths[] = {65533, 65534, 65535, 512 * 1024};
    for (unsigned direction = 0; direction < 2; ++direction)
        for (unsigned i = 0; i < 4; ++i)
        {
            runCase(direction != 0, lengths[i], 0);
            runCase(direction != 0, lengths[i], 65521);
        }
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        runCase(direction != 0, 128, 1);
        for (interruption = 1; interruption <= 2; ++interruption)
            runCase(direction != 0, 512 * 1024, 0);
        interruption = 0;
    }
    pool_size = 32768;
    runCase(false, 512 * 1024, 65521);
    runCase(true, 512 * 1024, 65521);
    frandThreadCleanup();
    frandGlobalCleanup();
    return 0;
}
