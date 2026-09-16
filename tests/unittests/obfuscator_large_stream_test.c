#include "tunnel_line_failure_harness.h"

extern tunnel_t *obfuscatorclientTunnelCreate(node_t *node);
extern tunnel_t *obfuscatorserverTunnelCreate(node_t *node);

typedef struct record_lifetime_s
{
    sbuf_lifetime_t base;
    unsigned        references;
} record_lifetime_t;
static void retainRecord(sbuf_lifetime_t *base)
{
    ++((record_lifetime_t *) base)->references;
}
static void releaseRecord(sbuf_lifetime_t *base)
{
    --((record_lifetime_t *) base)->references;
}

static unsigned  interruption;
static uint32_t  pool_size = LARGE_BUFFER_SIZE_RAM_HIGH;
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
    const uint32_t at = i % 65535;
    if (at == 0)
        return 0x45;
    if (at == 9)
        return 6;
    if (at == 32)
        return 0x50;
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
    record_lifetime_t lifetime = {.base = {.retain = retainRecord, .release = releaseRecord}, .references = 1};
    twf_worker_env_t  env;
    twfWorkerEnvSetupWithSmallBuffers(&env, pool_size, 4096, 128);
    cJSON *settings =
        cJSON_Parse("{\"method\":\"xor\",\"xor_key\":90,\"skip\":\"transport\",\"tls_record_header\":true}");
    node_t      node   = {.node_settings_json = settings};
    tunnel_t   *client = obfuscatorclientTunnelCreate(&node);
    tunnel_t   *server = obfuscatorserverTunnelCreate(&node);
    twf_trace_t trace  = {0};
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
    decoder_receives_upstream = false;
    client->fnInitU(client, cl);
    server->fnInitU(server, sl);
    cn->fnPayloadU = captureWire;
    sn->fnPayloadU = captureWire;
    cp->fnPayloadD = receive;
    sp->fnPayloadD = receive;
    for (unsigned delivery = 0; delivery < 2; ++delivery)
    {
        sbuf_t *input = bufferpoolGetLargeBuffer(env.pool);
        input         = sbufReserveSpace(input, length);
        sbufSetLength(input, length);
        for (uint32_t i = 0; i < length; ++i)
            sbufGetMutablePtr(input)[i] = pattern(i);
        if (reverse)
            server->fnPayloadU(server, sl, input);
        else
            client->fnPayloadU(client, cl, input);
        twfRequire(wire != NULL, "encoder dropped input");
        uint32_t       offset = 0;
        const uint8_t *p      = sbufGetRawPtr(wire);
        while (offset < sbufGetLength(wire))
        {
            twfRequire(sbufGetLength(wire) - offset >= 5, "truncated record header");
            twfRequire(p[offset] == 23 && p[offset + 1] == 3 && p[offset + 2] == 3, "invalid TLS-like header");
            uint32_t body = ((uint32_t) p[offset + 3] << 8) | p[offset + 4];
            twfRequire(body <= sbufGetLength(wire) - offset - 5, "invalid record length");
            offset += 5 + body;
        }
        received = calls  = 0;
        pause_on_delivery = fragment == 0;
        sbuf_t *encoded   = wire;
        wire              = NULL;
        if (interruption == 4)
        {
            uint8_t empty_records[] = {23, 3, 3, 0, 0, 23, 3, 3, 0, 0, 23, 3, 3, 0, 1, 0};
            empty_records[15]       = pattern(0) ^ 90;
            sbufWrite(encoded, empty_records, sizeof(empty_records));
            sbufSetLength(encoded, sizeof(empty_records));
            sbufAttachLifetime(encoded, &lifetime.base);
        }
        if (interruption == 2)
            sbufGetMutablePtr(encoded)[0] = 0;
        if (fragment == 0)
        {
            if (interruption == 3)
                decoder->fnPauseU(decoder, reverse ? cl : sl);
            if (reverse)
                client->fnPayloadD(client, cl, encoded);
            else
                server->fnPayloadD(server, sl, encoded);
            if (interruption == 1 || interruption == 2)
            {
                twfRequire(! lineIsAlive(reverse ? cl : sl), "decoder interruption did not close through owner");
                twfRequire(calls == (interruption == 1), "malformed frame escaped or close repeated delivery");
                break;
            }
            if (interruption == 3)
            {
                twfRequire(calls == 0, "paused decoder forwarded input");
                decoder->fnResumeU(decoder, reverse ? cl : sl);
            }
            twfRequire(calls == 1, "decoder sent another callback after Pause");
            if (reverse)
                client->fnResumeU(client, cl);
            else
                server->fnResumeU(server, sl);
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
                    server->fnPayloadD(server, sl, part);
            }
            lineReuseBuffer(cl, encoded);
        }
        if (interruption == 4)
        {
            twfRequire(received == 1 && lifetime.references == 0, "empty records lost lifetime ownership");
            break;
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
    const uint32_t lengths[] = {65534, 65535, 65536, LARGE_BUFFER_SIZE_RAM_HIGH};
    for (unsigned direction = 0; direction < 2; ++direction)
        for (unsigned i = 0; i < 4; ++i)
        {
            runCase(direction != 0, lengths[i], 0);
            runCase(direction != 0, lengths[i], 65521);
        }
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        runCase(direction != 0, 128, 1);
        for (interruption = 1; interruption <= 4; ++interruption)
            runCase(direction != 0, LARGE_BUFFER_SIZE_RAM_HIGH, 0);
        interruption = 0;
    }
    pool_size = 32768;
    runCase(false, LARGE_BUFFER_SIZE_RAM_HIGH, 65521);
    runCase(true, LARGE_BUFFER_SIZE_RAM_HIGH, 65521);
    frandThreadCleanup();
    frandGlobalCleanup();
    return 0;
}
