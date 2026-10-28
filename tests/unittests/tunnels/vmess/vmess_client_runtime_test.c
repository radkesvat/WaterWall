/* Real client/codec with ordinary buffers, owner-worker loops and mock L4
 * neighbors. Tests assert wire bytes, FIFO, datagrams and exact-line settlement;
 * independent protocol vectors are in vmess_crypto_test.
 * CTest: waterwall.vmess_client_runtime_unit, Debug and Release. */
#include "VmessClient/internal.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "loggers/network_logger.h"
#include "wloop_internal.h"

#include "vectors.h"

static bool refuse_first_payload_reset;
bool        __real_wtimerReset(wtimer_t *, uint32_t);
bool        __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms);
bool        __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms)
{
    return ! refuse_first_payload_reset && __real_wtimerReset(timer, timeout_ms);
}

enum
{
    kCaptureSize = 5 * 1024 * 1024
};
typedef struct client_fixture_s
{
    twf_worker_env_t       env;
    twf_line_pool_t        lines;
    worker_t               workers[2];
    buffer_pool_t         *buffer_pools[2];
    wloop_t               *loops[2];
    generic_pool_t        *line_pools[2];
    tunnel_chain_t        *chain;
    node_t                 node;
    tunnel_t              *client, *prev, *next;
    line_t                *application, *carrier;
    uint8_t                up[kCaptureSize], down[kCaptureSize];
    size_t                 up_size, down_size, request_size;
    unsigned               init_count, est_count, up_calls, down_calls, finishes, transport_finishes, pauses, resumes;
    uint32_t               datagram_sizes[16];
    unsigned               action, boundary;
    bool                   udp, request_parsed, response_started;
    vmess_request_header_t request;
    vmess_body_ctx_t       response_encoder;
    uint8_t                response_key[16], response_iv[16];
} client_fixture_t;
static client_fixture_t f;
static wid_t            fixture_wid;
static unsigned         initial_action;
static const char      *initial_address;
static uint16_t         initial_port;
static unsigned         initial_protocol;

static sbuf_t *bytes(line_t *l, const void *data, size_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(l), (uint32_t) length, 64);
    if (length != 0)
        memoryCopy(sbufGetMutablePtr(buf), data, length);
    sbufSetLength(buf, (uint32_t) length);
    return buf;
}
static void sendApplication(const void *data, size_t length)
{
    tunnelUpStreamPayload(f.client, f.application, bytes(f.application, data, length));
}
static void sendWire(const void *data, size_t length)
{
    tunnelDownStreamPayload(f.client, f.carrier, bytes(f.carrier, data, length));
}
static void readRequest(void)
{
    if (f.request_parsed)
        return;
    vmessclient_tstate_t *ts     = tunnelGetState(f.client);
    uint16_t              length = 0;
    twfRequire(f.up_size >= VMESS_REQUEST_PREFIX_SIZE, "first output omitted request prefix");
    twfRequire(vmessRequestLengthOpen(ts->key.cmd_key, f.up, f.up + 16, f.up + 34, &length) == kWCryptoOk,
               "outgoing request length did not authenticate");
    f.request_size = VMESS_REQUEST_PREFIX_SIZE + length + 16;
    twfRequire(f.up_size >= f.request_size && f.request_size <= VMESS_REQUEST_WIRE_MAX,
               "first output split the request header");
    twfRequire(vmessRequestHeaderOpen(
                   ts->key.cmd_key, f.up, f.up + 34, f.up + VMESS_REQUEST_PREFIX_SIZE, length + 16, &f.request) ==
                   kWCryptoOk,
               "outgoing request did not authenticate");
    twfRequire(f.request.command == (f.udp ? 2 : 1), "request changed selected command");
    twfRequire(vmessResponseKeys(f.request.key, f.request.iv, f.response_key, f.response_iv) == kWCryptoOk,
               "response key derivation failed");
    f.request_parsed = true;
}
static size_t response(uint8_t *wire, size_t capacity, const void *body, size_t length, bool eof)
{
    readRequest();
    size_t size = 0, written = 0;
    if (! f.response_started)
    {
        twfRequire(capacity >= VMESS_RESPONSE_HEADER_SIZE, "fixture response capacity");
        twfRequire(vmessResponseHeaderSeal(f.response_key, f.response_iv, f.request.response, wire) == kWCryptoOk,
                   "response seal failed");
        size = VMESS_RESPONSE_HEADER_SIZE;
        twfRequire(vmessBodyInit(&f.response_encoder,
                                 f.response_key,
                                 f.response_iv,
                                 f.request.security,
                                 f.request.options,
                                 f.request.command,
                                 true,
                                 kVmessCounterWrap) == kWCryptoOk,
                   "response body initialization failed");
        if ((f.request.options & VMESS_OPTION_AUTH_LENGTH) != 0)
            twfRequire(vmessBodySetLengthMaterial(&f.response_encoder, f.request.key, f.request.iv) == kWCryptoOk,
                       "response authenticated length initialization failed");
        f.response_started = true;
    }
    if (length != 0 || eof)
    {
        twfRequire(vmessBodySeal(&f.response_encoder, body, length, eof, wire + size, capacity - size, &written) ==
                       kWCryptoOk,
                   "response body seal failed");
        size += written;
    }
    return size;
}
static void reply(const char *data)
{
    uint8_t wire[1024];
    size_t  length = response(wire, sizeof(wire), data, strlen(data), false);
    sendWire(wire, length);
}
static void act(unsigned boundary)
{
    if (f.boundary != boundary)
        return;
    const unsigned action = f.action;
    f.action              = 0;
    if (action == 1)
        sendApplication("nested", 6);
    if (action == 2)
        reply("early");
    if (action == 3)
    {
        tunnelUpStreamFin(f.client, f.application);
        twfRequire(lineIsAlive(f.application), "client destroyed borrowed application");
        lineDestroy(f.application);
    }
    if (action == 4)
    {
        tunnelDownStreamFin(f.client, f.carrier);
        if (f.udp)
            twfRequire(! lineIsAlive(f.carrier), "owner Finish returned with carrier alive");
    }
    if (action == 5)
        reply("nested");
    if (action == 6)
        tunnelDownStreamPause(f.client, f.carrier);
    if (action == 7 || action == 8)
    {
        vmessclient_lstate_t      *ls      = lineGetState(f.carrier, f.client);
        const buffer_budget_cost_t initial = bufferbudgetGetUsage(&ls->upstream_budget);
        twfRequire(initial.entries >= 1, "active transmit head escaped its budget");
        for (size_t i = initial.entries; i < kVmessClientMaxOrderEntries; ++i)
            sendApplication("x", 1);
        twfRequire(lineIsAlive(f.application), "inclusive queue entry bound refused");
        twfRequire(bufferbudgetGetUsage(&ls->upstream_budget).entries == kVmessClientMaxOrderEntries,
                   "nested transmit reservations omit an active head");
        if (action == 8)
            sendApplication("x", 1);
    }
    if (action == 9)
    {
        vmessclient_lstate_t *ls = lineGetState(f.carrier, f.client);
        twfRequire(bufferbudgetGetUsage(&ls->downstream_budget).entries >= 1, "active receive head escaped its budget");
        for (unsigned i = 0; i < kVmessClientMaxOrderEntries && lineIsAlive(f.application); ++i)
            reply("x");
    }
    if (action == 10 || action == 11)
    {
        vmessclient_lstate_t *ls       = lineGetState(f.carrier, f.client);
        size_t                retained = bufferbudgetGetUsage(&ls->upstream_budget).bytes;
        twfRequire(retained > 0 && retained < kVmessClientMaxOrderBytes, "active transmit suffix lost its charge");
        size_t   remaining = kVmessClientMaxOrderBytes - retained;
        uint8_t *data      = memoryAllocate(remaining);
        memorySet(data, 'b', remaining);
        sendApplication(data, remaining);
        memoryFree(data);
        twfRequire(lineIsAlive(f.application) &&
                       bufferbudgetGetUsage(&ls->upstream_budget).bytes == kVmessClientMaxOrderBytes,
                   "inclusive logical byte limit rejected or miscounted");
        if (action == 11)
            sendApplication("x", 1);
    }
    if (action == 12)
    {
        for (unsigned i = 0; i < 20; ++i)
        {
            sbuf_t *oversized = twfTrackAcquired(sbufCreateWithPadding(1024 * 1024, 64));
            sbufSetLength(oversized, 1);
            sbufGetMutablePtr(oversized)[0] = 'x';
            tunnelUpStreamPayload(f.client, f.application, oversized);
            twfRequire(lineIsAlive(f.application), "beneficial compaction failed to admit tiny retained input");
        }
        vmessclient_lstate_t *ls = lineGetState(f.carrier, f.client);
        twfRequire(bufferbudgetGetUsage(&ls->upstream_budget).charge <= kVmessClientMaxOrderCharge,
                   "compacted allocation charge exceeded retention limit");
    }
}
static void ownerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == f.application, "Finish used carrier at application owner");
    ++f.finishes;
    lineDestroy(l);
}
static void nextFinish(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == f.carrier, "transport Finish used application line");
    ++f.transport_finishes;
}
static void nextInit(tunnel_t *t, line_t *l)
{
    discard t;
    ++f.init_count;
    f.carrier = l;
    if (l != f.application)
        lineRef(l);
    twfRequire(lineGetWID(l) == fixture_wid, "carrier changed worker");
    if (f.udp)
    {
        vmessclient_lstate_t *application = lineGetState(f.application, f.client);
        vmessclient_lstate_t *carrier     = lineGetState(l, f.client);
        twfRequire(application->carrier_line == l && carrier->application_line == f.application,
                   "association links were not published before next Init");
    }
    /* A downstream connector may replace this context synchronously. */
    addresscontextSetIpAddress(lineGetDestinationAddressContext(l), "192.0.2.10");
    addresscontextSetPort(lineGetDestinationAddressContext(l), 10000);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), IP_PROTO_TCP);
    act(1);
}
static void established(tunnel_t *t, line_t *l)
{
    discard t;
    twfRequire(l == f.application, "Est exposed carrier");
    ++f.est_count;
    act(2);
}
static void payload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const bool upstream = t == f.next;
    twfRequire(l == (upstream ? f.carrier : f.application), "Payload used wrong exact line");
    twfRequire(! sbufIsSplice(buf) && sbufGetLeftCapacity(buf) >= 64, "output lacks ordinary storage/onward padding");
    size_t        *size    = upstream ? &f.up_size : &f.down_size;
    uint8_t       *capture = upstream ? f.up : f.down;
    const uint32_t count   = sbufGetLength(buf);
    twfRequire(count <= kCaptureSize - *size, "fixture capture limit");
    memoryCopy(capture + *size, sbufGetRawPtr(buf), count);
    *size += count;
    lineReuseBuffer(l, buf);
    if (upstream)
    {
        ++f.up_calls;
        act(3);
    }
    else
    {
        if (f.down_calls < ARRAY_SIZE(f.datagram_sizes))
            f.datagram_sizes[f.down_calls] = count;
        ++f.down_calls;
        act(4);
    }
}
static void pauseSignal(tunnel_t *t, line_t *l)
{
    twfRequire(l == (t == f.prev ? f.application : f.carrier), "Pause mapped wrong line");
    ++f.pauses;
}
static void resumeSignal(tunnel_t *t, line_t *l)
{
    twfRequire(l == (t == f.prev ? f.application : f.carrier), "Resume mapped wrong line");
    ++f.resumes;
}
static cJSON *configuration(const char *security, bool udp)
{
    cJSON *settings = cJSON_CreateObject();
    cJSON_AddStringToObject(settings, "uuid", "5783a3e7-e373-51cd-8642-c83782b807c5");
    cJSON_AddStringToObject(settings, "address", "127.0.0.1");
    cJSON_AddNumberToObject(settings, "port", 443);
    cJSON_AddStringToObject(settings, "protocol", udp ? "udp" : "tcp");
    cJSON_AddStringToObject(settings, "security", security);
    return settings;
}
static void begin(cJSON *settings, bool udp)
{
    memoryZero(&f, sizeof(f));
    f.udp = udp;
    twfWorkerEnvSetupWithBufferSizes(&f.env, 131072, 512, 64, 8192, 131072);
    f.env.loop->status = WLOOP_STATUS_RUNNING;
    if (fixture_wid != 0)
    {
        GSTATE.workers_count         = 2;
        f.workers[0]                 = f.env.worker;
        f.workers[1]                 = f.env.worker;
        f.workers[1].wid             = fixture_wid;
        f.buffer_pools[fixture_wid]  = f.env.pool;
        f.loops[fixture_wid]         = f.env.loop;
        f.env.loop->wid              = fixture_wid;
        GSTATE.workers               = f.workers;
        GSTATE.shortcut_buffer_pools = f.buffer_pools;
        GSTATE.shortcut_loops        = f.loops;
        testWorkerBindWID(fixture_wid);
    }
    f.node = nodeVmessClientGet();
    twfRequire(f.node.flags == kNodeFlagBlocksSplice && f.node.required_padding_left == 0 &&
                   f.node.layer_group == kNodeLayer4 && f.node.can_have_prev && f.node.can_have_next,
               "client metadata violates topology or ordinary-buffer contract");
    f.node.node_settings_json = settings;
    f.client                  = vmessclientTunnelCreate(&f.node);
    twfRequire(f.client != NULL, "valid configuration rejected");
    f.prev                = tunnelCreate(NULL, 0, 0);
    f.next                = tunnelCreate(NULL, 0, 0);
    f.prev->chain_index   = 0;
    f.client->chain_index = 1;
    f.next->chain_index   = 2;
    tunnelBind(f.prev, f.client);
    tunnelBind(f.client, f.next);
    twfLinePoolSetup(&f.lines, f.client->lstate_size, 8);
    f.chain                          = memoryAllocateZero(sizeof(tunnel_chain_t) + 2 * sizeof(void *));
    f.line_pools[0]                  = f.lines.pools[0];
    f.chain->line_pools[0]           = f.lines.pools[0];
    f.line_pools[fixture_wid]        = f.lines.pools[0];
    f.chain->line_pools[fixture_wid] = f.lines.pools[0];
    f.client->chain                  = f.chain;
    f.application                    = lineCreate(f.line_pools, fixture_wid);
    lineRef(f.application);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(f.application), udp ? IP_PROTO_UDP : IP_PROTO_TCP);
    address_context_t *context = lineGetDestinationAddressContext(f.application);
    if (initial_address != NULL && ! addresscontextSetIpAddress(context, initial_address))
        addresscontextDomainSet(context, initial_address, (uint8_t) strlen(initial_address));
    if (initial_port != 0)
        addresscontextSetPort(context, initial_port);
    addresscontextSetOnlyProtocol(context, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
    if (initial_protocol == 1)
        context->proto_tcp = context->proto_udp = true;
    if (initial_protocol == 2)
        addresscontextSetOnlyProtocol(context, 0);
    f.prev->fnFinD     = ownerFinish;
    f.next->fnFinU     = nextFinish;
    f.next->fnInitU    = nextInit;
    f.prev->fnEstD     = established;
    f.prev->fnPayloadD = f.next->fnPayloadU = payload;
    f.prev->fnPauseD = f.next->fnPauseU = pauseSignal;
    f.prev->fnResumeD = f.next->fnResumeU = resumeSignal;
    f.boundary                            = 1;
    f.action                              = initial_action;
    tunnelUpStreamInit(f.client, f.application);
}
static void end(void)
{
    if (lineIsAlive(f.application))
    {
        twfRequire(tunnelIsActiveForLine(f.client, f.application), "VMess bypassed persistent codec");
        tunnelUpStreamFin(f.client, f.application);
        twfRequire(lineIsAlive(f.application), "client destroyed borrowed application");
        lineDestroy(f.application);
    }
    twfRequireLineStateZeroed(f.application, f.client, "application retains state");
    twfRequire(twfLineRefCount(f.application) == 1, "application reference imbalance");
    if (f.carrier != NULL && f.carrier != f.application)
    {
        twfRequire(! lineIsAlive(f.carrier), "owned UDP carrier survives application drain");
        twfRequireLineStateZeroed(f.carrier, f.client, "carrier retains state");
        twfRequire(twfLineRefCount(f.carrier) == 1, "carrier reference imbalance");
        lineUnref(f.carrier);
    }
    lineUnref(f.application);
    twfRequire(wloopNTimers(f.env.loop) == 0, "first-payload timer survives owner drain");
    vmessBodyDestroy(&f.response_encoder);
    twfLinePoolTeardown(&f.lines);
    f.client->onDestroy(f.client, wwLifecycleStartupRollback());
    tunnelDestroy(f.prev);
    tunnelDestroy(f.next);
    memoryFree(f.chain);
    cJSON_Delete(f.node.node_settings_json);
    memoryFree(f.node.type);
    if (fixture_wid != 0)
    {
        GSTATE.workers_count         = 1;
        GSTATE.workers               = &f.env.worker;
        GSTATE.shortcut_buffer_pools = f.env.pool_shortcut;
        GSTATE.shortcut_loops        = f.env.loop_shortcut;
        f.env.loop->wid              = 0;
        testWorkerBindWID(0);
    }
    twfWorkerEnvTeardown(&f.env);
}
static void pump(unsigned milliseconds)
{
    uint64_t deadline = getHRTimeUs() + (uint64_t) milliseconds * 1000;
    do
    {
        discard wloopProcessEvents(f.env.loop, 1);
    } while (getHRTimeUs() < deadline);
}
static void expectTx(const void *expected, size_t length)
{
    readRequest();
    twfRequire(f.request.port == 443 && f.request.address_type == 1 && f.request.address_length == 4 &&
                   f.request.address[0] == 127 && f.request.address[3] == 1,
               "transport destination replacement corrupted final target");
    vmess_body_ctx_t decoder = {0};
    twfRequire(vmessBodyInit(&decoder,
                             f.request.key,
                             f.request.iv,
                             f.request.security,
                             f.request.options,
                             f.request.command,
                             false,
                             kVmessCounterWrap) == kWCryptoOk,
               "outgoing decoder initialization");
    size_t  cursor = f.request_size, used = 0;
    uint8_t output[65536];
    while (cursor < f.up_size)
    {
        size_t written = 0;
        bool   eof     = false;
        if (decoder.raw)
        {
            written = f.up_size - cursor;
            twfRequire(written == length && memoryCompare(f.up + cursor, expected, written) == 0,
                       "raw TX changed bytes");
            used += written;
            cursor += written;
            break;
        }
        const size_t prefix = vmessBodyLengthSize(&decoder);
        uint32_t     body   = 0;
        twfRequire(f.up_size - cursor >= prefix &&
                       vmessBodyLengthOpen(&decoder, f.up + cursor, prefix, &body) == kWCryptoOk,
                   "outgoing record length invalid");
        cursor += prefix;
        twfRequire(f.up_size - cursor >= body &&
                       vmessBodyOpen(&decoder, f.up + cursor, body, output, sizeof(output), &written, &eof) ==
                           kWCryptoOk,
                   "outgoing record failed authentication");
        twfRequire(written <= length - used && memoryCompare(output, (const uint8_t *) expected + used, written) == 0,
                   "outgoing records lost bytes or FIFO order");
        used += written;
        cursor += body;
        twfRequire(! eof || cursor == f.up_size, "outgoing data follows termination");
    }
    twfRequire(used == length, "outgoing byte count differs");
    vmessBodyDestroy(&decoder);
}

static void bootstrap(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(configuration("aes-128-gcm", udp), udp);
        twfRequire(f.up_size == 0 && f.init_count == 1, "Init emitted request");
        sendApplication("", 0);
        twfRequire(f.up_size == 0, "empty input emitted request");
        f.boundary = 3;
        f.action   = 2;
        sendApplication("first", 5);
        twfRequire(f.up_calls == 1 && f.down_size == 5 && memoryCompare(f.down, "early", 5) == 0,
                   "synchronous server response missed published session state");
        f.boundary = 2;
        f.action   = 1;
        tunnelDownStreamEst(f.client, f.carrier);
        tunnelDownStreamEst(f.client, f.carrier);
        twfRequire(f.est_count == (udp ? 1U : 2U), "transport Est repeats/mapping changed");
        expectTx("firstnested", 11);
        twfRequire(! lineIsAuthenticated(f.application) && ! lineIsAuthenticated(f.carrier),
                   "outbound UUID published an authenticated local peer");
        end();
    }
}
static void timing(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        cJSON *settings = configuration("aes-128-gcm", udp);
        cJSON_AddNumberToObject(settings, "first-payload-timeout-ms", 10);
        begin(settings, udp);
        tunnelDownStreamPause(f.client, f.carrier);
        tunnelDownStreamEst(f.client, f.carrier);
        vmessclient_lstate_t *ls       = lineGetState(f.carrier, f.client);
        uint64_t              deadline = ls->first_payload.deadline_us;
        tunnelDownStreamEst(f.client, f.carrier);
        twfRequire(ls->first_payload.deadline_us == deadline, "duplicate Est reset original deadline");
        pump(25);
        twfRequire(udp ? f.up_size == 0 : f.up_size != 0, "idle header pressure semantics changed");
        tunnelDownStreamResume(f.client, f.carrier);
        twfRequire(f.up_calls == 1, "idle request missing or repeated");
        readRequest();
        twfRequire(f.up_size == f.request_size, "idle request contains body");
        pump(30);
        twfRequire(lineIsAlive(f.application), "silent backend hit synthetic response deadline");
        reply("greeting");
        twfRequire(f.down_size == 8 && memoryCompare(f.down, "greeting", 8) == 0, "server-first greeting missing");
        end();
        settings = configuration("aes-128-gcm", udp);
        cJSON_AddNumberToObject(settings, "first-payload-timeout-ms", 0);
        begin(settings, udp);
        f.boundary = 2;
        f.action   = 1;
        tunnelDownStreamEst(f.client, f.carrier);
        expectTx("nested", 6);
        twfRequire(f.up_calls == 1, "zero timeout split available first payload");
        end();
    }
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        twfSetCase("first-payload rearm refusal closes the association");
        begin(configuration("aes-128-gcm", udp), udp);
        tunnelDownStreamEst(f.client, f.carrier);
        vmessclient_lstate_t *ls = lineGetState(f.carrier, f.client);
        twfRequire(ls->first_payload.timer != NULL, "rearm refusal case did not arm a timer");
        refuse_first_payload_reset = true;
        wtimerTestMakePendingOneShot(ls->first_payload.timer);
        discard wloopProcessEvents(f.env.loop, 0);
        refuse_first_payload_reset = false;
        twfRequire(! lineIsAlive(f.application) && f.up_calls == 0 && wloopNTimers(f.env.loop) == 0,
                   "first-payload rearm refusal stranded the association");
        end();
    }
    fixture_wid = 1;
    begin(configuration("aes-128-gcm", true), true);
    tunnelDownStreamEst(f.client, f.carrier);
    vmessclient_lstate_t *ls = lineGetState(f.carrier, f.client);
    twfRequire(ls->first_payload.timer != NULL && ls->first_payload.timer->loop == f.env.loop &&
                   ls->first_payload.timer->loop->wid == 1,
               "timer uses wrong owner worker");
    end();
    fixture_wid = 0;
}
static void modesAndSplits(void)
{
    const char *names[] = {"aes-128-gcm", "chacha20-poly1305", "none", "zero"};
    for (size_t mode = 0; mode < ARRAY_SIZE(names); ++mode)
        for (unsigned udp = 0; udp < (mode == 3 ? 1U : 2U); ++udp)
            for (size_t split = 0; split <= VMESS_RESPONSE_HEADER_SIZE; ++split)
            {
                begin(configuration(names[mode], udp), udp);
                sendApplication("A", 1);
                uint8_t wire[1024];
                size_t  size = response(wire, sizeof(wire), "one", 3, false);
                size += response(wire + size, sizeof(wire) - size, "two", 3, false);
                sendWire(wire, split);
                twfRequire(f.down_size == 0, "partial response header released application bytes");
                for (size_t i = split; i < size; ++i)
                    sendWire(wire + i, 1);
                twfRequire(f.down_size == 6 && memoryCompare(f.down, "onetwo", 6) == 0,
                           "split response lost coalesced records");
                if (udp)
                    twfRequire(f.down_calls == 2 && f.datagram_sizes[0] == 3 && f.datagram_sizes[1] == 3,
                               "UDP record boundaries changed");
                end();
            }
}
static void reentryAndPressure(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(configuration("aes-128-gcm", udp), udp);
        tunnelDownStreamPause(f.client, f.carrier);
        tunnelDownStreamPause(f.client, f.carrier);
        sendApplication("A", 1);
        f.boundary = 3;
        f.action   = 1;
        sendApplication("B", 1);
        expectTx("ABnested", 8);
        tunnelDownStreamResume(f.client, f.carrier);
        tunnelDownStreamResume(f.client, f.carrier);
        if (! udp)
            twfRequire(f.pauses == 2 && f.resumes == 2, "direct TCP suppressed duplicate pressure");
        f.boundary = 4;
        f.action   = 5;
        reply("outer");
        twfRequire(f.down_size == 11 && memoryCompare(f.down, "outernested", 11) == 0,
                   "nested RX overtook active input");
        f.boundary = 4;
        f.action   = 6;
        uint8_t wire[1024];
        size_t  size = response(wire, sizeof(wire), "one", 3, false);
        size += response(wire + size, sizeof(wire) - size, "two", 3, false);
        sendWire(wire, size);
        twfRequire(f.down_size == 17 && memoryCompare(f.down + 11, "onetwo", 6) == 0,
                   "Pause stranded a complete admitted batch");
        end();
    }
    for (unsigned action = 7; action <= 9; ++action)
    {
        begin(configuration("none", false), false);
        f.boundary = action == 9 ? 4 : 3;
        f.action   = action;
        uint8_t active[32768];
        memorySet(active, 'a', sizeof(active));
        sendApplication(active, sizeof(active));
        if (action == 9)
        {
            uint8_t wire[1024];
            size_t  size = response(wire, sizeof(wire), "start", 5, false);
            size += response(wire + size, sizeof(wire) - size, "tail", 4, false);
            sendWire(wire, size);
        }
        twfRequire(lineIsAlive(f.application) == (action == 7), "retention entry limit did not settle correctly");
        end();
    }
}
static void closeAndMalformed(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned boundary = 1; boundary <= 4; ++boundary)
            for (unsigned action = 3; action <= 4; ++action)
            {
                initial_action = boundary == 1 ? action : 0;
                begin(configuration("aes-128-gcm", udp), udp);
                initial_action = 0;
                if (boundary != 1)
                {
                    f.boundary = boundary;
                    f.action   = action;
                    if (boundary == 2)
                        tunnelDownStreamEst(f.client, f.carrier);
                    else
                    {
                        sendApplication("A", 1);
                        if (boundary == 4)
                            reply("B");
                    }
                }
                twfRequire(! lineIsAlive(f.application), "nested closure failed to reach source owner");
                if (udp)
                    twfRequire(! lineIsAlive(f.carrier), "nested Finish left owned carrier alive");
                end();
            }
    for (unsigned corruption = 0; corruption < 3; ++corruption)
    {
        begin(configuration("aes-128-gcm", false), false);
        sendApplication("A", 1);
        uint8_t wire[1024];
        size_t  size = response(wire, sizeof(wire), "B", 1, false);
        if (corruption == 0)
            wire[17] ^= 1;
        if (corruption == 1)
            wire[VMESS_RESPONSE_HEADER_SIZE - 1] ^= 1;
        if (corruption == 2)
            twfRequire(vmessResponseHeaderSeal(
                           f.response_key, f.response_iv, (uint8_t) (f.request.response + 1), wire) == kWCryptoOk,
                       "wrong marker seal failed");
        sendWire(wire, size);
        twfRequire(! lineIsAlive(f.application) && f.down_size == 0, "invalid authenticated response accepted");
        end();
    }
    begin(configuration("aes-128-gcm", true), true);
    sendApplication("A", 1);
    uint8_t wire[1024];
    size_t  size = response(wire, sizeof(wire), NULL, 0, true);
    sendWire(wire, size);
    twfRequire(! lineIsAlive(f.application) && ! lineIsAlive(f.carrier) && f.down_calls == 0,
               "authenticated EOF became datagram or failed owner teardown");
    end();
    begin(configuration("aes-128-gcm", false), false);
    tunnelUpStreamFin(f.client, f.application);
    twfRequire(f.up_size == 0 && lineIsAlive(f.application), "Finish created request or destroyed borrowed line");
    end();
}

static void destinations(void)
{
    const char *addresses[] = {"198.51.100.23", "2001:db8::1234", "target.example.test"};
    for (size_t i = 0; i < ARRAY_SIZE(addresses); ++i)
        for (unsigned udp = 0; udp < 2; ++udp)
        {
            cJSON *settings = configuration("aes-128-gcm", udp);
            cJSON_ReplaceItemInObjectCaseSensitive(settings, "address", cJSON_CreateString("dest_context->address"));
            cJSON_ReplaceItemInObjectCaseSensitive(settings, "port", cJSON_CreateString("dest_context->port"));
            cJSON_ReplaceItemInObjectCaseSensitive(settings, "protocol", cJSON_CreateString("dest_context->protocol"));
            initial_address = addresses[i];
            initial_port    = 1234;
            begin(settings, udp);
            sendApplication("A", 1);
            readRequest();
            twfRequire(f.request.port == 1234 && f.request.address_type == (i == 0   ? 1
                                                                            : i == 1 ? 3
                                                                                     : 2),
                       "context target changed after transport Init");
            if (i == 2)
                twfRequire(f.request.address_length == strlen(addresses[i]) &&
                               memoryCompare(f.request.address, addresses[i], strlen(addresses[i])) == 0,
                           "domain target corrupted");
            end();
        }
    initial_address = NULL;
    initial_port    = 0;
    for (unsigned field = 0; field < 2; ++field)
    {
        cJSON *settings = configuration("aes-128-gcm", false);
        cJSON_ReplaceItemInObjectCaseSensitive(
            settings,
            field ? "port" : "address",
            cJSON_CreateString(field ? "dest_context->port" : "dest_context->address"));
        begin(settings, false);
        twfRequire(! lineIsAlive(f.application) && f.init_count == 0 && f.up_size == 0,
                   "missing context opened transport");
        end();
    }
    for (unsigned protocol = 1; protocol <= 2; ++protocol)
    {
        cJSON *settings = configuration("aes-128-gcm", false);
        cJSON_ReplaceItemInObjectCaseSensitive(settings, "protocol", cJSON_CreateString("dest_context->protocol"));
        initial_protocol = protocol;
        begin(settings, false);
        sendApplication("A", 1);
        readRequest();
        twfRequire(f.request.command == 1, "invalid context did not fall back to TCP");
        end();
    }
    initial_protocol = 0;
    cJSON *settings  = configuration("zero", false);
    cJSON_ReplaceItemInObjectCaseSensitive(settings, "protocol", cJSON_CreateString("dest_context->protocol"));
    begin(settings, true);
    twfRequire(! lineIsAlive(f.application) && f.init_count == 0, "dynamic UDP zero silently downgraded");
    end();
    settings = configuration("none", false);
    cJSON_AddBoolToObject(settings, "global-padding", true);
    cJSON_ReplaceItemInObjectCaseSensitive(settings, "protocol", cJSON_CreateString("dest_context->protocol"));
    begin(settings, false);
    twfRequire(! lineIsAlive(f.application) && f.init_count == 0, "dynamic mode skipped final command validation");
    end();
}

static void reservedPacketAddressTarget(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned dynamic = 0; dynamic < 2; ++dynamic)
        {
            cJSON *settings = configuration("aes-128-gcm", udp);
            cJSON_ReplaceItemInObjectCaseSensitive(
                settings, "address", cJSON_CreateString(dynamic ? "dest_context->address" : VMESS_PACKETADDR_DOMAIN));
            initial_address = dynamic ? VMESS_PACKETADDR_DOMAIN : NULL;
            begin(settings, udp);
            twfRequire(! lineIsAlive(f.application) && f.init_count == 0 && f.up_size == 0,
                       "reserved packetaddr domain opened an ordinary transport");
            end();
        }
    initial_address = NULL;

    /* The resolver calls its prepare hook before scheduling DNS. Exercise that
     * boundary directly without a resolver or any network dependency. */
    cJSON *settings = configuration("aes-128-gcm", false);
    cJSON_ReplaceItemInObjectCaseSensitive(settings, "address", cJSON_CreateString("dest_context->address"));
    initial_address = "127.0.0.1";
    begin(settings, false);
    initial_address          = NULL;
    vmessclient_tstate_t *ts = tunnelGetState(f.client);
    ts->resolve_domains      = true;
    addresscontextDomainSet(
        lineGetDestinationAddressContext(f.application), VMESS_PACKETADDR_DOMAIN, sizeof(VMESS_PACKETADDR_DOMAIN) - 1);
    twfRequire(! vmessclientDomainResolverPrepare(NULL, f.client, f.application, NULL),
               "reserved packetaddr domain passed the DNS prepare boundary");
    end();
}

static void frameBoundaries(void)
{
    const char   *names[]   = {"aes-128-gcm", "chacha20-poly1305", "none"};
    const uint8_t modes[]   = {VMESS_SECURITY_AES128_GCM, VMESS_SECURITY_CHACHA20_POLY1305, VMESS_SECURITY_NONE};
    const uint8_t options[] = {1, 5, 13, 17, 21, 29};
    for (size_t mode = 0; mode < ARRAY_SIZE(names); ++mode)
        for (size_t o = 0; o < ARRAY_SIZE(options); ++o)
        {
            if (mode == 2 && o >= 3)
                continue;
            cJSON *settings = configuration(names[mode], true);
            cJSON_AddBoolToObject(settings, "chunk-masking", (options[o] & VMESS_OPTION_MASK) != 0);
            cJSON_AddBoolToObject(settings, "global-padding", (options[o] & VMESS_OPTION_PADDING) != 0);
            cJSON_AddBoolToObject(settings, "authenticated-length", (options[o] & VMESS_OPTION_AUTH_LENGTH) != 0);
            begin(settings, true);
            vmess_body_ctx_t geometry = {.security = modes[mode], .options = options[o]};
            size_t           maximum  = vmessBodyMaxPlaintext(&geometry);
            uint8_t         *data     = memoryAllocate(maximum + 1);
            memorySet(data, 'z', maximum + 1);
            sendApplication(data, maximum + 1);
            sendApplication(data, 0);
            twfRequire(f.up_size == 0 && lineIsAlive(f.application),
                       "ineligible UDP input triggered request or closed association");
            sendApplication(data, maximum);
            expectTx(data, maximum);
            twfRequire(f.up_calls == 1 && f.request.options == options[o],
                       "maximum UDP split or framing controls ignored");
            uint8_t *wire   = memoryAllocate(maximum + 512);
            size_t   length = response(wire, maximum + 512, data, maximum, false);
            sendWire(wire, length);
            twfRequire(f.down_calls == 1 && f.down_size == maximum && memoryCompare(f.down, data, maximum) == 0,
                       "maximum UDP response did not remain one datagram");
            memoryFree(wire);
            memoryFree(data);
            end();
        }
    cJSON *strict_settings = configuration("aes-128-gcm", false);
    cJSON_AddStringToObject(strict_settings, "encrypted-counter-policy", "strict");
    begin(strict_settings, false);
    sendApplication("A", 1);
    vmessclient_lstate_t *ls  = lineGetState(f.carrier, f.client);
    ls->output_crypto.counter = UINT16_MAX - 1;
    sendApplication("B", 1);
    twfRequire(lineIsAlive(f.application) && ls->output_crypto.counter == UINT16_MAX, "last data nonce refused");
    sendApplication("C", 1);
    twfRequire(! lineIsAlive(f.application) && f.up_calls == 3, "nonce exhaustion wrapped or omitted bounded EOF");
    end();
}

static void terminalReentry(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        begin(configuration("aes-128-gcm", udp), udp);
        sendApplication("A", 1);
        f.boundary = 3;
        f.action   = 4;
        tunnelUpStreamFin(f.client, f.application);
        twfRequire(lineIsAlive(f.application) && f.finishes == 0 && f.transport_finishes == 0,
                   "terminal reentry reflected Finish toward a closed side");
        if (udp)
            twfRequire(! lineIsAlive(f.carrier), "nested terminal Finish left owned carrier alive");
        end();
    }
}

static void retainedBytesAndAllocation(void)
{
    for (unsigned action = 10; action <= 12; ++action)
    {
        begin(configuration("none", false), false);
        f.boundary      = 3;
        f.action        = action;
        size_t   length = action == 12 ? 32768 : kVmessClientMaxOrderBytes;
        uint8_t *data   = memoryAllocate(length);
        memorySet(data, 'a', length);
        sendApplication(data, length);
        memoryFree(data);
        twfRequire(lineIsAlive(f.application) == (action != 11), "logical overflow failed to close exactly its line");
        if (action != 11)
        {
            vmessclient_lstate_t *ls   = lineGetState(f.carrier, f.client);
            buffer_budget_cost_t  used = bufferbudgetGetUsage(&ls->upstream_budget);
            twfRequire(used.bytes == 0 && used.charge == 0 && used.entries == 0,
                       "transmit reservations survived drain");
        }
        end();
    }
}

static void finalIncomingNonce(void)
{
    const uint8_t *frames[] = {vector_last_counter, vector_last_counter_auth_aes, vector_last_counter_auth_chacha};
    const size_t   sizes[]  = {
        sizeof(vector_last_counter), sizeof(vector_last_counter_auth_aes), sizeof(vector_last_counter_auth_chacha)};
    for (unsigned mode = 0; mode < ARRAY_SIZE(frames); ++mode)
    {
        cJSON *settings = configuration(mode == 2 ? "chacha20-poly1305" : "aes-128-gcm", false);
        cJSON_AddStringToObject(settings, "encrypted-counter-policy", "strict");
        begin(settings, false);
        sendApplication("A", 1);
        uint8_t header[VMESS_RESPONSE_HEADER_SIZE];
        size_t  length = response(header, sizeof(header), NULL, 0, false);
        sendWire(header, length);
        vmessclient_lstate_t *ls = lineGetState(f.carrier, f.client);
        /* Install the independent vector's session at its final inbound ordinal,
         * avoiding a 65,535-record prelude in this lifecycle fixture. */
        vmessBodyDestroy(&ls->input_crypto);
        twfRequire(vmessBodyInit(&ls->input_crypto,
                                 vector_key,
                                 vector_iv,
                                 mode == 2 ? VMESS_SECURITY_CHACHA20_POLY1305 : VMESS_SECURITY_AES128_GCM,
                                 mode == 0 ? 1 : 29,
                                 1,
                                 false,
                                 kVmessCounterStrict) == kWCryptoOk,
                   "final inbound session setup failed");
        ls->input_crypto.counter = UINT16_MAX;
        sendWire(frames[mode], sizes[mode]);
        twfRequire(! lineIsAlive(f.application) && f.down_size == 4 && memoryCompare(f.down, "last", 4) == 0,
                   "final inbound data was lost or allowed nonce reuse");
        end();
    }
}

/* Inspect each submitted record, including the actual ordinal-zero prelude.
 * Captures are reset after each synchronous exchange; no giant golden corpus. */
static size_t openTx(vmess_body_ctx_t *decoder, size_t cursor, uint8_t *out, size_t capacity)
{
    const size_t prefix = vmessBodyLengthSize(decoder);
    uint32_t     body   = 0;
    twfRequire(cursor <= f.up_size && f.up_size - cursor >= prefix &&
                   vmessBodyLengthOpen(decoder, f.up + cursor, prefix, &body) == kWCryptoOk,
               "submitted record length did not authenticate");
    cursor += prefix;
    size_t written = 0;
    bool   eof     = false;
    twfRequire(f.up_size - cursor == body &&
                   vmessBodyOpen(decoder, f.up + cursor, body, out, capacity, &written, &eof) == kWCryptoOk && ! eof,
               "submitted record body did not authenticate or was split");
    return written;
}

static void runtimeCounterWrap(void)
{
    const char *names[] = {"aes-128-gcm", "chacha20-poly1305"};
    for (unsigned mode = 0; mode < ARRAY_SIZE(names); ++mode)
        for (unsigned udp = 0; udp < 2; ++udp)
        {
            cJSON *settings = configuration(names[mode], udp);
            cJSON_AddBoolToObject(settings, "authenticated-length", true);
            begin(settings, udp);
            vmess_body_ctx_t decoder = {0};
            enum
            {
                kRecords = 2 * 65536 + 2
            };
            for (unsigned ordinal = 0; ordinal < kRecords; ++ordinal)
            {
                sendApplication("W", 1);
                if (ordinal == 0)
                {
                    readRequest();
                    twfRequire(vmessBodyInit(&decoder,
                                             f.request.key,
                                             f.request.iv,
                                             f.request.security,
                                             f.request.options,
                                             f.request.command,
                                             false,
                                             kVmessCounterWrap) == kWCryptoOk,
                               "runtime peer body initialization failed");
                }
                uint8_t decoded[16], wire[256];
                twfRequire(openTx(&decoder, ordinal == 0 ? f.request_size : 0, decoded, sizeof(decoded)) == 1 &&
                               decoded[0] == 'W',
                           "runtime rollover TX lost plaintext");
                f.up_size     = 0;
                size_t length = response(wire, sizeof(wire), "R", 1, false);
                /* Split the length prefix at the boundary to retain pending-mask semantics. */
                if ((ordinal & 65535) >= 65534)
                {
                    sendWire(wire, 1);
                    sendWire(wire + 1, length - 1);
                }
                else
                    sendWire(wire, length);
                twfRequire(lineIsAlive(f.application) && f.down_size == 1 && f.down[0] == 'R',
                           "runtime rollover closed or changed response plaintext");
                f.down_size = 0;
            }
            vmessclient_tstate_t *ts = tunnelGetState(f.client);
            twfRequire(f.init_count == 1 && atomicLoadU64Relaxed(&ts->stats.tx_records) == kRecords &&
                           atomicLoadU64Relaxed(&ts->stats.rx_records) == kRecords &&
                           atomicLoadU64Relaxed(&ts->stats.tx_wraps) == 2 &&
                           atomicLoadU64Relaxed(&ts->stats.rx_wraps) == 2,
                       "runtime test did not prove two wraps on one association");
            vmessBodyDestroy(&decoder);
            end();
        }
}

static void terminationPolicy(void)
{
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned enabled = 0; enabled < 2; ++enabled)
        {
            cJSON *settings = configuration("aes-128-gcm", udp);
            cJSON_AddBoolToObject(settings, "send-termination", enabled != 0);
            begin(settings, udp);
            tunnelUpStreamFin(f.client, f.application);
            twfRequire(f.up_size == 0, "idle termination emitted a request");
            end();
            settings = configuration("aes-128-gcm", udp);
            cJSON_AddBoolToObject(settings, "send-termination", enabled != 0);
            begin(settings, udp);
            sendApplication("A", 1);
            size_t before = f.up_size;
            tunnelUpStreamFin(f.client, f.application);
            twfRequire((f.up_size > before) == (enabled != 0) && f.transport_finishes == 1,
                       "termination setting did not control final record");
            twfRequire(atomicLoadU64Relaxed(&((vmessclient_tstate_t *) tunnelGetState(f.client))
                                                 ->stats.reasons[kVmessClientReasonNormalClose]) == 1,
                       "paired close was counted more than once");
            end();
            settings = configuration("aes-128-gcm", udp);
            cJSON_AddBoolToObject(settings, "send-termination", enabled != 0);
            cJSON_AddStringToObject(settings, "encrypted-counter-policy", "strict");
            begin(settings, udp);
            sendApplication("A", 1);
            vmessclient_lstate_t *ls  = lineGetState(f.carrier, f.client);
            ls->output_crypto.counter = UINT16_MAX;
            before                    = f.up_size;
            sendApplication("B", 1);
            twfRequire(! lineIsAlive(f.application) && (f.up_size > before) == (enabled != 0),
                       "strict exhaustion ignored termination policy");
            end();
            settings = configuration("aes-128-gcm", udp);
            cJSON_AddBoolToObject(settings, "send-termination", enabled != 0);
            begin(settings, udp);
            sendApplication("A", 1);
            uint8_t wire[256];
            size_t  length = response(wire, sizeof(wire), NULL, 0, true);
            sendWire(wire, length);
            twfRequire(! lineIsAlive(f.application), "termination option refused incoming authenticated EOF");
            end();
        }
}

static void packetAddress(void)
{
    const char   *names[] = {"aes-128-gcm", "chacha20-poly1305", "none"};
    const uint8_t v4[]    = {1, 127, 0, 0, 1, 1, 187};
    const uint8_t v6[]    = {2, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187};
    for (unsigned mode = 0; mode < ARRAY_SIZE(names); ++mode)
        for (unsigned ipv6 = 0; ipv6 < 2; ++ipv6)
        {
            cJSON *settings = configuration(names[mode], true);
            cJSON_AddStringToObject(settings, "packet-encoding", "packetaddr");
            if (ipv6)
                cJSON_ReplaceItemInObjectCaseSensitive(settings, "address", cJSON_CreateString("2001:db8::1"));
            begin(settings, true);
            sendApplication(NULL, 0);
            readRequest();
            twfRequire(vmessRequestIsPacketAddr(&f.request), "packetaddr did not use exact magic request destination");
            vmess_body_ctx_t decoder = {0};
            twfRequire(vmessBodyInit(&decoder,
                                     f.request.key,
                                     f.request.iv,
                                     f.request.security,
                                     f.request.options,
                                     2,
                                     false,
                                     kVmessCounterWrap) == kWCryptoOk,
                       "packetaddr decoder setup");
            uint8_t        plain[65536];
            const uint8_t *envelope      = ipv6 ? v6 : v4;
            size_t         envelope_size = ipv6 ? sizeof(v6) : sizeof(v4);
            size_t         got           = openTx(&decoder, f.request_size, plain, sizeof(plain));
            twfRequire(got == envelope_size && memoryCompare(plain, envelope, got) == 0,
                       "packetaddr empty datagram envelope differs from independent vector");
            f.up_size = 0;
            uint8_t wire[66048];
            size_t  length = response(wire, sizeof(wire), envelope, envelope_size, false);
            sendWire(wire, length);
            twfRequire(f.down_calls == 1 && f.datagram_sizes[0] == 0 && lineIsAlive(f.application),
                       "packetaddr header-only record did not deliver empty datagram");
            vmessclient_lstate_t *ls      = lineGetState(f.carrier, f.client);
            size_t                maximum = vmessBodyMaxPlaintext(&ls->output_crypto) - envelope_size;
            uint8_t              *data    = memoryAllocate(maximum + 1);
            memorySet(data, 'D', maximum + 1);
            sendApplication(data, maximum + 1);
            twfRequire(f.up_size == 0, "oversized packetaddr input emitted wire bytes");
            sendApplication(data, maximum);
            got = openTx(&decoder, 0, plain, sizeof(plain));
            twfRequire(got == maximum + envelope_size && memoryCompare(plain, envelope, envelope_size) == 0 &&
                           memoryCompare(plain + envelope_size, data, maximum) == 0,
                       "packetaddr maximum was split");
            f.up_size = 0;
            length    = response(wire, sizeof(wire), plain, got, false);
            sendWire(wire, length);
            twfRequire(f.down_calls == 2 && f.datagram_sizes[1] == maximum && memoryCompare(f.down, data, maximum) == 0,
                       "near-limit packetaddr reply changed payload");
            plain[1] ^= 1;
            length = response(wire, sizeof(wire), plain, envelope_size, false);
            sendWire(wire, length);
            vmessclient_tstate_t *ts = tunnelGetState(f.client);
            twfRequire(f.down_calls == 2 && lineIsAlive(f.application) &&
                           atomicLoadU64Relaxed(&ts->stats.reasons[kVmessClientReasonUnexpectedSource]) == 1,
                       "unexpected packetaddr source was delivered or closed association");
            length = response(wire, sizeof(wire), "bad", 3, false);
            sendWire(wire, length);
            twfRequire(! lineIsAlive(f.application) && ! lineIsAlive(f.carrier),
                       "malformed packetaddr envelope survived");
            memoryFree(data);
            vmessBodyDestroy(&decoder);
            end();
        }
    cJSON *settings = configuration("aes-128-gcm", true);
    cJSON_AddStringToObject(settings, "packet-encoding", "packetaddr");
    cJSON_ReplaceItemInObjectCaseSensitive(settings, "address", cJSON_CreateString("unresolved.example.test"));
    begin(settings, true);
    twfRequire(! lineIsAlive(f.application) && f.init_count == 0, "packetaddr unresolved domain opened a transport");
    end();
    /* Dynamic TCP retains its ordinary destination, even when packetaddr is selected. */
    settings = configuration("aes-128-gcm", false);
    cJSON_ReplaceItemInObjectCaseSensitive(settings, "protocol", cJSON_CreateString("dest_context->protocol"));
    cJSON_AddStringToObject(settings, "packet-encoding", "packetaddr");
    begin(settings, false);
    sendApplication("A", 1);
    expectTx("A", 1);
    end();
}

static void packetAddressReentry(void)
{
    const uint8_t envelope[] = {1, 127, 0, 0, 1, 1, 187, 'R'};
    for (unsigned boundary = 1; boundary <= 4; ++boundary)
        for (unsigned action = 3; action <= 4; ++action)
        {
            cJSON *settings = configuration("aes-128-gcm", true);
            cJSON_AddStringToObject(settings, "packet-encoding", "packetaddr");
            initial_action = boundary == 1 ? action : 0;
            begin(settings, true);
            initial_action = 0;
            if (boundary != 1)
            {
                f.boundary = boundary;
                f.action   = action;
                if (boundary == 2)
                    tunnelDownStreamEst(f.client, f.carrier);
                else
                {
                    sendApplication("A", 1);
                    if (boundary == 4)
                    {
                        uint8_t wire[256];
                        size_t  length = response(wire, sizeof(wire), envelope, sizeof(envelope), false);
                        sendWire(wire, length);
                    }
                }
            }
            twfRequire(! lineIsAlive(f.application) && ! lineIsAlive(f.carrier),
                       "packetaddr reentry retained an owned carrier");
            end();
        }
}

static api_result_t queryStats(const char *request, size_t response_limit, size_t working_limit, uint64_t deadline)
{
    const node_api_operation_t *operation = nodeApiFind(f.client, "stats");
    twfRequire(operation != NULL && operation->read_only && operation->execution == kNodeApiCallingWorker,
               "stats operation has wrong registry metadata");
    node_api_call_context_t context = {.operation                = "stats",
                                       .principal                = "fixture",
                                       .deadline_ms              = deadline,
                                       .max_response_body_size   = response_limit,
                                       .working_memory_allowance = working_limit};
    return operation->handler(f.client, bytes(f.application, request, strlen(request)), &context);
}

typedef struct stats_publication_s
{
    vmessclient_tstate_t *state;
    atomic_bool           stop;
} stats_publication_t;

static void *publishStats(void *argument)
{
    stats_publication_t *publication = argument;
    while (! atomicLoadExplicit(&publication->stop, memory_order_acquire))
        atomicIncU64Relaxed(&publication->state->stats.tx_records);
    return NULL;
}

static void statsApi(void)
{
    cJSON *settings = configuration("auto", true);
    cJSON_AddBoolToObject(settings, "send-termination", false);
    cJSON_AddStringToObject(settings, "packet-encoding", "packetaddr");
    begin(settings, true);
    sendApplication("A", 1);
    vmessclient_tstate_t *ts = tunnelGetState(f.client);
    atomicStoreU64Relaxed(&ts->stats.tx_application_bytes, UINT64_MAX);
    api_result_t result = queryStats(" {} \n", 4096, 128 * 1024, nodeApiNowMs() + 1000);
    twfRequire(result.result_code == kApiResultOk && result.buffer != NULL, "registered stats dispatch refused");
    char   text[4097];
    size_t length = sbufGetLength(result.buffer);
    twfRequire(length < sizeof(text), "stats output bound");
    memoryCopy(text, sbufGetRawPtr(result.buffer), length);
    text[length] = 0;
    cJSON *body  = cJSON_Parse(text);
    twfRequire(
        body != NULL && strstr(text, "18446744073709551615") != NULL &&
            strstr(text, "\"send_termination\":false") != NULL && strstr(text, "\"security_auto\":true") != NULL &&
            strstr(text, "\"active_applications\":\"1\"") != NULL && strstr(text, "\"active_carriers\":\"1\"") != NULL,
        "stats lost uint64 precision or effective settings/counts");
    cJSON_Delete(body);
    lineReuseBuffer(f.application, result.buffer);
    const char *invalid[] = {"[]", "{\"reset\":true}", "{}x", "{\"a\":{}}", "{\"a\":1,\"a\":1}", "{\"a\\u0000x\":1}"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        result = queryStats(invalid[i], 4096, 128 * 1024, nodeApiNowMs() + 1000);
        twfRequire(result.result_code == kApiResultError && result.buffer == NULL,
                   "stats accepted nonempty/invalid body");
    }
    result = queryStats("{}", 1, 128 * 1024, nodeApiNowMs() + 1000);
    twfRequire(result.result_code == kApiResultError && result.buffer == NULL, "stats ignored response allowance");
    result = queryStats("{}", 4096, 4096, nodeApiNowMs() + 1000);
    twfRequire(result.result_code == kApiResultError && result.buffer == NULL, "stats ignored allocation allowance");
    result = queryStats("{}", 4096, 128 * 1024, nodeApiNowMs());
    twfRequire(result.result_code == kApiResultError && result.buffer == NULL, "stats ignored deadline");
    buffer_pool_fit_t result_fit;
    twfRequire(bufferpoolQueryBestFit(lineGetBufferPool(f.application), length, 0, &result_fit),
               "stats result geometry unavailable");
    size_t exact_working = 4608 + result_fit.allocation_charge;
    result               = queryStats("{}", 4096, exact_working - 1, nodeApiNowMs() + 1000);
    twfRequire(result.result_code == kApiResultError && result.buffer == NULL,
               "stats omitted fixed metadata from working-memory charge");
    result = queryStats("{}", 4096, exact_working, nodeApiNowMs() + 1000);
    twfRequire(result.result_code == kApiResultOk && result.buffer != NULL,
               "stats rejected inclusive fixed-plus-result working budget");
    lineReuseBuffer(f.application, result.buffer);
    stats_publication_t publication = {.state = ts};
    atomic_init(&publication.stop, false);
    pthread_t publisher;
    twfRequire(pthread_create(&publisher, NULL, publishStats, &publication) == 0, "stats publisher creation failed");
    for (unsigned i = 0; i < 32; ++i)
    {
        result = queryStats("{}", 4096, 128 * 1024, nodeApiNowMs() + 1000);
        twfRequire(result.result_code == kApiResultOk && result.buffer != NULL,
                   "stats refused concurrent synchronized publication");
        lineReuseBuffer(f.application, result.buffer);
    }
    atomicStoreExplicit(&publication.stop, true, memory_order_release);
    twfRequire(pthread_join(publisher, NULL) == 0, "stats publisher join failed");
    end();
}

int main(void)
{
    initWLibc();
    logger_t *logger = loggerCreate();
    loggerSetLevel(logger, LOG_LEVEL_ERROR);
    setNetworkLogger(logger);
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    frandInit();
    twfRequire(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    TEST_RUN_CASE(bootstrap);
    TEST_RUN_CASE(timing);
    TEST_RUN_CASE(modesAndSplits);
    TEST_RUN_CASE(reentryAndPressure);
    TEST_RUN_CASE(closeAndMalformed);
    TEST_RUN_CASE(destinations);
    TEST_RUN_CASE(reservedPacketAddressTarget);
    TEST_RUN_CASE(frameBoundaries);
    TEST_RUN_CASE(terminalReentry);
    TEST_RUN_CASE(retainedBytesAndAllocation);
    TEST_RUN_CASE(finalIncomingNonce);
    TEST_RUN_CASE(runtimeCounterWrap);
    TEST_RUN_CASE(terminationPolicy);
    TEST_RUN_CASE(packetAddress);
    TEST_RUN_CASE(packetAddressReentry);
    TEST_RUN_CASE(statsApi);
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    return 0;
}
