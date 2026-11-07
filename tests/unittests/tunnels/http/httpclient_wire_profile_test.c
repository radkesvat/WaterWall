/*
 * Covers: HttpClient's bounded HTTP/1 chunks and Chrome-reference HTTP/2 startup/DATA framing.
 * Setup: Production constructor and callbacks, worker-zero pools, captured next-neighbour buffers,
 *        an nghttp2 peer, borrowed application lines, and HttpClient-owned HTTP/2 carriers.
 * Checks: Exact framing/payload bytes, settings and windows, one request stream, WebSocket/h2c
 *         settings, nested-payload FIFO order, custom-upgrade bypass, flow-control resumption,
 *         readiness/provider limits, reentrant Finish, retained uploads, fixed deadlines,
 *         timer refusal/quiescence, pressure, cancellation and exact line ownership.
 * Limits: No TLS record, network-packet, browser traffic timing, or multi-stream equivalence claims.
 * CTest: waterwall.httpclient_wire_profile_unit
 */
#include "HttpClient/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "wfrand.h"
#include "wloop_internal.h"

enum
{
    kWireCapacity = 256 * 1024,
    kMaxWrites    = 256,
    kH1BodyLimit  = 16372,
    kH2BodyLimit  = 16375,
    kLargeBody    = 65536,
};

static const uint8_t kChromeSettings[] = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, /* HEADER_TABLE_SIZE = 65536 */
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, /* ENABLE_PUSH = 0 */
    0x00, 0x04, 0x00, 0x60, 0x00, 0x00, /* INITIAL_WINDOW_SIZE = 6 MiB */
    0x00, 0x06, 0x00, 0x04, 0x00, 0x00, /* MAX_HEADER_LIST_SIZE = 256 KiB */
};
static const uint8_t kConnectSetting[] = {0x00, 0x08, 0x00, 0x00, 0x00, 0x01};
static const char    kPreface[]        = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

typedef struct fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    cJSON           *settings;
    node_t           node;
    tunnel_t        *prev, *http, *next;
    line_t          *line, *carrier;
    tunnel_chain_t  *chain;
    master_pool_t   *context_master;
    generic_pool_t  *contexts;
    uint8_t          wire[kWireCapacity];
    uint32_t         lengths[kMaxWrites];
    size_t           wire_length, writes, peer_offset;
    bool             nested_payload, finish_first;
    bool             h2_startup_payload;
    bool             h2_finish_during_data, h2_fin_in_progress;
    bool             custom_startup_reply, raw_up_reentry, raw_down_reentry, raw_down_finish;
    bool             pending_refill, expire_drain_output;
    nghttp2_session *peer;
    size_t           received_body;
    unsigned         request_streams, end_streams;
} fixture_t;

static fixture_t *active;
static uint64_t   now_us;
static unsigned   timer_add_calls, timer_reset_calls;
static uint32_t   timer_reset_ms;
static bool       refuse_timer_add, refuse_timer_reset;

uint64_t __wrap_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void)
{
    return now_us;
}

wtimer_t *__real_wtimerAdd(wloop_t *, wtimer_cb, uint32_t, uint32_t);
wtimer_t *__wrap_wtimerAdd(wloop_t *, wtimer_cb, uint32_t, uint32_t);
wtimer_t *__wrap_wtimerAdd(wloop_t *loop, wtimer_cb callback, uint32_t timeout_ms, uint32_t repeat)
{
    ++timer_add_calls;
    return refuse_timer_add ? NULL : __real_wtimerAdd(loop, callback, timeout_ms, repeat);
}

bool __real_wtimerReset(wtimer_t *, uint32_t);
bool __wrap_wtimerReset(wtimer_t *, uint32_t);
bool __wrap_wtimerReset(wtimer_t *timer, uint32_t timeout_ms)
{
    ++timer_reset_calls;
    timer_reset_ms = timeout_ms;
    return ! refuse_timer_reset && __real_wtimerReset(timer, timeout_ms);
}

static void captureInit(tunnel_t *next, line_t *line)
{
    twfNextInit(next, line);
    active->carrier = line;
    if (line != active->line)
    {
        routing_context_t *routing = lineGetRoutingContext(line);
        twfRequire(routing->src_ctx.port == 12345 && routing->dest_ctx.port == 23456 &&
                       routing->local_listener_port == 34567 && routing->peer_source_port == 45678 &&
                       ip_addr_cmp(&routing->src_ctx.ip_address, &active->line->routing_context.src_ctx.ip_address) &&
                       ip_addr_cmp(&routing->dest_ctx.ip_address, &active->line->routing_context.dest_ctx.ip_address),
                   "carrier Init lost routing context or source-port metadata");
        twfRequire(lineHasAuthenticatedCredentials(line, "fixture-user", "fixture-password"),
                   "carrier Init lost application authentication markers");
        lineRef(line); /* Inspect the owned carrier after HttpClient destroys it. */
    }
}

static sbuf_t *textPayload(fixture_t *f, const char *text)
{
    uint32_t length = (uint32_t) strlen(text);
    sbuf_t  *buf    = bufferpoolGetBestFit(f->env.pool, length, kHttpClientRequiredPaddingLeft);
    sbufSetLength(buf, length);
    sbufWrite(buf, text, length);
    return buf;
}

static sbuf_t *chargedPayload(size_t charge, const char *text)
{
    const uint32_t padding = 64;
    sbuf_t        *buf     = twfTrackAcquired(
        sbufCreateWithPadding((uint32_t) (charge - sizeof(sbuf_t) - kSbufAllocationAlignment - padding), padding));
    twfRequire(sbufGetQueueCharge(buf) == charge, "fixture charge was rounded unexpectedly");
    sbufSetLength(buf, (uint32_t) strlen(text));
    sbufWrite(buf, text, (uint32_t) strlen(text));
    return buf;
}

static void captureRawDown(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    fixture_t *f = active;
    twfPrevPayload(prev, line, buf);
    if (f->raw_down_finish)
    {
        f->raw_down_finish = false;
        tunnelUpStreamFin(f->http, line);
        return;
    }
    if (f->raw_down_reentry)
    {
        f->raw_down_reentry = false;
        twfRequire(tunnelIsActiveForLine(f->http, line), "custom upgrade retired during downstream drain");
        tunnelUpStreamPayload(f->http, line, textPayload(f, "EF"));
        tunnelDownStreamPayload(f->http, line, textPayload(f, "tail"));
    }
}

static void ownerFinish(tunnel_t *t, line_t *line)
{
    discard t;
    ++active->trace.prev_finish;
    lineDestroy(line);
}

static sbuf_t *payload(fixture_t *f, uint32_t length, bool no_tail)
{
    sbuf_t *buf = bufferpoolGetBestFit(f->env.pool, length, kHttpClientRequiredPaddingLeft);
    if (no_tail)
    {
        uint32_t skip = sbufGetWritableCapacity(buf) - length;
        sbufSetLength(buf, skip);
        sbufShiftRight(buf, skip);
    }
    sbufSetLength(buf, length);
    for (uint32_t i = 0; i < length; ++i)
        sbufGetMutablePtr(buf)[i] = (uint8_t) (i % 251);
    return buf;
}

static void capture(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    fixture_t *f = active;
    discard    next;
    uint32_t   length = sbufGetLength(buf);
    twfRequire(f->writes < kMaxWrites && length <= kWireCapacity - f->wire_length, "capture overflow");
    f->lengths[f->writes++] = length;
    memoryCopy(f->wire + f->wire_length, sbufGetRawPtr(buf), length);
    f->wire_length += length;
    lineReuseBuffer(line, buf);
    if (f->expire_drain_output)
    {
        httpclient_lstate_t *ls = lineGetState(line, f->http);
        twfRequire(ls->close_drain_deadline_ms != 0, "final output preceded the drain deadline");
        now_us = ls->close_drain_deadline_ms * 1000;
    }
    if (f->pending_refill)
    {
        f->pending_refill       = false;
        httpclient_lstate_t *ls = lineGetState(line, f->http);
        twfRequire(bufferbudgetGetUsage(&ls->pending_up_budget).charge == kHttpClientPendingMaxCharge - 192,
                   "readiness replay did not release exactly the dispatched buffer's charge");
        httpclientTunnelUpStreamPayload(f->http, f->line, chargedPayload(192, "nested!"));
        twfRequire(lineIsAlive(line) && f->writes == 1 && bufferqueueGetEntryCount(&ls->pending_up) == 2 &&
                       bufferbudgetGetUsage(&ls->pending_up_budget).charge == kHttpClientPendingMaxCharge,
                   "nested readiness input overtook the backlog or failed to use released capacity");
    }
    else if (f->h2_finish_during_data)
    {
        f->h2_finish_during_data = false;
        httpclient_lstate_t *ls  = lineGetState(line, f->http);
        twfRequire(f->writes == 1 && length == 9 + kH2BodyLimit && f->wire[3] == NGHTTP2_DATA,
                   "reentrant H2 close did not interrupt the first partial DATA provider read");
        twfRequire(ls->h2_data.active != NULL && ls->h2_data.head != NULL,
                   "reentrant H2 close did not retain both active and pending providers");
        twfRequireEqualU32(g_twf_buffers.live_count, 2, "H2 provider payloads were released before close");
        httpclientTunnelDownStreamFinish(f->http, line);
        twfRequire(! lineIsAlive(line), "owned H2 carrier survived its downstream Finish");
    }
    else if (f->custom_startup_reply)
    {
        f->custom_startup_reply = false;
        tunnelUpStreamPayload(f->http, line, textPayload(f, "Q"));
        tunnelDownStreamPayload(
            f->http,
            line,
            textPayload(f, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: unit\r\n\r\nS"));
        twfRequire(tunnelIsActiveForLine(f->http, line), "custom upgrade retired inside its opening write");
    }
    else if (f->raw_up_reentry)
    {
        f->raw_up_reentry = false;
        twfRequire(tunnelIsActiveForLine(f->http, line), "custom upgrade retired during upstream drain");
        tunnelUpStreamPayload(f->http, line, textPayload(f, "GH"));
        tunnelDownStreamPayload(f->http, line, textPayload(f, "last"));
    }
    else if (f->finish_first)
    {
        f->finish_first = false;
        httpclientTunnelDownStreamFinish(f->http, line);
    }
    else if (f->h2_startup_payload)
    {
        f->h2_startup_payload = false;
        httpclientTunnelUpStreamPayload(f->http, f->line, payload(f, 20000, false));
    }
    else if (f->nested_payload)
    {
        f->nested_payload = false;
        sbuf_t *nested    = bufferpoolGetBestFit(f->env.pool, 7, kHttpClientRequiredPaddingLeft);
        sbufSetLength(nested, 7);
        sbufWrite(nested, "nested!", 7);
        httpclientTunnelUpStreamPayload(f->http, f->line, nested);
    }
}

static void setupWithStartupAction(fixture_t *f, const char *json, unsigned action)
{
    static char node_name[] = "http-wire-test";
    static char node_type[] = "HttpClient";
    memoryZero(f, sizeof(*f));
    active = f;
    now_us          = UINT64_C(1000123456);
    timer_add_calls = timer_reset_calls = 0;
    refuse_timer_add = refuse_timer_reset = false;
    twfWorkerEnvSetup(&f->env, 65536, 96);
    f->context_master = masterpoolCreateWithCapacity(8);
    f->contexts       = genericpoolCreateWithDefaultAllocatorAndCapacity(f->context_master, sizeof(context_t), 8);
    GSTATE.shortcut_context_pools = &f->contexts;
    f->settings = cJSON_Parse(json);
    twfRequire(f->settings != NULL, "invalid fixture settings");
    f->node = (node_t) {.name = node_name, .type = node_type, .node_settings_json = f->settings};
    f->prev = twfCreatePrevTunnel(&f->trace);
    f->http = httpclientTunnelCreate(&f->node);
    f->next = twfCreateNextTunnel(&f->trace);
    twfRequire(f->http != NULL, "HttpClient construction failed");
    f->prev->fnFinD     = ownerFinish;
    f->next->fnPayloadU = capture;
    f->next->fnInitU    = captureInit;
    tunnelBind(f->prev, f->http);
    tunnelBind(f->http, f->next);
    f->prev->chain_index = 0;
    f->http->chain_index = 1;
    f->next->chain_index = 2;
    twfLinePoolSetup(&f->lines, f->http->lstate_size, 4);
    f->chain                = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    f->chain->workers_count = 1;
    f->chain->line_pools[0] = f->lines.pools[0];
    f->http->chain          = f->chain;
    f->line = twfLinePoolCreateLine(&f->lines);
    lineRef(f->line); /* The fixture owns the line; retain allocation across reentrant owner Finish. */
    routing_context_t *routing = lineGetRoutingContext(f->line);
    twfRequire(addresscontextSetIpAddressPortProtocol(&routing->src_ctx, "127.0.0.9", 12345, IPPROTO_TCP) &&
                   addresscontextSetIpAddressPortProtocol(&routing->dest_ctx, "127.0.0.10", 23456, IPPROTO_TCP),
               "fixture routing context initialization failed");
    routing->local_listener_port = 34567;
    routing->peer_source_port    = 45678;
    lineAddAuthenticatedCredentials(f->line, "fixture-user", "fixture-password");
    f->h2_startup_payload = action == 1;
    f->finish_first       = action == 2;
    f->custom_startup_reply = action == 3;
    httpclientTunnelUpStreamInit(f->http, f->line);
    twfRequire(lineIsAlive(f->line) == (action != 2), "startup callback did not preserve the expected line lifetime");
}

static void setup(fixture_t *f, const char *json)
{
    setupWithStartupAction(f, json, 0);
}

static void resetWire(fixture_t *f)
{
    f->wire_length = f->writes = f->peer_offset = 0;
}

static void teardown(fixture_t *f)
{
    if (f->carrier != f->line && lineIsAlive(f->carrier))
        httpclientTunnelDownStreamFinish(f->http, f->carrier);
    httpclient_lstate_t *ls = lineGetState(f->line, f->http);
    if (ls->tunnel != NULL)
        httpclientLinestateDestroy(ls);
    if (lineIsAlive(f->line))
        lineDestroy(f->line);
    twfRequireLineStateZeroed(f->line, f->http, "HttpClient state remained at line release");
    twfRequireEqualU32(twfLineRefCount(f->line), 1, "HttpClient retained an application reference");
    lineUnref(f->line);
    if (f->carrier != f->line)
    {
        twfRequire(! lineIsAlive(f->carrier), "HttpClient retained an owned carrier");
        twfRequireLineStateZeroed(f->carrier, f->http, "HttpClient retained carrier state");
        twfRequireEqualU32(twfLineRefCount(f->carrier), 1, "HttpClient retained a carrier reference");
        lineUnref(f->carrier);
    }
    if (f->peer != NULL)
        nghttp2_session_del(f->peer);
    twfRequireNoLeakedBuffers();
    twfRequire(wloopNTimers(f->env.loop) == 0, "HttpClient retained a drain timer");
    twfLinePoolTeardown(&f->lines);
    httpclientTunnelDestroy(f->http, wwLifecycleStartupRollback());
    tunnelDestroy(f->prev);
    tunnelDestroy(f->next);
    cJSON_Delete(f->settings);
    memoryFree(f->chain);
    GSTATE.shortcut_context_pools = NULL;
    genericpoolDestroy(f->contexts);
    masterpoolMakeEmpty(f->context_master);
    masterpoolDestroy(f->context_master);
    twfWorkerEnvTeardown(&f->env);
    active = NULL;
}

static void checkChunks(const fixture_t *f, uint32_t body_length, bool nested)
{
    size_t wire_offset = 0, body_offset = 0;
    for (size_t i = 0; i < f->writes; ++i)
    {
        const uint8_t *wire   = f->wire + wire_offset;
        uint32_t       length = f->lengths[i], chunk = 0, prefix = 0;
        while (prefix < length && wire[prefix] != '\r')
        {
            uint8_t  c     = wire[prefix++];
            unsigned digit = c >= '0' && c <= '9'   ? c - '0'
                             : c >= 'a' && c <= 'f' ? c - 'a' + 10
                             : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                                    : 16;
            twfRequire(digit < 16 && prefix <= 8, "invalid chunk size prefix");
            chunk = chunk * 16 + digit;
        }
        twfRequire(prefix > 0 && prefix + 2 <= length && wire[prefix] == '\r' && wire[prefix + 1] == '\n',
                   "split or absent chunk prefix");
        prefix += 2;
        twfRequire(chunk > 0 && chunk <= kH1BodyLimit && prefix + chunk + 2 == length,
                   "output is not one complete bounded chunk");
        twfRequire(wire[length - 2] == '\r' && wire[length - 1] == '\n', "chunk tail separated from body");
        for (uint32_t j = 0; j < chunk; ++j, ++body_offset)
        {
            twfRequire(body_offset < body_length + (nested ? 7U : 0U), "chunk body exceeds submitted bytes");
            uint8_t expected = body_offset < body_length ? (uint8_t) (body_offset % 251)
                                                         : (uint8_t) "nested!"[body_offset - body_length];
            twfRequire(body_offset < body_length + (nested ? 7U : 0U) && wire[prefix + j] == expected,
                       "chunking changed payload bytes or nested FIFO order");
        }
        wire_offset += length;
    }
    twfRequire(body_offset == body_length + (nested ? 7U : 0U), "chunking lost payload bytes");
    twfRequire(wire_offset == f->wire_length, "unaccounted chunk bytes");
}

static void caseHttp1Chunks(uint32_t length, bool no_tail)
{
    twfSetCase("HttpClient complete bounded H1 chunk callbacks");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":1}");
    resetWire(&f);
    httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, length, no_tail));
    twfRequire(f.writes == (length + kH1BodyLimit - 1U) / kH1BodyLimit, "wrong H1 chunk count");
    checkChunks(&f, length, false);
    resetWire(&f);
    httpclientTunnelUpStreamFinish(f.http, f.line);
    twfRequire(f.writes == 1 && f.wire_length == 5 && memoryCompare(f.wire, "0\r\n\r\n", 5) == 0,
               "Finish did not emit exactly one complete terminal chunk");
    twfRequire(f.trace.next_finish == 1 && f.trace.prev_finish == 0,
               "Finish reflected or failed to close its next direction");
    teardown(&f);
}

static void caseHttp1NestedPayload(void)
{
    twfSetCase("HttpClient H1 nested payload waits for the original body");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":1}");
    resetWire(&f);
    f.nested_payload = true;
    httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, kLargeBody, true));
    twfRequire(lineIsAlive(f.line), "nested H1 payload closed the line");
    checkChunks(&f, kLargeBody, true);
    teardown(&f);
}

static void caseHttp1FinishDuringBody(void)
{
    twfSetCase("HttpClient H1 first-chunk Finish releases original remainder");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":1}");
    resetWire(&f);
    f.finish_first = true;
    httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, kLargeBody, true));
    twfRequire(! lineIsAlive(f.line), "fixture owner did not close the line");
    twfRequire(f.writes == 1 && f.trace.prev_finish == 1 && f.trace.next_finish == 0,
               "body output continued or Finish reflected after reentrant close");
    twfRequireNoLeakedBuffers();
    teardown(&f);
}

static void setupPending(fixture_t *f, unsigned mode)
{
    setup(f,
          mode == 1   ? "{\"host\":\"unit.test\",\"http-version\":\"both\",\"upgrade\":true}"
          : mode == 2 ? "{\"host\":\"unit.test\",\"http-version\":1,\"websocket\":true}"
                      : "{\"host\":\"unit.test\",\"http-version\":1}");
    httpclient_lstate_t *ls = lineGetState(f->carrier, f->http);
    if (mode == 0)
        ls->runtime_proto = kHttpClientRuntimeUnknown;
    else if (mode == 3)
    {
        ls->runtime_proto = kHttpClientRuntimeHttp2;
        ls->h2_stream_id  = 0;
    }
    resetWire(f);
}

static void casePendingLimits(unsigned mode, bool charge_limit)
{
    twfSetCase(charge_limit ? "HttpClient readiness rejects excess allocation charge, including empty input"
                            : "HttpClient readiness admits exact byte limit and closes on one excess byte");
    fixture_t f;
    setupPending(&f, mode);
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    sbuf_t              *first =
        charge_limit ? chargedPayload(kHttpClientPendingMaxCharge, "") : payload(&f, kHttpClientPendingMaxBytes, false);
    size_t charge = sbufGetQueueCharge(first);
    httpclientTunnelUpStreamPayload(f.http, f.line, first);
    twfRequire(lineIsAlive(f.line) && f.writes == 0 && bufferqueueGetEntryCount(&ls->pending_up) == 1,
               "readiness queue rejected its inclusive limit or sent before ready");
    buffer_budget_cost_t used = bufferbudgetGetUsage(&ls->pending_up_budget);
    twfRequire(used.bytes == (charge_limit ? 0 : kHttpClientPendingMaxBytes) && used.charge == charge,
               "readiness queue did not account its retained input");
    twfRequire(httpclientTransportFlushPendingUp(f.http, f.carrier, ls) && f.writes == 0 &&
                   bufferqueueGetEntryCount(&ls->pending_up) == 1 &&
                   bufferbudgetGetUsage(&ls->pending_up_budget).charge == charge,
               "not-ready flush changed or uncharged the backlog");
    httpclientTunnelUpStreamPayload(f.http, f.line, textPayload(&f, charge_limit ? "" : "x"));
    twfRequire(! lineIsAlive(f.line) && f.writes == 0 && f.trace.prev_finish == 1 && f.trace.next_finish == 1,
               "readiness refusal did not close exactly the affected connection");
    twfRequireLineStateZeroed(f.line, f.http, "readiness refusal retained buffers or budget accounting");
    teardown(&f);
}

static void casePendingWebSocketReplay(bool finish)
{
    twfSetCase(finish ? "HttpClient readiness replay stops and releases its backlog after Finish"
                      : "HttpClient readiness replay preserves FIFO and reuses popped charge during nested input");
    fixture_t f;
    setupPending(&f, 2);
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    httpclientTunnelUpStreamPayload(f.http, f.line, chargedPayload(192, "first!"));
    httpclientTunnelUpStreamPayload(f.http, f.line, chargedPayload(kHttpClientPendingMaxCharge - 192, "second!"));
    twfRequire(bufferbudgetGetUsage(&ls->pending_up_budget).charge == kHttpClientPendingMaxCharge,
               "fixture did not fill readiness charge allowance");
    ls->websocket_active = true;
    f.pending_refill     = ! finish;
    f.finish_first       = finish;
    bool ok              = httpclientTransportFlushPendingUp(f.http, f.carrier, ls);
    if (finish)
    {
        twfRequire(! ok && ! lineIsAlive(f.line) && f.writes == 1 && f.trace.prev_finish == 1 &&
                       f.trace.next_finish == 0,
                   "readiness replay continued or reflected Finish after close");
        twfRequireLineStateZeroed(f.line, f.http, "readiness replay close retained its budget/state");
    }
    else
    {
        const char *expected[] = {"first!", "second!", "nested!"};
        twfRequire(ok && f.writes == ARRAY_SIZE(expected), "readiness replay lost a queued WebSocket payload");
        size_t offset = 0;
        for (size_t i = 0; i < ARRAY_SIZE(expected); ++i)
        {
            const uint8_t *frame  = f.wire + offset;
            size_t         length = strlen(expected[i]);
            twfRequire(f.lengths[i] == length + 6 && frame[0] == 0x82 && frame[1] == (0x80 | length),
                       "readiness replay changed WebSocket framing");
            for (size_t j = 0; j < length; ++j)
                twfRequire((frame[6 + j] ^ frame[2 + (j % 4)]) == (uint8_t) expected[i][j],
                           "nested WebSocket input overtook older readiness data");
            offset += f.lengths[i];
        }
        twfRequire(! ls->pending_up_draining && bufferqueueGetEntryCount(&ls->pending_up) == 0,
                   "completed replay kept its draining guard or backlog");
        bufferbudgetAssertEmpty(&ls->pending_up_budget);
    }
    teardown(&f);
}

static void casePendingManyBuffers(void)
{
    twfSetCase("HttpClient readiness limits bytes and charge rather than buffer count");
    fixture_t f;
    setupPending(&f, 0);
    for (unsigned i = 0; i < 32; ++i)
        httpclientTunnelUpStreamPayload(f.http, f.line, textPayload(&f, ""));
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    twfRequire(lineIsAlive(f.line) && bufferqueueGetEntryCount(&ls->pending_up) == 32 &&
                   bufferbudgetGetUsage(&ls->pending_up_budget).bytes == 0 &&
                   bufferbudgetGetUsage(&ls->pending_up_budget).charge != 0,
               "empty queued buffers were uncharged or rejected by count");
    httpclientTunnelUpStreamFinish(f.http, f.line);
    twfRequire(f.trace.next_finish == 1 && f.trace.prev_finish == 0,
               "readiness teardown reflected Finish toward its sender");
    twfRequireLineStateZeroed(f.line, f.http, "readiness teardown retained queue accounting");
    teardown(&f);
}

static uint32_t read32(const uint8_t *data)
{
    return ((uint32_t) data[0] << 24) | ((uint32_t) data[1] << 16) | ((uint32_t) data[2] << 8) | data[3];
}

static size_t frameLength(const uint8_t *data)
{
    return ((size_t) data[0] << 16) | ((size_t) data[1] << 8) | data[2];
}

static int peerFrame(nghttp2_session *session, const nghttp2_frame *frame, void *user)
{
    discard    session;
    fixture_t *f = user;
    twfRequire(frame->hd.type != NGHTTP2_GOAWAY && frame->hd.type != NGHTTP2_RST_STREAM,
               "peer observed an unexpected stream/session close");
    if (frame->hd.type == NGHTTP2_HEADERS)
        ++f->request_streams;
    if ((frame->hd.type == NGHTTP2_DATA || frame->hd.type == NGHTTP2_HEADERS) &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        ++f->end_streams;
    return 0;
}

static int peerData(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t length,
                    void *user)
{
    discard    session;
    discard    flags;
    fixture_t *f = user;
    twfRequire(stream_id == 1, "HttpClient opened a second request stream");
    for (size_t i = 0; i < length; ++i)
        twfRequire(data[i] == (uint8_t) ((f->received_body + i) % 251), "H2 DATA changed application bytes");
    f->received_body += length;
    return 0;
}

static void peerConsume(fixture_t *f)
{
    if (f->peer_offset < f->wire_length)
    {
        size_t length = f->wire_length - f->peer_offset;
        twfRequire(nghttp2_session_mem_recv2(f->peer, f->wire + f->peer_offset, length) == (nghttp2_ssize) length,
                   "peer rejected emitted H2 bytes");
        f->peer_offset = f->wire_length;
    }
}

static void peerPump(fixture_t *f)
{
    for (unsigned i = 0; i < 32; ++i)
    {
        peerConsume(f);
        const uint8_t *data   = NULL;
        nghttp2_ssize  length = nghttp2_session_mem_send2(f->peer, &data);
        twfRequire(length >= 0, "peer serialization failed");
        if (length == 0)
            return;
        sbuf_t *buffer = bufferpoolGetBestFit(f->env.pool, (uint32_t) length, 0);
        sbufSetLength(buffer, (uint32_t) length);
        sbufWrite(buffer, data, (uint32_t) length);
        httpclientTunnelDownStreamPayload(f->http, f->carrier, buffer);
        if (! lineIsAlive(f->carrier))
        {
            peerConsume(f);
            return;
        }
    }
    twfRequire(false, "unbounded H2 fixture control exchange");
}

static void createPeerWithWindow(fixture_t *f, uint32_t stream_window, bool manual_window_updates)
{
    nghttp2_session_callbacks *callbacks = NULL;
    twfRequire(nghttp2_session_callbacks_new(&callbacks) == 0, "peer callback allocation failed");
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, peerFrame);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, peerData);
    nghttp2_option *options = NULL;
    twfRequire(nghttp2_option_new(&options) == 0, "peer option allocation failed");
    nghttp2_option_set_no_auto_window_update(options, manual_window_updates);
    twfRequire(nghttp2_session_server_new2(&f->peer, callbacks, f, options) == 0, "peer allocation failed");
    nghttp2_option_del(options);
    nghttp2_session_callbacks_del(callbacks);
    const nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, stream_window},
                                               {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65536}};
    twfRequire(nghttp2_submit_settings(f->peer, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings)) == 0,
               "peer settings failed");
    twfRequire(nghttp2_submit_window_update(f->peer, NGHTTP2_FLAG_NONE, 0, 1U << 20) == 0, "peer window failed");
    peerPump(f);
}

static void createPeer(fixture_t *f)
{
    createPeerWithWindow(f, 1U << 20, false);
}

static void checkStartup(const fixture_t *f, bool websocket)
{
    const uint32_t settings_length = sizeof(kChromeSettings) + (websocket ? sizeof(kConnectSetting) : 0);
    const uint32_t startup_length  = 24 + 9 + settings_length + 13;
    twfRequire(f->writes > 0 && f->lengths[0] == startup_length,
               "preface/SETTINGS/WINDOW_UPDATE were not one startup buffer");
    twfRequire(memoryCompare(f->wire, kPreface, 24) == 0, "invalid H2 connection preface");
    const uint8_t *settings = f->wire + 24;
    twfRequire(frameLength(settings) == settings_length && settings[3] == NGHTTP2_SETTINGS && settings[4] == 0 &&
                   read32(settings + 5) == 0,
               "invalid initial SETTINGS frame");
    twfRequire(memoryCompare(settings + 9, kChromeSettings, sizeof(kChromeSettings)) == 0,
               "Chrome SETTINGS values/order differ");
    if (websocket)
        twfRequire(memoryCompare(settings + 9 + sizeof(kChromeSettings), kConnectSetting, sizeof(kConnectSetting)) == 0,
                   "WebSocket CONNECT setting omitted");
    const uint8_t *window = settings + 9 + settings_length;
    twfRequire(frameLength(window) == 4 && window[3] == NGHTTP2_WINDOW_UPDATE && read32(window + 5) == 0 &&
                   read32(window + 9) == 15663105,
               "connection receive window is not 15 MiB");
    if (! websocket)
        twfRequire(f->writes >= 2 && f->wire[startup_length + 3] == NGHTTP2_HEADERS,
                   "request HEADERS were not separate from startup");
}

static void caseHttp2WireProfile(void)
{
    twfSetCase("HttpClient H2 Chrome startup and bounded DATA");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2}");
    checkStartup(&f, false);
    createPeer(&f);
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    twfRequire(nghttp2_session_get_local_settings(ls->session, NGHTTP2_SETTINGS_MAX_FRAME_SIZE) == 16384,
               "receive max frame did not retain protocol default");
    twfRequire(nghttp2_session_get_local_window_size(ls->session) == 15 * 1024 * 1024,
               "local connection window differs from advertised target");
    twfRequire(nghttp2_session_get_stream_local_window_size(ls->session, 1) == 6 * 1024 * 1024,
               "local stream window differs from SETTINGS");
    twfRequire(nghttp2_session_get_remote_settings(f.peer, NGHTTP2_SETTINGS_ENABLE_PUSH) == 0,
               "peer did not receive ENABLE_PUSH=0");
    twfRequire(f.request_streams == 1, "startup did not open exactly one H2 request stream");
    resetWire(&f);
    httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, kLargeBody, false));
    peerPump(&f);
    size_t offset = 0, data_bytes = 0, data_frames = 0;
    while (offset < f.wire_length)
    {
        twfRequire(f.wire_length - offset >= 9, "truncated H2 frame header");
        const uint8_t *frame  = f.wire + offset;
        size_t         length = frameLength(frame);
        twfRequire(length <= f.wire_length - offset - 9, "truncated H2 frame payload");
        if (frame[3] == NGHTTP2_DATA)
        {
            twfRequire(length > 0 && length <= kH2BodyLimit && read32(frame + 5) == 1,
                       "DATA exceeded Chrome payload cap or changed streams");
            twfRequire(! (frame[4] & NGHTTP2_FLAG_END_STREAM), "payload prematurely closed the H2 stream");
            data_bytes += length;
            ++data_frames;
        }
        offset += 9 + length;
    }
    twfRequire(data_bytes == kLargeBody && f.received_body == kLargeBody && data_frames == 5,
               "H2 DATA lost bytes or did not honor its cap");
    twfRequire(f.request_streams == 1 && f.end_streams == 0, "payload changed the one-stream contract");
    httpclientTunnelUpStreamFinish(f.http, f.line);
    peerConsume(&f);
    twfRequire(f.end_streams == 1, "Finish did not terminate the single H2 stream");
    teardown(&f);
}

static void caseHttp2StartupReentry(bool finish)
{
    twfSetCase(finish ? "HttpClient H2 startup Finish stops HEADERS and releases pending output"
                      : "HttpClient H2 startup nested payload waits for request HEADERS");
    fixture_t f;
    setupWithStartupAction(&f, "{\"host\":\"unit.test\",\"http-version\":2}", finish ? 2 : 1);
    if (finish)
    {
        twfRequire(f.writes == 1 && f.lengths[0] == 70 && f.trace.prev_finish == 1 && f.trace.next_finish == 0,
                   "H2 startup close continued output or reflected Finish");
        twfRequireNoLeakedBuffers();
    }
    else
    {
        checkStartup(&f, false);
        createPeer(&f);
        twfRequire(f.received_body == 20000 && f.request_streams == 1 && f.end_streams == 0,
                   "startup-reentrant H2 payload was lost, reordered, or opened another stream");
    }
    teardown(&f);
}

static void caseHttp2FinishWithActiveAndPending(bool upstream_finish)
{
    twfSetCase(upstream_finish ? "HttpClient H2 nested Finish settles active and pending providers on a live line"
                               : "HttpClient H2 DATA callback Finish settles active and pending providers");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2}");
    createPeer(&f);
    resetWire(&f);
    const uint32_t       initial_refs     = twfLineRefCount(f.line);
    const uint32_t       initial_recycles = twfRecycleCount();
    httpclient_lstate_t *ls               = lineGetState(f.carrier, f.http);
    h2DataAppend(&ls->h2_data, payload(&f, kLargeBody, false), false);
    f.h2_finish_during_data = true;
    f.h2_fin_in_progress    = upstream_finish;
    if (upstream_finish)
    {
        h2DataAppend(&ls->h2_data, payload(&f, 251, false), false);
        httpclientTunnelUpStreamFinish(f.http, f.line);
    }
    else
    {
        httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, 251, false));
    }
    twfRequire(lineIsAlive(f.line) == upstream_finish, "H2 reentrant Finish changed line ownership");
    twfRequire(f.writes == 1 && f.trace.next_finish == 0 && f.trace.prev_finish == (upstream_finish ? 0U : 1U),
               "H2 provider output continued or Finish reflected after reentrant close");
    twfRequireLineStateZeroed(f.line, f.http, "H2 reentrant Finish retained provider/session state");
    twfRequireEqualU32(twfLineRefCount(f.line),
                       initial_refs - (upstream_finish ? 0U : 1U),
                       "H2 reentrant Finish leaked a line reference");
    twfRequireEqualU32(twfRecycleCount() - initial_recycles,
                       3,
                       "H2 reentrant Finish did not settle both payloads and the wire buffer exactly once");
    twfRequireNoLeakedBuffers();
    teardown(&f);
}

static void caseHttp2FlowControlResumes(void)
{
    twfSetCase("HttpClient H2 active provider and pending FIFO resume after WINDOW_UPDATE");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2}");
    const uint32_t window = 20000, first_length = 251 * 256, pending_length = 251;
    createPeerWithWindow(&f, window, true);
    resetWire(&f);
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, first_length, false));
    twfRequire(ls->h2_data.active != NULL && ls->h2_data.head == NULL && f.writes == 2,
               "stream window did not stop a partially consumed H2 provider");
    twfRequire(nghttp2_session_get_stream_remote_window_size(ls->session, 1) == 0,
               "H2 provider did not exhaust the peer's stream window");
    const size_t blocked_length = f.wire_length;
    httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, pending_length, false));
    twfRequire(f.wire_length == blocked_length && ls->h2_data.active != NULL && ls->h2_data.head != NULL,
               "H2 pending admission emitted bytes despite the exhausted stream window");
    peerConsume(&f);
    twfRequire(f.received_body == window, "H2 sent more or less than the available stream window");
    twfRequire(nghttp2_submit_window_update(
                   f.peer, NGHTTP2_FLAG_NONE, 1, (int32_t) (first_length + pending_length - window + 1U)) == 0,
               "peer could not replenish the blocked H2 stream");
    peerPump(&f);
    twfRequire(f.received_body == first_length + pending_length && f.end_streams == 0,
               "WINDOW_UPDATE failed to resume active and pending H2 payloads in FIFO order");
    twfRequire(ls->h2_data.active == NULL && ls->h2_data.head == NULL && ls->h2_data.tail == NULL,
               "resumed H2 output retained a completed provider");
    twfRequireNoLeakedBuffers();
    httpclientTunnelUpStreamFinish(f.http, f.line);
    peerConsume(&f);
    twfRequire(f.end_streams == 1, "H2 terminal provider failed after flow-control recovery");
    teardown(&f);
}

static void caseWebSocketStartup(void)
{
    twfSetCase("HttpClient WebSocket keeps conditional extended CONNECT setting");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2,\"websocket\":true}");
    checkStartup(&f, true);
    twfRequire(f.writes == 1, "WebSocket sent CONNECT before peer support was advertised");
    teardown(&f);
}

static void caseH2cSettings(void)
{
    twfSetCase("HttpClient h2c uses the canonical settings payload");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":\"both\",\"upgrade\":true}");
    httpclient_tstate_t *ts = tunnelGetState(f.http);
    twfRequire(ts->upgrade_settings_payload_len == sizeof(kChromeSettings) &&
                   memoryCompare(ts->upgrade_settings_payload, kChromeSettings, sizeof(kChromeSettings)) == 0,
               "h2c settings drifted from direct H2 settings");
    twfRequire(f.wire_length > 0 && memoryCompare(f.wire, "POST ", 5) == 0,
               "h2c no longer begins with an HTTP/1 request");
    teardown(&f);
}

static void caseCustomUpgrade(unsigned action)
{
    twfSetCase(action == 3   ? "HttpClient custom upgrade defers bypass until opening write returns"
               : action == 2 ? "HttpClient custom upgrade stops after borrowed-line Finish"
                             : "HttpClient custom upgrade drains nested FIFO and permanently bypasses");
    fixture_t f;
    setupWithStartupAction(
        &f,
        "{\"host\":\"unit.test\",\"http-version\":\"both\",\"upgrade\":true,\"upgrade-protocol\":\"unit\"}",
        action == 3 ? 3 : 0);
    uint8_t response[32];
    if (action != 3)
    {
        resetWire(&f);
        f.trace.capture          = response;
        f.trace.capture_capacity = sizeof(response);
        f.prev->fnPayloadD       = captureRawDown;
        f.raw_down_reentry       = action == 0;
        f.raw_up_reentry         = action == 0;
        f.raw_down_finish        = action == 2;
        tunnelUpStreamPause(f.http, f.line);
        tunnelUpStreamPause(f.http, f.line);
        tunnelDownStreamPause(f.http, f.line);
        tunnelDownStreamPause(f.http, f.line);
        tunnelUpStreamPayload(f.http, f.line, textPayload(&f, "AB"));
        tunnelUpStreamPayload(f.http, f.line, textPayload(&f, "CD"));
        tunnelDownStreamPayload(
            f.http,
            f.line,
            textPayload(&f, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: unit\r\n"));
        twfRequire(tunnelIsActiveForLine(f.http, f.line) && f.writes == 0,
                   "custom upgrade bypassed before the complete response header");
        tunnelDownStreamPayload(f.http, f.line, textPayload(&f, "\r\nserver"));
    }
    twfRequireLineStateZeroed(f.line, f.http, "custom upgrade retained state after transition");
    twfRequire(lineIsAlive(f.line), "custom upgrade destroyed a borrowed line");
    if (action == 2)
    {
        twfRequire(tunnelIsActiveForLine(f.http, f.line) && f.writes == 0 && f.trace.next_finish == 1 &&
                       f.trace.prev_finish == 0,
                   "custom upgrade bypassed or sent payload/Finish after reentrant Finish");
    }
    else
    {
        twfRequire(! tunnelIsActiveForLine(f.http, f.line), "custom raw upgrade did not bypass");
        if (action == 3)
        {
            twfRequire(f.writes == 2 && f.wire[f.wire_length - 1] == 'Q' && f.trace.prev_payload_bytes == 1,
                       "synchronous custom upgrade lost queued payload");
        }
        else
        {
            twfRequire(f.wire_length == 8 && memoryCompare(f.wire, "ABCDEFGH", 8) == 0 && f.trace.capture_len == 14 &&
                           memoryCompare(response, "servertaillast", 14) == 0,
                       "custom upgrade reordered or lost retained input");
        }
        f.trace.len    = 0;
        f.trace.seq[0] = '\0';
        for (unsigned i = 0; i < 2; ++i)
        {
            tunnelUpStreamPause(f.http, f.line);
            tunnelUpStreamResume(f.http, f.line);
            tunnelDownStreamPause(f.http, f.line);
            tunnelDownStreamResume(f.http, f.line);
            tunnelDownStreamEst(f.http, f.line);
        }
        twfRequire(strcmp(f.trace.seq, "URureURure") == 0, "bypassed custom upgrade lost repeated notifications");
        tunnelUpStreamPayload(f.http, f.line, textPayload(&f, "Z"));
        twfRequire(f.wire[f.wire_length - 1] == 'Z', "bypassed custom upgrade changed later payload");
        tunnelUpStreamFin(f.http, f.line);
        twfRequire(f.trace.next_finish == 1 && f.trace.prev_finish == 0, "bypassed custom upgrade lost Finish");
        twfRequireLineStateZeroed(f.line, f.http, "bypassed callbacks revived custom upgrade state");
    }
    teardown(&f);
}

static void advanceClock(fixture_t *f, uint64_t time_us)
{
    twfRequire(time_us >= now_us, "fixture moved its clock backwards");
    now_us = time_us;
    twfRequire(wloopProcessEvents(f->env.loop, 0) >= 0, "HttpClient timer dispatch failed");
}

static void finishApplication(fixture_t *f)
{
    twfRequire(f->carrier != f->line, "HTTP/2 Init reused the borrowed application line for its carrier");
    httpclientTunnelUpStreamFinish(f->http, f->line);
    twfRequire(lineIsAlive(f->line), "HttpClient destroyed its borrowed application line");
    twfRequireLineStateZeroed(f->line, f->http, "application Finish retained HTTP state on the borrowed line");
    twfRequire(f->trace.prev_finish == 0, "application Finish reflected toward its sender");
    lineDestroy(f->line); /* The source owner may destroy this exact line immediately. */
}

static void setupBlockedUpload(fixture_t *f)
{
    setup(f, "{\"host\":\"unit.test\",\"http-version\":2,\"close-drain-timeout-ms\":1000}");
    createPeerWithWindow(f, 0, true);
    resetWire(f);
    httpclientTunnelUpStreamPayload(f->http, f->line, payload(f, kLargeBody, false));
    httpclient_lstate_t *ls = lineGetState(f->carrier, f->http);
    twfRequire(h2DataPendingBytes(&ls->h2_data) == kLargeBody && f->writes == 0,
               "zero peer window did not retain the complete upload");
    twfRequire(wloopNTimers(f->env.loop) == 0, "HttpClient armed close timeout before application Finish");
}

static void requireCarrierClosed(fixture_t *f, unsigned next_finish)
{
    twfRequire(! lineIsAlive(f->carrier), "HttpClient retained its owned carrier after terminal close");
    twfRequireLineStateZeroed(f->carrier, f->http, "carrier close retained protocol state");
    twfRequireEqualU32(twfLineRefCount(f->carrier), 1, "carrier close leaked a line reference");
    twfRequireEqualU32(f->trace.next_finish, next_finish, "carrier close used the wrong Finish direction/count");
    twfRequire(wloopNTimers(f->env.loop) == 0, "carrier close retained a drain timer");
    twfRequireNoLeakedBuffers();
}

static void feedWire(fixture_t *f, const uint8_t *bytes, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(f->env.pool, length, 0);
    sbufSetLength(buf, length);
    sbufWrite(buf, bytes, length);
    httpclientTunnelDownStreamPayload(f->http, f->carrier, buf);
}

static void peerStartResponse(fixture_t *f, bool end_stream)
{
    nghttp2_nv header = {(uint8_t *) ":status", (uint8_t *) "200", 7, 3, NGHTTP2_NV_FLAG_NONE};
    twfRequire(nghttp2_submit_headers(
                   f->peer, end_stream ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE, 1, NULL, &header, 1, NULL) == 0,
               "peer response headers submission failed");
    peerPump(f);
}

static void caseHttp2FinishDrainsAfterApplicationDies(void)
{
    twfSetCase("HttpClient retains blocked upload on its owned carrier after application Finish");
    fixture_t f;
    setupBlockedUpload(&f);
    finishApplication(&f);
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    twfRequire(lineIsAlive(f.carrier) && ls->session != NULL && h2DataPendingBytes(&ls->h2_data) == kLargeBody &&
                   ls->close_drain_timer != NULL && f.trace.next_finish == 0,
               "application Finish discarded flow-controlled upload data");

    peerStartResponse(&f, false);
    const uint8_t late_data[] = {0, 0, 1, NGHTTP2_DATA, 0, 0, 0, 0, 1, 'x'};
    feedWire(&f, late_data, sizeof(late_data));
    twfRequire(f.trace.prev_payload == 0 && f.trace.prev_finish == 0 && lineIsAlive(f.carrier),
               "late response DATA reached the closed application or prevented upload draining");
    twfRequire(nghttp2_submit_window_update(f.peer, NGHTTP2_FLAG_NONE, 1, kLargeBody + 1) == 0,
               "peer could not reopen the upload window");
    peerPump(&f);
    peerConsume(&f);
    twfRequire(f.received_body == kLargeBody && f.end_streams == 1,
               "draining lost accepted bytes or failed to emit exactly one END_STREAM");
    twfRequire(lineShouldLingerOnClose(f.carrier), "completed upload did not request TCP close linger");
    requireCarrierClosed(&f, 1);
    teardown(&f);
}

static void caseHttp2DrainDeadline(bool progress)
{
    twfSetCase(progress ? "HttpClient upload progress does not extend the first drain deadline"
                        : "HttpClient blocked upload expires without incoming traffic");
    fixture_t f;
    setupBlockedUpload(&f);
    finishApplication(&f);
    httpclient_lstate_t *ls       = lineGetState(f.carrier, f.http);
    const uint64_t       deadline = ls->close_drain_deadline_ms;
    wtimer_t *const      timer    = ls->close_drain_timer;
    twfRequire(deadline == now_us / 1000 + 1000 && timer != NULL && timer_add_calls == 1,
               "application Finish did not arm its fixed configured deadline");
    if (progress)
    {
        for (unsigned i = 0; i < 3; ++i)
        {
            advanceClock(&f, now_us + 250000);
            twfRequire(nghttp2_submit_window_update(f.peer, NGHTTP2_FLAG_NONE, 1, 7) == 0,
                       "partial upload window submission failed");
            peerPump(&f);
            twfRequire(h2DataPendingBytes(&ls->h2_data) == kLargeBody - 7 * (i + 1) &&
                           ls->close_drain_deadline_ms == deadline && ls->close_drain_timer == timer &&
                           timer_add_calls == 1 && timer_reset_calls == 0,
                       "upload progress failed or changed the original close deadline");
        }
    }
    advanceClock(&f, deadline * 1000 + 1000);
    twfRequire(f.end_streams == 0 && ! lineShouldLingerOnClose(f.carrier),
               "timed-out upload falsely completed or requested successful-drain linger");
    requireCarrierClosed(&f, 1);
    teardown(&f);
}

static void caseHttp2DeadlineDuringSynchronousOutput(void)
{
    twfSetCase("HttpClient synchronous final output observes fresh time before the next frame");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2}");
    createPeer(&f);
    resetWire(&f);
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    h2DataAppend(&ls->h2_data, payload(&f, kLargeBody, false), false);
    f.expire_drain_output = true;
    finishApplication(&f);
    twfRequire(f.wire_length == 9 + kH2BodyLimit && f.writes == 1,
               "final drain emitted another HTTP/2 frame after its fixed deadline");
    twfRequire(! lineShouldLingerOnClose(f.carrier), "expired synchronous output requested successful-drain linger");
    requireCarrierClosed(&f, 1);
    teardown(&f);
}

static void caseHttp2DrainTimerFailure(unsigned failure)
{
    twfSetCase(failure == 0   ? "HttpClient timer admission refusal closes a blocked upload"
               : failure == 1 ? "HttpClient early timer preserves the original upload deadline"
                              : "HttpClient early timer reset refusal closes a blocked upload");
    fixture_t f;
    setupBlockedUpload(&f);
    refuse_timer_add = failure == 0;
    finishApplication(&f);
    if (failure != 0)
    {
        httpclient_lstate_t *ls       = lineGetState(f.carrier, f.http);
        const uint64_t       deadline = ls->close_drain_deadline_ms;
        twfRequire(ls->close_drain_timer != NULL && ls->close_drain_timer->next_timeout < deadline * 1000,
                   "fixture did not exercise early timer rounding");
        refuse_timer_reset = failure == 2;
        advanceClock(&f, ls->close_drain_timer->next_timeout + 1);
        twfRequire(timer_reset_calls == 1, "early drain wakeup did not rearm remaining time");
        if (failure == 1)
        {
            twfRequire(lineIsAlive(f.carrier) && ls->close_drain_deadline_ms == deadline &&
                           timer_reset_ms == deadline - now_us / 1000,
                       "early timer moved the fixed deadline or closed prematurely");
            advanceClock(&f, deadline * 1000 + 1000);
        }
    }
    requireCarrierClosed(&f, 1);
    teardown(&f);
}

static void caseHttp2CarrierFinishDuringDrain(void)
{
    twfSetCase("HttpClient carrier Finish immediately destroys the owned draining line");
    fixture_t f;
    setupBlockedUpload(&f);
    finishApplication(&f);
    httpclientTunnelDownStreamFinish(f.http, f.carrier);
    requireCarrierClosed(&f, 0);
    twfRequire(f.trace.prev_finish == 0, "carrier Finish reflected toward the closed application");
    teardown(&f);
}

static void caseHttp2PeerReset(bool draining)
{
    twfSetCase(draining ? "HttpClient peer reset cancels a retained upload"
                        : "HttpClient peer reset closes the active application and carrier");
    fixture_t f;
    setupBlockedUpload(&f);
    if (draining)
        finishApplication(&f);
    twfRequire(nghttp2_submit_rst_stream(f.peer, NGHTTP2_FLAG_NONE, 1, NGHTTP2_CANCEL) == 0,
               "peer reset submission failed");
    peerPump(&f);
    requireCarrierClosed(&f, 1);
    twfRequire(! lineIsAlive(f.line) && f.trace.prev_finish == (draining ? 0U : 1U),
               "peer reset reflected Finish or failed to close its active application");
    teardown(&f);
}

static void caseHttp2ResponseEndDoesNotCancelUpload(void)
{
    twfSetCase("HttpClient ordinary response END_STREAM does not cancel an unfinished upload");
    fixture_t f;
    setupBlockedUpload(&f);
    peerStartResponse(&f, true);
    twfRequire(lineIsAlive(f.carrier) && lineIsAlive(f.line) && f.trace.next_finish == 0 && f.trace.prev_finish == 0,
               "response END_STREAM was mistaken for an unusable HTTP/2 stream");
    finishApplication(&f);
    twfRequire(nghttp2_submit_window_update(f.peer, NGHTTP2_FLAG_NONE, 1, kLargeBody + 1) == 0,
               "response-ended peer could not reopen the upload window");
    peerPump(&f);
    twfRequire(f.received_body == kLargeBody && f.end_streams == 1, "response-ended stream lost its remaining upload");
    requireCarrierClosed(&f, 1);
    teardown(&f);
}

static void caseHttp2ShutdownCancelsDrain(bool draining)
{
    twfSetCase(draining ? "HttpClient owner-worker shutdown settles a quiesced upload timer and carrier"
                        : "HttpClient owner-worker shutdown closes an active application and carrier");
    fixture_t f;
    setupBlockedUpload(&f);
    if (draining)
        finishApplication(&f);
    f.http->onQuiesceRequest(f.http, NULL);
    wloopCloseNormalAdmission(f.env.loop);
    wloopQuiesceNormalWork(f.env.loop);
    f.http->onWorkerQuiesce(f.http, 0, NULL);
    f.http->onWorkerStop(f.http, 0, NULL);
    requireCarrierClosed(&f, 1);
    twfRequire(f.trace.prev_finish == (draining ? 0U : 1U) && ! lineIsAlive(f.line),
               "shutdown reflected Finish toward a detached application or left an active application alive");
    teardown(&f);
}

static void caseHttp2FinishBeforeWebSocketReady(void)
{
    twfSetCase("HttpClient application Finish retains pre-handshake bytes until its fixed deadline");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2,\"websocket\":true,\"close-drain-timeout-ms\":40}");
    httpclientTunnelUpStreamPayload(f.http, f.line, textPayload(&f, "queued"));
    finishApplication(&f);
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    twfRequire(lineIsAlive(f.carrier) && bufferqueueGetEntryCount(&ls->pending_up) == 1 &&
                   ls->close_drain_timer != NULL,
               "application Finish discarded an upload waiting for WebSocket readiness");
    advanceClock(&f, ls->close_drain_deadline_ms * 1000 + 1000);
    requireCarrierClosed(&f, 1);
    teardown(&f);
}

static void discardPressureWire(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    discard next;
    twfRequire(line == active->carrier, "HTTP/2 output used the application line");
    lineReuseBuffer(line, buf);
}

static void caseHttp2PressureCombinesTransportPause(void)
{
    twfSetCase("HttpClient upload high/low pressure combines with the next transport's Pause");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2}");
    createPeerWithWindow(&f, 0, true);
    f.trace.len          = 0;
    f.trace.seq[0]       = '\0';
    const uint32_t bytes = 1024 * 1024 + 1;
    httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, bytes, false));
    twfRequireEqualText(f.trace.seq, "u", "upload above high water did not Pause its application once");
    httpclientTunnelDownStreamPause(f.http, f.carrier);
    twfRequireEqualText(f.trace.seq, "uu", "transport Pause did not reach the held application");
    f.next->fnPayloadU      = discardPressureWire;
    const uint32_t credit   = bytes - 128 * 1024;
    const uint8_t  update[] = {0,
                               0,
                               4,
                               NGHTTP2_WINDOW_UPDATE,
                               0,
                               0,
                               0,
                               0,
                               1,
                               (uint8_t) (credit >> 24),
                               (uint8_t) (credit >> 16),
                               (uint8_t) (credit >> 8),
                               (uint8_t) credit};
    feedWire(&f, update, sizeof(update));
    httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
    twfRequire(h2DataPendingBytes(&ls->h2_data) == 128 * 1024,
               "WINDOW_UPDATE did not lower retained upload below low water");
    twfRequireEqualText(f.trace.seq, "uu", "low water resumed the application while its transport remained paused");
    httpclientTunnelDownStreamResume(f.http, f.carrier);
    twfRequireEqualText(f.trace.seq, "uur", "clearing both pressure reasons did not Resume once");
    teardown(&f);
}

static void caseHttp2QueueHardLimit(bool charge)
{
    twfSetCase(charge ? "HttpClient HTTP/2 upload rejects excess retained allocation charge"
                      : "HttpClient HTTP/2 upload rejects an over-limit body");
    fixture_t f;
    setup(&f, "{\"host\":\"unit.test\",\"http-version\":2}");
    createPeerWithWindow(&f, 0, true);
    if (charge)
    {
        httpclientTunnelUpStreamPayload(f.http, f.line, chargedPayload(16 * 1024 * 1024, "x"));
        httpclient_lstate_t *ls = lineGetState(f.carrier, f.http);
        twfRequire(lineIsAlive(f.carrier) && h2DataRetainedCharge(&ls->h2_data) == 16 * 1024 * 1024 &&
                       h2DataPendingBytes(&ls->h2_data) == 1,
                   "HTTP/2 provider rejected its inclusive allocation-charge limit");
        httpclientTunnelUpStreamPayload(f.http, f.line, textPayload(&f, "x"));
    }
    else
        httpclientTunnelUpStreamPayload(f.http, f.line, payload(&f, 16 * 1024 * 1024 + 1, false));
    requireCarrierClosed(&f, 1);
    twfRequire(! lineIsAlive(f.line) && f.trace.prev_finish == 1,
               "HTTP/2 provider limit did not settle the affected application");
    teardown(&f);
}

static void caseHttp2FinishReleasesApplicationReadPause(void)
{
    twfSetCase("HttpClient application Finish releases response-read Pause for upload control frames");
    fixture_t f;
    setupBlockedUpload(&f);
    f.trace.len    = 0;
    f.trace.seq[0] = '\0';
    httpclientTunnelUpStreamPause(f.http, f.line);
    twfRequireEqualText(f.trace.seq, "U", "application read Pause did not reach its owned carrier");
    finishApplication(&f);
    twfRequireEqualText(f.trace.seq, "UR", "application Finish did not release the carrier read hold");
    twfRequire(nghttp2_submit_window_update(f.peer, NGHTTP2_FLAG_NONE, 1, kLargeBody + 1) == 0,
               "resumed carrier could not receive upload credit");
    peerPump(&f);
    twfRequire(f.received_body == kLargeBody && f.end_streams == 1 && f.trace.prev_finish == 0,
               "released carrier read hold did not complete the upload without application callbacks");
    requireCarrierClosed(&f, 1);
    teardown(&f);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "fixture random initialization failed");
    frandInit();
    const uint32_t sizes[] = {0, 5, kH1BodyLimit, kH1BodyLimit + 1, kLargeBody};
    for (size_t i = 0; i < ARRAY_SIZE(sizes); ++i)
    {
        caseHttp1Chunks(sizes[i], false);
        caseHttp1Chunks(sizes[i], true);
    }
    caseHttp1NestedPayload();
    caseHttp1FinishDuringBody();
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        casePendingLimits(mode, false);
        casePendingLimits(mode, true);
    }
    casePendingWebSocketReplay(false);
    casePendingWebSocketReplay(true);
    casePendingManyBuffers();
    caseHttp2WireProfile();
    caseHttp2StartupReentry(false);
    caseHttp2StartupReentry(true);
    caseHttp2FinishWithActiveAndPending(false);
    caseHttp2FinishWithActiveAndPending(true);
    caseHttp2FlowControlResumes();
    caseHttp2FinishDrainsAfterApplicationDies();
    caseHttp2DrainDeadline(false);
    caseHttp2DrainDeadline(true);
    caseHttp2DeadlineDuringSynchronousOutput();
    caseHttp2DrainTimerFailure(0);
    caseHttp2DrainTimerFailure(1);
    caseHttp2DrainTimerFailure(2);
    caseHttp2CarrierFinishDuringDrain();
    caseHttp2PeerReset(false);
    caseHttp2PeerReset(true);
    caseHttp2ResponseEndDoesNotCancelUpload();
    caseHttp2ShutdownCancelsDrain(false);
    caseHttp2ShutdownCancelsDrain(true);
    caseHttp2FinishBeforeWebSocketReady();
    caseHttp2PressureCombinesTransportPause();
    caseHttp2QueueHardLimit(false);
    caseHttp2QueueHardLimit(true);
    caseHttp2FinishReleasesApplicationReadPause();
    caseWebSocketStartup();
    caseH2cSettings();
    caseCustomUpgrade(0);
    caseCustomUpgrade(2);
    caseCustomUpgrade(3);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
