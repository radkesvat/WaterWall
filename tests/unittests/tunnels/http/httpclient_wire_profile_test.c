/*
 * Covers: HttpClient's bounded HTTP/1 chunks and Chrome-reference HTTP/2 startup/DATA framing.
 * Setup: Production constructor and callbacks, worker-zero pools, captured next-neighbour buffers,
 *        an nghttp2 peer, and fixture-owned normal lines borrowed by HttpClient.
 * Checks: Exact framing/payload bytes, settings and windows, one request stream, WebSocket/h2c
 *         settings, nested-payload FIFO order, and cleanup after first-chunk Finish.
 * Limits: No TLS record, network-packet, browser traffic timing, or multi-stream equivalence claims.
 * CTest: waterwall.httpclient_wire_profile_unit
 */
#include "HttpClient/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "wfrand.h"

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
    line_t          *line;
    uint8_t          wire[kWireCapacity];
    uint32_t         lengths[kMaxWrites];
    size_t           wire_length, writes, peer_offset;
    bool             nested_payload, finish_first;
    bool             h2_startup_payload;
    nghttp2_session *peer;
    size_t           received_body;
    unsigned         request_streams, end_streams;
} fixture_t;

static fixture_t *active;

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
        uint32_t skip = sbufGetMaximumWriteableSize(buf) - length;
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
    if (f->finish_first)
    {
        f->finish_first = false;
        httpclientTunnelDownStreamFinish(f->http, line);
    }
    else if (f->h2_startup_payload)
    {
        f->h2_startup_payload = false;
        httpclientTunnelUpStreamPayload(f->http, line, payload(f, 20000, false));
    }
    else if (f->nested_payload)
    {
        f->nested_payload = false;
        sbuf_t *nested    = bufferpoolGetBestFit(f->env.pool, 7, kHttpClientRequiredPaddingLeft);
        sbufSetLength(nested, 7);
        sbufWrite(nested, "nested!", 7);
        httpclientTunnelUpStreamPayload(f->http, line, nested);
    }
}

static void setupWithStartupAction(fixture_t *f, const char *json, unsigned action)
{
    static char node_name[] = "http-wire-test";
    static char node_type[] = "HttpClient";
    memoryZero(f, sizeof(*f));
    active = f;
    twfWorkerEnvSetup(&f->env, 65536, 96);
    f->settings = cJSON_Parse(json);
    twfRequire(f->settings != NULL, "invalid fixture settings");
    f->node = (node_t) {.name = node_name, .type = node_type, .node_settings_json = f->settings};
    f->prev = twfCreatePrevTunnel(&f->trace);
    f->http = httpclientTunnelCreate(&f->node);
    f->next = twfCreateNextTunnel(&f->trace);
    twfRequire(f->http != NULL, "HttpClient construction failed");
    f->prev->fnFinD     = ownerFinish;
    f->next->fnPayloadU = capture;
    tunnelBind(f->prev, f->http);
    tunnelBind(f->http, f->next);
    twfLinePoolSetup(&f->lines, f->http->lstate_size, 4);
    f->line = twfLinePoolCreateLine(&f->lines);
    lineRef(f->line); /* The fixture owns the line; retain allocation across reentrant owner Finish. */
    f->h2_startup_payload = action == 1;
    f->finish_first       = action == 2;
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
    httpclient_lstate_t *ls = lineGetState(f->line, f->http);
    if (ls->tunnel != NULL)
        httpclientLinestateDestroy(ls);
    if (lineIsAlive(f->line))
        lineDestroy(f->line);
    twfRequireLineStateZeroed(f->line, f->http, "HttpClient state remained at line release");
    lineUnref(f->line);
    if (f->peer != NULL)
        nghttp2_session_del(f->peer);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&f->lines);
    httpclientTunnelDestroy(f->http, wwLifecycleStartupRollback());
    tunnelDestroy(f->prev);
    tunnelDestroy(f->next);
    cJSON_Delete(f->settings);
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
        httpclientTunnelDownStreamPayload(f->http, f->line, buffer);
        twfRequire(lineIsAlive(f->line), "peer control frame closed HttpClient");
    }
    twfRequire(false, "unbounded H2 fixture control exchange");
}

static void createPeer(fixture_t *f)
{
    nghttp2_session_callbacks *callbacks = NULL;
    twfRequire(nghttp2_session_callbacks_new(&callbacks) == 0, "peer callback allocation failed");
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, peerFrame);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, peerData);
    twfRequire(nghttp2_session_server_new(&f->peer, callbacks, f) == 0, "peer allocation failed");
    nghttp2_session_callbacks_del(callbacks);
    const nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1U << 20},
                                               {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65536}};
    twfRequire(nghttp2_submit_settings(f->peer, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings)) == 0,
               "peer settings failed");
    twfRequire(nghttp2_submit_window_update(f->peer, NGHTTP2_FLAG_NONE, 0, 1U << 20) == 0, "peer window failed");
    peerPump(f);
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
    httpclient_lstate_t *ls = lineGetState(f.line, f.http);
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
    caseHttp2WireProfile();
    caseHttp2StartupReentry(false);
    caseHttp2StartupReentry(true);
    caseWebSocketStartup();
    caseH2cSettings();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
