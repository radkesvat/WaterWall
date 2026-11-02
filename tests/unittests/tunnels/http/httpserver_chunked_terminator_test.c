/*
 * Covers: httpserver chunked terminator; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes,
 * caseBodylessRequestStaysOpenForResponse, caseHeaderLimitExcludesDeliveredBody,
 * caseCustomUpgradeBypassesAfterReentrantTails
 * Checks: Assertion labels include: HttpServer destroyed its state at HTTP body end; HttpServer completed a
 * partial trailer block; HttpServer did not forward exactly one body chunk; HttpServer forwarded the
 * wrong body length
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.httpserver_chunked_terminator_unit
 */
/*
 * A terminating HTTP/1.1 chunk can arrive separately from the empty trailer
 * line. The parser must resume trailer scanning without spinning, and body end
 * in single mode must leave the Waterwall line open.
 */
#include "HttpServer/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 4096
};

typedef struct httpserver_chunked_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *line;
    bool             retired;
} httpserver_chunked_fixture_t;

static void fixtureSetup(httpserver_chunked_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->http != NULL, "failed to create the HttpServer tunnel");

    fixture->prev->chain_index = 0;
    fixture->http->chain_index = 1;
    fixture->next->chain_index = 2;
    fixture->http->fnInitU     = httpserverTunnelUpStreamInit;
    fixture->http->fnPayloadU  = httpserverTunnelUpStreamPayload;
    fixture->http->fnPayloadD  = httpserverTunnelDownStreamPayload;
    fixture->http->fnFinU      = httpserverTunnelUpStreamFinish;
    fixture->http->fnFinD      = httpserverTunnelDownStreamFinish;
    fixture->http->fnPauseU    = httpserverTunnelUpStreamPause;
    fixture->http->fnResumeU   = httpserverTunnelUpStreamResume;
    fixture->http->fnPauseD    = httpserverTunnelDownStreamPause;
    fixture->http->fnResumeD   = httpserverTunnelDownStreamResume;

    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);

    fixture->line           = twfLineCreate(fixture->http->lstate_size);
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    httpserverLinestateInitialize(ls, fixture->http, fixture->line);
    ls->runtime_proto     = kHttpServerRuntimeHttp1;
    ls->h1_headers_parsed = true;
    ls->h1_body_mode      = kHttpServerH1BodyChunked;
}

static void fixtureFeed(httpserver_chunked_fixture_t *fixture, const char *bytes)
{
    const uint32_t len = (uint32_t) strlen(bytes);
    sbuf_t        *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(buf, len);
    sbufWrite(buf, bytes, len);
    tunnelUpStreamPayload(fixture->http, fixture->line, buf);
}

static void fixtureTeardown(httpserver_chunked_fixture_t *fixture)
{
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    if (fixture->retired)
    {
        twfRequireLineStateZeroed(fixture->line, fixture->http, "HttpServer retained retired state");
    }
    else
    {
        twfRequire(ls->tunnel == fixture->http, "HttpServer destroyed its state at HTTP body end");
        httpserverLinestateDestroy(ls);
    }
    twfRequireNoLeakedBuffers();

    twfLineDestroy(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes(void)
{
    twfSetCase("HttpServer chunked terminator split across payloads");

    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);

    fixtureFeed(&fixture, "5\r\nhello\r\n");
    fixtureFeed(&fixture, "0\r\n");

    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    twfRequire(! ls->h1_request_finished, "HttpServer completed a partial trailer block");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "HttpServer did not forward exactly one body chunk");
    twfRequireEqualU32(fixture.trace.next_payload_bytes, 5, "HttpServer forwarded the wrong body length");

    fixtureFeed(&fixture, "\r\n");

    twfRequire(ls->h1_request_finished, "HttpServer did not complete the chunked request");
    twfRequire(lineIsAlive(fixture.line), "HttpServer closed a single-mode line at request body end");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "HttpServer reflected request body end into Finish");
    twfRequire(bufferstreamGetBufLen(&ls->in_stream) == 0, "HttpServer retained chunk trailer bytes");

    fixtureFeed(&fixture, "x");

    twfRequire(bufferstreamGetBufLen(&ls->in_stream) == 0, "HttpServer buffered bytes after request completion");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "HttpServer forwarded trailing request bytes");

    fixtureTeardown(&fixture);
}

static void caseBodylessRequestStaysOpenForResponse(void)
{
    twfSetCase("HttpServer bodyless request remains open for response");

    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);

    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    httpserverLinestateDestroy(ls);
    httpserverLinestateInitialize(ls, fixture.http, fixture.line);
    ls->runtime_proto = kHttpServerRuntimeHttp1;

    httpserver_tstate_t *ts = tunnelGetState(fixture.http);
    ts->status_code         = 200;

    fixtureFeed(&fixture, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");

    twfRequire(ls->h1_request_finished, "HttpServer did not record the bodyless request end");
    twfRequire(lineIsAlive(fixture.line), "HttpServer closed a bodyless single-mode request");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "HttpServer reflected a bodyless request into Finish");

    sbuf_t *response = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(response, 2);
    sbufWrite(response, "ok", 2);
    httpserverTunnelDownStreamPayload(fixture.http, fixture.line, response);

    twfRequire(fixture.trace.prev_payload > 0, "HttpServer did not emit a response for a bodyless request");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "HttpServer closed while emitting the response");

    fixtureTeardown(&fixture);
}

static void caseHeaderLimitExcludesDeliveredBody(unsigned mode)
{
    twfSetCase("HttpServer checks header size separately from a large delivered body");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_lstate_t *ls      = lineGetState(fixture.line, fixture.http);
    ls->h1_headers_parsed        = false;
    const char    *header        = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2097152\r\n\r\n";
    const uint32_t header_length = (uint32_t) stringLength(header);
    const uint32_t length        = LARGE_BUFFER_SIZE_RAM_HIGH;
    sbuf_t        *input         = bufferpoolTryGetBestFit(fixture.env.pool, length, 0);
    memorySet(sbufGetMutablePtr(input), 'b', length);
    sbufSetLength(input, length);
    if (mode == 0)
        memoryCopy(sbufGetMutablePtr(input), header, header_length);
    else if (mode == 1)
        memoryCopy((uint8_t *) sbufGetMutablePtr(input) + kHttpServerMaxHeaderBytes, "\r\n\r\n", 4);
    bufferstreamPush(&ls->in_stream, input);
    bool accepted = httpserverTransportHandleHttp1RequestHeaderPhase(fixture.http, fixture.line, ls);
    twfRequire(accepted == (mode == 0), "HTTP header admission used the complete delivery length");
    if (accepted)
    {
        twfRequire(ls->h1_headers_parsed, "valid coalesced HTTP headers were not parsed");
        twfRequire(bufferstreamGetBufLen(&ls->in_stream) == length - header_length,
                   "header parsing lost or consumed the following body");
        twfRequire(bufferstreamViewByteAt(&ls->in_stream, length - header_length - 1) == 'b',
                   "header parsing changed the trailing body");
    }
    fixtureTeardown(&fixture);
}

static httpserver_chunked_fixture_t *upgrade_fixture;
static char                          upgrade_up[16], upgrade_down[256];
static size_t                        upgrade_up_len, upgrade_down_len;
static bool                          upgrade_injected;
static unsigned                      upgrade_stop;

static sbuf_t *upgradeBuffer(line_t *line, const char *text)
{
    sbuf_t        *buf    = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    const uint32_t length = (uint32_t) strlen(text);
    sbufSetLength(buf, length);
    sbufWrite(buf, text, length);
    return buf;
}

static void upgradeRequestSink(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    twfRequire(upgrade_up_len + sbufGetLength(buf) < sizeof(upgrade_up), "raw request capture overflow");
    memoryCopy(upgrade_up + upgrade_up_len, sbufGetRawPtr(buf), sbufGetLength(buf));
    upgrade_up_len += sbufGetLength(buf);
    lineReuseBuffer(line, buf);
    if (upgrade_up_len == 1)
    {
        if (upgrade_stop == 1)
        {
            tunnelDownStreamFin(next->prev, line);
            return;
        }
        fixtureFeed(upgrade_fixture, "C");
    }
}

static void upgradeResponseSink(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    const bool initial     = ! upgrade_injected;
    const bool queued_body = sbufGetLength(buf) == 1 && *(const char *) sbufGetRawPtr(buf) == 'Q';
    twfRequire(upgrade_down_len + sbufGetLength(buf) < sizeof(upgrade_down), "raw response capture overflow");
    memoryCopy(upgrade_down + upgrade_down_len, sbufGetRawPtr(buf), sbufGetLength(buf));
    upgrade_down_len += sbufGetLength(buf);
    lineReuseBuffer(line, buf);
    if (initial)
    {
        upgrade_injected = true;
        twfRequire(tunnelIsActiveForLine(prev->next, line), "HttpServer bypassed before the 101 handoff settled");
        for (unsigned i = 0; i < 2; ++i)
        {
            tunnelUpStreamPause(prev->next, line);
            tunnelDownStreamPause(prev->next, line);
        }
        if (upgrade_stop >= 2)
        {
            for (size_t charge = 0; charge <= kHttpServerUpgradeQueueChargeLimit;)
            {
                sbuf_t *nested = upgradeBuffer(line, "x");
                charge += sbufGetQueueCharge(nested);
                if (upgrade_stop == 2)
                    tunnelUpStreamPayload(prev->next, line, nested);
                else
                    tunnelDownStreamPayload(prev->next, line, nested);
                if (((httpserver_lstate_t *) lineGetState(line, prev->next))->line == NULL)
                    break;
            }
            return;
        }
        fixtureFeed(upgrade_fixture, "B");
        tunnelDownStreamPayload(prev->next, line, upgradeBuffer(line, "R"));
    }
    else if (queued_body && upgrade_stop == 0)
    {
        fixtureFeed(upgrade_fixture, "D");
    }
}

static void upgradeDuringNextInit(tunnel_t *next, line_t *line)
{
    twfNextInit(next, line);
    tunnelDownStreamPayload(next->prev, line, upgradeBuffer(line, "Q"));
    fixtureFeed(upgrade_fixture,
                "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: raw-test\r\n\r\nA");
    twfRequireLineStateZeroed(line, next->prev, "raw transition left state after nested next Init");
}

static void caseCustomUpgradeBypassesAfterReentrantTails(unsigned stop)
{
    twfSetCase("HttpServer custom upgrade settles nested tails before permanent bypass");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserverLinestateDestroy(lineGetState(fixture.line, fixture.http));
    fixture.retired = true;
    upgrade_fixture = &fixture;
    upgrade_up_len = upgrade_down_len = 0;
    memoryZero(upgrade_up, sizeof(upgrade_up));
    memoryZero(upgrade_down, sizeof(upgrade_down));
    upgrade_injected         = false;
    upgrade_stop             = stop;
    fixture.prev->fnPayloadD = upgradeResponseSink;
    fixture.next->fnPayloadU = upgradeRequestSink;
    fixture.next->fnInitU    = upgradeDuringNextInit;
    httpserver_tstate_t *ts  = tunnelGetState(fixture.http);
    ts->version_mode         = kHttpServerVersionModeBoth;
    ts->enable_upgrade       = true;
    char upgrade_protocol[]  = "raw-test";
    ts->upgrade_protocol     = upgrade_protocol;
    tunnelUpStreamInit(fixture.http, fixture.line);
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed a borrowed line");
    twfRequireLineStateZeroed(fixture.line, fixture.http, "suspended Init revived retired HTTP state");
    if (stop == 0)
    {
        twfRequire(! tunnelIsActiveForLine(fixture.http, fixture.line), "completed raw upgrade stayed active");
        twfRequireEqualText(upgrade_up, "ABCD", "raw upgrade reordered nested request data");
        twfRequireEqualText(upgrade_down,
                            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: raw-test\r\n\r\nQR",
                            "raw response overtook 101 or queued data");
        twfRequireEqualText(fixture.trace.seq, "IUuUu", "active HTTP flow signals were not repeatable");
        for (unsigned i = 0; i < 2; ++i)
        {
            tunnelUpStreamResume(fixture.http, fixture.line);
            tunnelDownStreamResume(fixture.http, fixture.line);
        }
        fixtureFeed(&fixture, "E");
        tunnelDownStreamPayload(fixture.http, fixture.line, upgradeBuffer(fixture.line, "S"));
        twfRequireEqualText(upgrade_up, "ABCDE", "bypassed request did not reach next");
        tunnelUpStreamFin(fixture.http, fixture.line);
        twfRequireEqualU32(fixture.trace.next_finish, 1, "bypassed Finish did not reach next");
    }
    else
    {
        twfRequire(tunnelIsActiveForLine(fixture.http, fixture.line), "failed upgrade incorrectly bypassed");
        twfRequireEqualU32(fixture.trace.prev_finish, 1, "failed upgrade did not finish previous direction");
        twfRequireEqualU32(fixture.trace.next_finish, stop == 1 ? 0 : 1, "failed upgrade violated Finish direction");
    }
    fixtureTeardown(&fixture);
}

static sbuf_t *pendingBuffer(line_t *line, uint32_t capacity, uint32_t length, char value)
{
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(line), capacity, 0);
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), value, length);
    return buf;
}

static void caseEmptyResponsePayloadDoesNotTerminate(bool queued)
{
    twfSetCase("HttpServer empty response payload is not a final chunk");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    uint8_t wire[128]              = {0};
    fixture.trace.capture          = wire;
    fixture.trace.capture_capacity = sizeof(wire) - 1;
    httpserver_lstate_t *ls        = lineGetState(fixture.line, fixture.http);
    ls->h1_response_headers_sent   = true;
    ls->h1_headers_parsed          = ! queued;
    const uint32_t lengths[]       = {1, 0, 1};
    const char     values[]        = {'A', 'x', 'B'};
    for (unsigned i = 0; i < ARRAY_SIZE(lengths); ++i)
        tunnelDownStreamPayload(fixture.http, fixture.line, pendingBuffer(fixture.line, 1, lengths[i], values[i]));
    if (queued)
    {
        twfRequire(fixture.trace.capture_len == 0, "waiting HTTP response leaked body bytes");
        ls->h1_headers_parsed = true;
        tunnelDownStreamPayload(fixture.http, fixture.line, pendingBuffer(fixture.line, 1, 0, 'x'));
    }
    twfRequireEqualText((char *) wire, "1\r\nA\r\n1\r\nB\r\n", "empty input ended the response");
    bufferbudgetAssertEmpty(&ls->pending_down_budget);
    tunnelDownStreamFin(fixture.http, fixture.line);
    fixture.retired = true;
    twfRequireEqualText((char *) wire, "1\r\nA\r\n1\r\nB\r\n0\r\n\r\n", "Finish did not emit one final chunk");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "response Finish was not forwarded");
    fixtureTeardown(&fixture);
}

static bool submitWaitingPayload(httpserver_chunked_fixture_t *fixture, unsigned mode, sbuf_t *buf)
{
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    if (mode == 4)
    {
        if (! httpserverTransportSendHttp2DataFrame(fixture->http, fixture->line, ls, buf, false))
            httpserverTransportCloseBothDirections(fixture->http, fixture->line, ls);
    }
    else
        tunnelDownStreamPayload(fixture->http, fixture->line, buf);
    return ls->line != NULL;
}

static void caseWaitingResponseLimit(unsigned mode, bool charge_limit)
{
    twfSetCase("HttpServer readiness queue enforces byte and allocation limits");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    httpserver_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    httpserver_tstate_t *ts = tunnelGetState(fixture.http);
    ls->h1_headers_parsed   = false;
    if (mode == 1)
        ls->runtime_proto = kHttpServerRuntimeUnknown;
    else if (mode == 2)
        ts->websocket_enabled = true;
    else if (mode >= 3)
        ls->runtime_proto = kHttpServerRuntimeHttp2;
    const uint32_t capacity =
        charge_limit ? kHttpServerPendingCharge - sizeof(sbuf_t) - kSbufAllocationAlignment : kHttpServerPendingBytes;
    const uint32_t length = charge_limit ? 1 : capacity;
    twfRequire(submitWaitingPayload(&fixture, mode, pendingBuffer(fixture.line, capacity, length, 'A')),
               "exact waiting limit was refused");
    const buffer_budget_cost_t used = bufferbudgetGetUsage(&ls->pending_down_budget);
    twfRequire(used.bytes == length, "waiting bytes were not charged");
    if (charge_limit)
        twfRequire(used.charge == kHttpServerPendingCharge, "test did not reach the exact allocation limit");
    twfRequire(fixture.trace.prev_payload == 0, "unready response was emitted");
    twfRequire(! submitWaitingPayload(&fixture, mode, pendingBuffer(fixture.line, 1, 1, 'B')),
               "waiting response overflow was accepted");
    fixture.retired = true;
    twfRequireEqualText(fixture.trace.seq, "Ff", "overflow did not close both directions in order");
    twfRequire(lineIsAlive(fixture.line), "HttpServer destroyed a borrowed line on overflow");
    fixtureTeardown(&fixture);
}

static unsigned pending_drain_mode;
static bool     pending_header_seen, pending_body_seen;

static void pendingDrainSink(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    tunnel_t            *http   = prev->next;
    httpserver_lstate_t *ls     = lineGetState(line, http);
    bool                 body_a = sbufGetLength(buf) == 3 && memcmp(sbufGetRawPtr(buf), "A\r\n", 3) == 0;
    twfPrevPayload(prev, line, buf);
    if (! pending_header_seen)
    {
        pending_header_seen = true;
        twfRequire(ls->pending_down_draining, "drain guard was not published before response headers");
        twfRequire(bufferbudgetGetUsage(&ls->pending_down_budget).bytes == 2,
                   "oldest pending response lost its charge across the header callback");
        if (pending_drain_mode == 1)
        {
            tunnelDownStreamPayload(
                http, line, pendingBuffer(line, kHttpServerPendingBytes, kHttpServerPendingBytes, 'X'));
            return;
        }
        if (pending_drain_mode == 2)
        {
            tunnelUpStreamFin(http, line);
            return;
        }
        tunnelDownStreamPayload(http, line, pendingBuffer(line, 1, 1, 'C'));
        twfRequire(httpserverTransportFlushPendingDown(http, line, ls), "recursive drain failed");
    }
    else if (body_a && ! pending_body_seen)
    {
        pending_body_seen = true;
        twfRequire(bufferbudgetGetUsage(&ls->pending_down_budget).bytes == 2,
                   "handed-off payload retained its queue charge");
        if (pending_drain_mode == 3)
        {
            tunnelUpStreamFin(http, line);
            return;
        }
        tunnelDownStreamPayload(http, line, pendingBuffer(line, 1, 1, 'D'));
    }
}

static void casePendingDrainReentry(unsigned mode)
{
    twfSetCase("HttpServer response drain preserves FIFO, bounds and callback lifetime");
    httpserver_chunked_fixture_t fixture;
    fixtureSetup(&fixture);
    uint8_t wire[1024]             = {0};
    fixture.trace.capture          = wire;
    fixture.trace.capture_capacity = sizeof(wire) - 1;
    httpserver_lstate_t *ls        = lineGetState(fixture.line, fixture.http);
    httpserver_tstate_t *ts        = tunnelGetState(fixture.http);
    ts->status_code                = 200;
    ls->h1_headers_parsed          = false;
    for (char value = 'A'; value <= 'B'; ++value)
        tunnelDownStreamPayload(fixture.http, fixture.line, pendingBuffer(fixture.line, 1, 1, value));
    twfRequire(fixture.trace.prev_payload == 0, "queued payload bypassed request readiness");
    ls->h1_headers_parsed    = true;
    fixture.prev->fnPayloadD = pendingDrainSink;
    pending_drain_mode       = mode;
    pending_header_seen = pending_body_seen = false;
    bool drained                            = httpserverTransportFlushPendingDown(fixture.http, fixture.line, ls);
    twfRequire(drained == (mode == 0), "response drain reported the wrong callback result");
    if (mode == 0)
    {
        const char *body = strstr((char *) wire, "\r\n\r\n");
        twfRequire(body != NULL, "response header terminator missing");
        twfRequireEqualText(
            body + 4, "1\r\nA\r\n1\r\nB\r\n1\r\nC\r\n1\r\nD\r\n", "nested response overtook the pending FIFO");
        bufferbudgetAssertEmpty(&ls->pending_down_budget);
        twfRequire(! ls->pending_down_draining, "response drain guard remained set");
    }
    else
    {
        fixture.retired = true;
        twfRequireEqualU32(fixture.trace.next_finish, 1, "closing header callback did not finish next");
        twfRequireEqualU32(fixture.trace.prev_finish, mode == 1 ? 1 : 0, "closing header callback reflected Finish");
        twfRequireEqualU32(fixture.trace.prev_payload, mode == 3 ? 3 : 1, "body escaped after callback closure");
    }
    fixtureTeardown(&fixture);
}

int main(void)
{
    for (unsigned mode = 0; mode < 4; ++mode)
        casePendingDrainReentry(mode);
    for (unsigned mode = 0; mode < 5; ++mode)
        for (unsigned charge_limit = 0; charge_limit < 2; ++charge_limit)
            caseWaitingResponseLimit(mode, charge_limit != 0);
    caseEmptyResponsePayloadDoesNotTerminate(false);
    caseEmptyResponsePayloadDoesNotTerminate(true);
    for (unsigned stop = 0; stop < 4; ++stop)
        caseCustomUpgradeBypassesAfterReentrantTails(stop);
    for (unsigned mode = 0; mode < 3; ++mode)
        caseHeaderLimitExcludesDeliveredBody(mode);
    caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes();
    caseBodylessRequestStaysOpenForResponse();
    return 0;
}
