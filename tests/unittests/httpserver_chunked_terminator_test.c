/*
 * A terminating HTTP/1.1 chunk can arrive separately from the empty trailer
 * line. The parser must resume trailer scanning without spinning, and body end
 * in single mode must leave the Waterwall line open.
 */
#include "HttpServer/structure.h"

#include "tunnel_line_failure_harness.h"

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
} httpserver_chunked_fixture_t;

static void fixtureSetup(httpserver_chunked_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->http != NULL, "failed to create the HttpServer tunnel");

    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);

    fixture->line           = twfLineCreate(fixture->http->lstate_size);
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    httpserverLinestateInitialize(ls, fixture->http, fixture->line);
    ls->runtime_proto     = kHttpServerRuntimeHttp1;
    ls->h1_headers_parsed = true;
    ls->h1_body_mode      = kHttpServerH1BodyChunked;
    ls->h1_chunk_expected = -1;
}

static void fixtureFeed(httpserver_chunked_fixture_t *fixture, const char *bytes)
{
    const uint32_t len = (uint32_t) strlen(bytes);
    sbuf_t        *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(buf, len);
    sbufWrite(buf, bytes, len);
    httpserverTunnelUpStreamPayload(fixture->http, fixture->line, buf);
}

static void fixtureTeardown(httpserver_chunked_fixture_t *fixture)
{
    httpserver_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    twfRequire(ls->tunnel == fixture->http, "HttpServer destroyed its state at HTTP body end");
    httpserverLinestateDestroy(ls);
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

int main(void)
{
    caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes();
    caseBodylessRequestStaysOpenForResponse();
    return 0;
}
