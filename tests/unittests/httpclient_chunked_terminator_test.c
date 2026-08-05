/*
 * Mirror the server regression: a split terminating chunk must resume trailer
 * scanning, and response body end must not close a single-mode Waterwall line.
 */
#include "HttpClient/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 4096
};

typedef struct httpclient_chunked_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *http;
    tunnel_t        *next;
    line_t          *line;
} httpclient_chunked_fixture_t;

static void fixtureSetup(httpclient_chunked_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, 0);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->http = tunnelCreate(NULL, sizeof(httpclient_tstate_t), sizeof(httpclient_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->http != NULL, "failed to create the HttpClient tunnel");

    tunnelBind(fixture->prev, fixture->http);
    tunnelBind(fixture->http, fixture->next);

    fixture->line           = twfLineCreate(fixture->http->lstate_size);
    httpclient_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    httpclientLinestateInitialize(ls, fixture->http, fixture->line);
    ls->runtime_proto     = kHttpClientRuntimeHttp1;
    ls->h1_headers_parsed = true;
    ls->h1_body_mode      = kHttpClientH1BodyChunked;
    ls->h1_chunk_expected = -1;
}

static void fixtureFeed(httpclient_chunked_fixture_t *fixture, const char *bytes)
{
    const uint32_t len = (uint32_t) strlen(bytes);
    sbuf_t        *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(buf, len);
    sbufWrite(buf, bytes, len);
    httpclientTunnelDownStreamPayload(fixture->http, fixture->line, buf);
}

static void fixtureTeardown(httpclient_chunked_fixture_t *fixture)
{
    httpclient_lstate_t *ls = lineGetState(fixture->line, fixture->http);
    twfRequire(ls->tunnel == fixture->http, "HttpClient destroyed its state at HTTP body end");
    httpclientLinestateDestroy(ls);
    twfRequireNoLeakedBuffers();

    twfLineDestroy(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->http);
    tunnelDestroy(fixture->next);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes(void)
{
    twfSetCase("HttpClient chunked terminator split across payloads");

    httpclient_chunked_fixture_t fixture;
    fixtureSetup(&fixture);

    fixtureFeed(&fixture, "5\r\nhello\r\n");
    fixtureFeed(&fixture, "0\r\n");

    httpclient_lstate_t *ls = lineGetState(fixture.line, fixture.http);
    twfRequire(! ls->response_complete, "HttpClient completed a partial trailer block");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "HttpClient did not forward exactly one body chunk");
    twfRequireEqualU32(fixture.trace.prev_payload_bytes, 5, "HttpClient forwarded the wrong body length");

    fixtureFeed(&fixture, "\r\n");

    twfRequire(ls->response_complete, "HttpClient did not complete the chunked response");
    twfRequire(lineIsAlive(fixture.line), "HttpClient closed a single-mode line at response body end");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "HttpClient finished the transport at response body end");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "HttpClient reflected response body end into Finish");
    twfRequire(bufferstreamGetBufLen(&ls->in_stream) == 0, "HttpClient retained chunk trailer bytes");

    fixtureFeed(&fixture, "x");

    twfRequire(bufferstreamGetBufLen(&ls->in_stream) == 0, "HttpClient buffered bytes after response completion");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "HttpClient forwarded trailing response bytes");

    fixtureTeardown(&fixture);
}

int main(void)
{
    caseTerminatorSplitAcrossPayloadsResumesAndDropsTrailingBytes();
    return 0;
}
