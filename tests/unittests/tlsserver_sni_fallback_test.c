#include "TlsServer/structure.h"
#include "fallback_finish_lifetime_fixture.h"

/* Real SSL_accept and original wire replay; the test owns the normal line. */
typedef struct fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      wire, protected, fallback;
    tunnel_t        *prev, *tls, *next, *cover;
    line_t          *line;
    SSL_CTX         *ctx, *client_ctx;
    SSL             *client;
    uint8_t          captured[32768];
} fixture_t;

static int  init_action;
static char expected_sni[] = "protected.integration.test";

static void ownerFinish(tunnel_t *t, line_t *l)
{
    twfPrevFinish(t, l);
    lineDestroy(l);
}

static void coverInit(tunnel_t *t, line_t *l)
{
    twfNextInit(t, l);
    if (init_action >= 3)
    {
        sbuf_t *buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
        sbufSetLength(buf, 5);
        sbufWrite(buf, "LATER", 5);
        tlsserverTunnelUpStreamPayload(t->prev, l, buf);
        twfRequire(twfTrace(t)->capture_len == 0, "payload drained before fallback Init returned");
        twfRequire(! g_fallback_finish_task.pending, "drain scheduled before fallback Init returned");
        if (init_action == 4)
        {
            tlsserverTunnelDownStreamPause(t->prev, l);
            tlsserverTunnelDownStreamResume(t->prev, l);
            twfRequire(! g_fallback_finish_task.pending, "re-entrant Resume scheduled an Init-time drain");
            tlsserverTunnelDownStreamPause(t->prev, l);
        }
        else if (init_action == 5)
        {
            tlsserverTunnelDownStreamFinish(t->prev, l);
        }
        else if (init_action == 6)
        {
            tlsserverTunnelUpStreamFinish(t->prev, l);
            lineDestroy(l);
        }
    }
    if (init_action == 1)
    {
        tlsserverTunnelDownStreamPause(t->prev, l);
    }
    else if (init_action == 2)
    {
        tlsserverTunnelDownStreamFinish(t->prev, l);
    }
}

static void setup(fixture_t *f, const char *sni, int version, bool fallback)
{
    memoryZero(f, sizeof(*f));
    fallbackFinishResetScheduledTask();
    twfWorkerEnvSetup(&f->env, 65536, 0);
    f->ctx        = SSL_CTX_new(TLS_server_method());
    f->client_ctx = SSL_CTX_new(TLS_client_method());
    twfRequire(f->ctx != NULL && f->client_ctx != NULL, "SSL contexts");
    twfRequire(SSL_CTX_use_certificate_chain_file(f->ctx, TLSSERVER_TEST_CERT_FILE) == 1 &&
                   SSL_CTX_use_PrivateKey_file(f->ctx, TLSSERVER_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1,
               "server certificate");
    f->prev         = twfCreatePrevTunnel(&f->wire);
    f->prev->fnFinD = ownerFinish;
    f->tls          = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
    twfRequire(f->tls != NULL, "TLS tunnel");
    f->next           = twfCreateNextTunnel(&f->protected);
    f->cover          = twfCreateNextTunnel(&f->fallback);
    f->cover->fnInitU = coverInit;
    tunnelBind(f->prev, f->tls);
    tunnelBind(f->tls, f->next);
    f->cover->prev               = f->tls;
    f->fallback.capture          = f->captured;
    f->fallback.capture_capacity = sizeof(f->captured);
    tlsserver_tstate_t *ts       = tunnelGetState(f->tls);
    ts->expected_sni             = expected_sni;
    ts->fallback_tunnel          = fallback ? f->cover : NULL;
    SSL_CTX_set_tlsext_servername_callback(f->ctx, tlsserverOnServername);
    SSL_CTX_set_tlsext_servername_arg(f->ctx, ts);
    if (fallback)
    {
        SSL_CTX_set_client_hello_cb(f->ctx, tlsserverOnClientHello, ts);
    }
    twfLinePoolSetup(&f->lines, f->tls->lstate_size, 4);
    f->line = twfLinePoolCreateLine(&f->lines);
    lineRef(f->line); /* Observe state even when a callback destroys the owner line. */
    tlsserver_lstate_t       *ls      = lineGetState(f->line, f->tls);
    tlsrecordshaping_config_t shaping = {0};
    twfRequire(tlsserverLinestateInitialize(ls, f->ctx, f->env.pool, &shaping, false), "line TLS state");
    ls->tunnel = f->tls;
    ls->line   = f->line;
    f->client  = SSL_new(f->client_ctx);
    twfRequire(f->client != NULL, "SSL client");
    SSL_set_bio(f->client, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
    SSL_set_connect_state(f->client);
    twfRequire(SSL_set_min_proto_version(f->client, version) == 1 && SSL_set_max_proto_version(f->client, version) == 1,
               "client version");
    if (sni != NULL)
    {
        twfRequire(SSL_set_tlsext_host_name(f->client, sni) == 1, "client SNI");
    }
}

static void teardown(fixture_t *f)
{
    if (lineIsAlive(f->line))
    {
        tlsserverTunnelUpStreamFinish(f->tls, f->line);
        lineDestroy(f->line);
    }
    if (g_fallback_finish_task.pending)
    {
        fallbackFinishDriveDelayedTask();
    }
    twfRequireLineStateZeroed(f->line, f->tls, "state after close");
    lineUnref(f->line);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&f->lines);
    SSL_free(f->client);
    SSL_CTX_free(f->ctx);
    SSL_CTX_free(f->client_ctx);
    tunnelDestroy(f->cover);
    tunnelDestroy(f->next);
    tunnelDestroy(f->tls);
    tunnelDestroy(f->prev);
    twfWorkerEnvTeardown(&f->env);
}

static size_t hello(fixture_t *f, uint8_t *bytes, size_t cap, bool records)
{
    int ret = SSL_do_handshake(f->client);
    twfRequire(SSL_get_error(f->client, ret) == SSL_ERROR_WANT_READ, "client generates hello");
    int n = BIO_read(SSL_get_wbio(f->client), bytes, (int) cap);
    twfRequire(n > 10, "ClientHello length");
    if (records)
    {
        /* Split the handshake header itself across two TLS records. */
        size_t payload = ((size_t) bytes[3] << 8) | bytes[4];
        twfRequire(payload + 5 == (size_t) n && (size_t) n + 5 <= cap, "single input record");
        memmove(bytes + 12, bytes + 7, n - 7);
        memcpy(bytes + 7, bytes, 3);
        bytes[3]  = 0;
        bytes[4]  = 2;
        bytes[10] = (payload - 2) >> 8;
        bytes[11] = (payload - 2) & 255;
        n += 5;
    }
    return (size_t) n;
}

static void sendBytes(fixture_t *f, const uint8_t *bytes, size_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(f->env.pool);
    buf         = sbufReserveSpace(buf, (uint32_t) length);
    sbufSetLength(buf, (uint32_t) length);
    sbufWrite(buf, bytes, (uint32_t) length);
    tlsserverTunnelUpStreamPayload(f->tls, f->line, buf);
}

static void replayCase(const char *sni, int version, bool fragmented, int action)
{
    twfSetCase("SNI fallback wire replay");
    init_action = action;
    fixture_t f;
    setup(&f, sni, version, true);
    uint8_t bytes[8192];
    size_t  n = hello(&f, bytes, sizeof(bytes), fragmented);
    if (fragmented)
    {
        for (size_t i = 0; i + 1 < n; ++i)
        {
            sendBytes(&f, bytes + i, 1);
            twfRequire(f.wire.prev_payload == 0 && f.fallback.next_init == 0 && f.protected.next_init == 0,
                       "incomplete hello emitted bytes or initialized a branch");
        }
        sendBytes(&f, bytes + n - 1, 1);
    }
    else
    {
        /* Trailing bytes coalesced with ClientHello must also survive the handoff. */
        memcpy(bytes + n, "tail", 4);
        n += 4;
        sendBytes(&f, bytes, n);
    }
    twfRequire(f.wire.prev_payload == 0 && f.protected.next_init == 0, "TLS output or protected Init on fallback");
    twfRequire(f.fallback.next_init == 1, "fallback initialized exactly once");
    if (action == 2)
    {
        twfRequire(! lineIsAlive(f.line) && f.fallback.capture_len == 0, "Init close must discard replay");
    }
    else
    {
        if (action == 1)
        {
            twfRequire(f.fallback.capture_len == 0, "paused fallback received payload");
            tlsserverTunnelDownStreamResume(f.tls, f.line);
            if (g_fallback_finish_task.pending)
            {
                fallbackFinishDriveDelayedTask();
            }
        }
        twfRequire(f.fallback.capture_len == n && memcmp(bytes, f.captured, n) == 0, "byte-exact replay");
        sendBytes(&f, (const uint8_t *) "later", 5);
        twfRequire(f.fallback.capture_len == n + 5 && memcmp(f.captured + n, "later", 5) == 0,
                   "subsequent payload stays in fallback FIFO");
    }
    teardown(&f);
}

static void reentrantInitCase(uint32_t delay_ms, int action, bool plaintext)
{
    twfSetCase("re-entrant Init transcript ordering");
    init_action = action;
    fixture_t f;
    setup(&f, "cover.integration.test", TLS1_3_VERSION, true);
    ((tlsserver_tstate_t *) tunnelGetState(f.tls))->fallback_intentional_delay_ms = delay_ms;
    uint8_t bytes[8192];
    size_t  n;
    if (plaintext)
    {
        memcpy(bytes, "GET / HTTP/1.0\r\n\r\n", 18);
        n = 18;
    }
    else
    {
        n = hello(&f, bytes, sizeof(bytes), true);
        /* Ensure the handoff includes bytes from an earlier socket delivery. */
        sendBytes(&f, bytes, 1);
    }
    sendBytes(&f, bytes + (plaintext ? 0 : 1), n - (plaintext ? 0 : 1));
    if (action >= 5)
    {
        twfRequire(! lineIsAlive(f.line) && f.fallback.capture_len == 0, "Init close leaked queued payload");
    }
    else
    {
        if (action == 4)
        {
            twfRequire(f.fallback.capture_len == 0 && ! g_fallback_finish_task.pending,
                       "paused Init drained its queue");
            tlsserverTunnelDownStreamResume(f.tls, f.line);
        }
        if (g_fallback_finish_task.pending)
        {
            fallbackFinishDriveDelayedTask();
        }
        twfRequire(f.fallback.capture_len == n + 5 && memcmp(f.captured, bytes, n) == 0 &&
                       memcmp(f.captured + n, "LATER", 5) == 0,
                   "new bytes overtook the saved transcript");
    }
    teardown(&f);
}

static void compactTranscriptCase(void)
{
    twfSetCase("tiny fragments retain compact transcript allocations");
    init_action = 0;
    fixture_t f;
    setup(&f, "cover.integration.test", TLS1_3_VERSION, true);
    /* A large incomplete record keeps OpenSSL waiting while the wire transcript grows. */
    const uint8_t header[]       = {0x16, 0x03, 0x03, 0x40, 0x00, 0x01, 0x00, 0x3f, 0xfc};
    uint8_t       expected[8201] = {0};
    memcpy(expected, header, sizeof(header));
    for (size_t i = 0; i < sizeof(expected); ++i)
    {
        sendBytes(&f, expected + i, 1);
        tlsserver_lstate_t *state    = lineGetState(f.line, f.tls);
        size_t              retained = 0;
        c_foreach(chunk, bs_doublequeue_t, state->fallback_probe.q)
        {
            retained += sizeof(sbuf_t) + sbufGetTotalCapacity(*chunk.ref);
        }
        twfRequire(retained <= 32768, "tiny fragments retained more than 32 KiB of transcript buffers");
    }
    tlsserver_lstate_t *ls = lineGetState(f.line, f.tls);
    twfRequire(lineIsAlive(f.line) && ! ls->tls_committed && f.fallback.next_init == 0,
               "incomplete transcript must remain unassigned");
    size_t allocation_bytes = 0;
    c_foreach(i, bs_doublequeue_t, ls->fallback_probe.q)
    {
        allocation_bytes += sizeof(sbuf_t) + sbufGetTotalCapacity(*i.ref);
    }
    twfRequire(allocation_bytes <= 32768, "8201 tiny input bytes retained more than 32 KiB of transcript buffers");
    uint8_t actual[sizeof(expected)];
    bufferstreamViewBytesAt(&ls->fallback_probe, 0, actual, sizeof(actual));
    twfRequire(bufferstreamGetBufLen(&ls->fallback_probe) == sizeof(expected) &&
                   memcmp(actual, expected, sizeof(actual)) == 0,
               "compaction changed the original bytes");
    teardown(&f);
}

static void tlsCase(const char *sni, bool fallback, bool match)
{
    twfSetCase("matching SNI and strict rejection");
    init_action = 0;
    fixture_t f;
    setup(&f, sni, TLS1_3_VERSION, fallback);
    uint8_t bytes[8192];
    size_t  n = hello(&f, bytes, sizeof(bytes), true);
    sendBytes(&f, bytes, n);
    twfRequire(f.fallback.next_init == 0, "TLS branch selected fallback");
    if (match)
    {
        tlsserver_lstate_t *ls = lineGetState(f.line, f.tls);
        twfRequire(lineIsAlive(f.line) && ls->tls_committed && f.protected.next_init == 1 && f.wire.prev_payload > 0 &&
                       bufferstreamIsEmpty(&ls->fallback_probe),
                   "matching TLS commitment");
    }
    else
    {
        twfRequire(! lineIsAlive(f.line) && f.wire.prev_finish == 1, "strict SNI rejection closes owner");
    }
    teardown(&f);
}

static void malformedCase(void)
{
    twfSetCase("malformed SNI never routes as mismatch");
    fixture_t f;
    setup(&f, "cover.integration.test", TLS1_3_VERSION, true);
    uint8_t bytes[8192];
    size_t  n       = hello(&f, bytes, sizeof(bytes), false);
    bool    mutated = false;
    for (size_t i = 0; i + 22 <= n; ++i)
    {
        if (memcmp(bytes + i, "cover.integration.test", 22) == 0)
        {
            bytes[i] = 0;
            mutated  = true;
            break;
        }
    }
    twfRequire(mutated, "found SNI mutation position");
    sendBytes(&f, bytes, n);
    twfRequire(! lineIsAlive(f.line) && f.fallback.next_init == 0, "malformed SNI closes without fallback");
    teardown(&f);
}

static void retryCase(void)
{
    twfSetCase("HelloRetryRequest commits the protected branch");
    fixture_t f;
    setup(&f, "protected.integration.test", TLS1_3_VERSION, true);
    tlsserver_lstate_t *ls = lineGetState(f.line, f.tls);
    twfRequire(SSL_set1_groups_list(ls->ssl, "P-256") == 1 && SSL_set1_groups_list(f.client, "X25519:P-256") == 1,
               "HRR groups");
    uint8_t bytes[8192];
    size_t  n = hello(&f, bytes, sizeof(bytes), false);
    sendBytes(&f, bytes, n);
    twfRequire(lineIsAlive(f.line) && ls->tls_committed && ! ls->handshake_completed && f.protected.next_init == 1 &&
                   f.fallback.next_init == 0,
               "HRR committed TLS");
    /* An invalid second flight after HRR must never hand off to cover. */
    const uint8_t alert[] = {21, 3, 3, 0, 2, 2, 40};
    sendBytes(&f, alert, sizeof(alert));
    twfRequire(! lineIsAlive(f.line) && f.fallback.next_init == 0, "post-HRR failure stays on TLS");
    teardown(&f);
}

static void transcriptLimitCase(bool overflow)
{
    twfSetCase("pre-routing input limit and exact replay at the boundary");
    init_action = 0;
    fixture_t f;
    setup(&f, "cover.integration.test", TLS1_3_VERSION, true);
    size_t   n       = kTlsServerMaxFallbackPendingBytes + (overflow ? 1U : 0U);
    uint8_t *bytes   = calloc(n, 1);
    uint8_t *capture = malloc(n);
    twfRequire(bytes != NULL && capture != NULL, "boundary fixture allocation");
    discard hello(&f, bytes, n, false);
    f.fallback.capture          = capture;
    f.fallback.capture_capacity = (uint32_t) n;
    sendBytes(&f, bytes, n);
    if (overflow)
    {
        twfRequire(! lineIsAlive(f.line) && f.fallback.next_init == 0 && f.protected.next_init == 0,
                   "overflow must close without routing");
    }
    else
    {
        twfRequire(lineIsAlive(f.line) && f.fallback.next_init == 1 && f.fallback.capture_len == n &&
                       memcmp(bytes, capture, n) == 0,
                   "exact 1 MiB input must replay intact");
    }
    teardown(&f);
    free(capture);
    free(bytes);
}

int main(void)
{
    compactTranscriptCase();
    for (uint32_t delay = 0; delay <= 7; delay += 7)
    {
        for (int action = 3; action <= 6; ++action)
        {
            reentrantInitCase(delay, action, false);
            reentrantInitCase(delay, action, true);
        }
    }
    for (int version = TLS1_2_VERSION; version <= TLS1_3_VERSION; ++version)
    {
        replayCase("cover.integration.test", version, false, 0);
        replayCase("cover.integration.test", version, true, 0);
        replayCase(NULL, version, false, 0);
        replayCase(NULL, version, true, 0);
    }
    replayCase("cover.integration.test", TLS1_3_VERSION, false, 1);
    replayCase("cover.integration.test", TLS1_3_VERSION, false, 2);
    tlsCase("PrOtEcTeD.integration.test", true, true);
    tlsCase("cover.integration.test", false, false);
    tlsCase(NULL, false, false);
    malformedCase();
    retryCase();
    transcriptLimitCase(false);
    transcriptLimitCase(true);
    puts("tlsserver_sni_fallback_test: all cases passed");
    return 0;
}
