#include "TlsServer/structure.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

typedef struct server_delay_context_s
{
    tunnel_t *tls;
    uint32_t  prev_payload;
    uint32_t  prev_finish;
    uint32_t  next_payload;
    uint32_t  next_est;
    uint32_t  next_pause;
    uint32_t  next_resume;
    uint32_t  next_finish;
    sbuf_t   *upstream_payload_on_prev_payload;
    bool      pause_on_prev_payload;
} server_delay_context_t;

typedef struct server_delay_fixture_s
{
    master_pool_t         *large_master;
    master_pool_t         *small_master;
    buffer_pool_t         *pool;
    buffer_pool_t        **saved_buffer_pools;
    buffer_pool_t         *buffer_pools[1];
    wloop_t              **saved_loops;
    wloop_t               *loops[1];
    uint32_t               saved_workers_count;
    SSL_CTX               *client_ctx;
    SSL_CTX               *server_ctx;
    SSL                   *client;
    tunnel_t              *prev;
    tunnel_t              *tls;
    tunnel_t              *next;
    line_t                *line;
    server_delay_context_t context;
} server_delay_fixture_t;

static void requireServer(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

static server_delay_context_t *serverContext(tunnel_t *t)
{
    return *(server_delay_context_t **) tunnelGetState(t);
}

static void serverPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    server_delay_context_t *context = serverContext(t);
    ++context->prev_payload;
    lineReuseBuffer(l, buf);
    if (context->upstream_payload_on_prev_payload != NULL)
    {
        sbuf_t *upstream_payload                  = context->upstream_payload_on_prev_payload;
        context->upstream_payload_on_prev_payload = NULL;
        tlsserverTunnelUpStreamPayload(context->tls, l, upstream_payload);
    }
    if (context->pause_on_prev_payload)
    {
        context->pause_on_prev_payload = false;
        tlsserverTunnelUpStreamPause(context->tls, l);
    }
}

static void serverPrevFinish(tunnel_t *t, line_t *l)
{
    discard l;
    ++serverContext(t)->prev_finish;
}

static void serverNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ++serverContext(t)->next_payload;
    lineReuseBuffer(l, buf);
}

static void serverNextEst(tunnel_t *t, line_t *l)
{
    discard l;
    ++serverContext(t)->next_est;
}

static void serverNextPause(tunnel_t *t, line_t *l)
{
    discard l;
    ++serverContext(t)->next_pause;
}

static void serverNextResume(tunnel_t *t, line_t *l)
{
    discard l;
    ++serverContext(t)->next_resume;
}

static void serverNextFinish(tunnel_t *t, line_t *l)
{
    discard l;
    ++serverContext(t)->next_finish;
}

static tlsrecordshaping_config_t serverDelayConfig(void)
{
    tlsrecordshaping_config_t config = {
        .first_application_records = 1024,
        .outcome_count             = 1,
        .sender_role               = kTlsRecordShapingSenderServer,
        .enabled                   = true,
    };
    config.outcomes[0] = (tlsrecordshaping_outcome_t) {
        .delay_ms          = {.minimum = 1000, .maximum = 1000},
        .probability       = 100,
        .delay_probability = 100,
        .has_delay         = true,
    };
    return config;
}

static bool serverTransferBio(BIO *source, BIO *destination)
{
    uint8_t bytes[4096];
    while (BIO_ctrl_pending(source) > 0)
    {
        int read_length = BIO_read(source, bytes, (int) sizeof(bytes));
        if (read_length <= 0)
        {
            return false;
        }
        int offset = 0;
        while (offset < read_length)
        {
            int written = BIO_write(destination, bytes + offset, read_length - offset);
            if (written <= 0)
            {
                return false;
            }
            offset += written;
        }
    }
    return true;
}

static bool serverAdvanceHandshake(SSL *ssl, bool *complete)
{
    if (*complete)
    {
        return true;
    }
    int result = SSL_do_handshake(ssl);
    if (result == 1)
    {
        *complete = true;
        return true;
    }
    int error = SSL_get_error(ssl, result);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}

static void serverDriveHandshake(server_delay_fixture_t *fixture, tlsserver_lstate_t *ls)
{
    bool client_complete = false;
    bool server_complete = false;
    for (uint32_t step = 0; step < 100; ++step)
    {
        requireServer(serverAdvanceHandshake(fixture->client, &client_complete),
                      "delay lifecycle client handshake failed");
        requireServer(serverTransferBio(SSL_get_wbio(fixture->client), SSL_get_rbio(ls->ssl)),
                      "delay lifecycle client handshake transfer failed");
        requireServer(serverAdvanceHandshake(ls->ssl, &server_complete), "delay lifecycle TlsServer handshake failed");
        requireServer(serverTransferBio(SSL_get_wbio(ls->ssl), SSL_get_rbio(fixture->client)),
                      "delay lifecycle server handshake transfer failed");
        if (client_complete && server_complete)
        {
            requireServer(BIO_ctrl_pending(SSL_get_wbio(ls->ssl)) == 0,
                          "delay lifecycle server write BIO was not empty after handshake");
            ls->handshake_completed = true;
            return;
        }
    }
    requireServer(false, "delay lifecycle TLS 1.3 handshake did not complete");
}

static void serverFixtureSetup(server_delay_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));

    fixture->saved_workers_count = GSTATE.workers_count;
    fixture->saved_buffer_pools  = GSTATE.shortcut_buffer_pools;
    fixture->saved_loops         = GSTATE.shortcut_loops;
    GSTATE.workers_count         = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);

    fixture->large_master = masterpoolCreateWithCapacity(64);
    fixture->small_master = masterpoolCreateWithCapacity(8);
    fixture->pool         = bufferpoolCreate(fixture->large_master, fixture->small_master, 8, 32768, 1024);
    requireServer(fixture->large_master != NULL && fixture->small_master != NULL && fixture->pool != NULL,
                  "failed to create server lifecycle pools");
    bufferpoolUpdateAllocationPaddings(fixture->pool, 64, 64);
    fixture->buffer_pools[0]     = fixture->pool;
    GSTATE.shortcut_buffer_pools = fixture->buffer_pools;
    fixture->loops[0]            = wloopCreate(0, fixture->pool, 0);
    GSTATE.shortcut_loops        = fixture->loops;
    requireServer(fixture->loops[0] != NULL, "failed to create server lifecycle loop");

    fixture->prev = tunnelCreate(NULL, sizeof(server_delay_context_t *), 0);
    fixture->tls  = tunnelCreate(NULL, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(server_delay_context_t *), 0);
    requireServer(fixture->prev != NULL && fixture->tls != NULL && fixture->next != NULL,
                  "failed to create server lifecycle tunnels");
    tunnelBind(fixture->prev, fixture->tls);
    tunnelBind(fixture->tls, fixture->next);
    fixture->context.tls                                       = fixture->tls;
    *(server_delay_context_t **) tunnelGetState(fixture->prev) = &fixture->context;
    *(server_delay_context_t **) tunnelGetState(fixture->next) = &fixture->context;
    fixture->prev->fnPayloadD                                  = serverPrevPayload;
    fixture->prev->fnFinD                                      = serverPrevFinish;
    fixture->next->fnPayloadU                                  = serverNextPayload;
    fixture->next->fnEstU                                      = serverNextEst;
    fixture->next->fnPauseU                                    = serverNextPause;
    fixture->next->fnResumeU                                   = serverNextResume;
    fixture->next->fnFinU                                      = serverNextFinish;

    tlsrecordshaping_config_t config                                      = serverDelayConfig();
    ((tlsserver_tstate_t *) tunnelGetState(fixture->tls))->record_shaping = config;

    fixture->client_ctx = SSL_CTX_new(TLS_client_method());
    fixture->server_ctx = SSL_CTX_new(TLS_server_method());
    requireServer(fixture->client_ctx != NULL && fixture->server_ctx != NULL,
                  "failed to create server lifecycle SSL contexts");
    SSL_CTX_set_verify(fixture->client_ctx, SSL_VERIFY_NONE, NULL);
    requireServer(SSL_CTX_set_min_proto_version(fixture->client_ctx, TLS1_3_VERSION) == 1 &&
                      SSL_CTX_set_max_proto_version(fixture->client_ctx, TLS1_3_VERSION) == 1 &&
                      SSL_CTX_set_min_proto_version(fixture->server_ctx, TLS1_3_VERSION) == 1 &&
                      SSL_CTX_set_max_proto_version(fixture->server_ctx, TLS1_3_VERSION) == 1 &&
                      SSL_CTX_use_certificate_chain_file(fixture->server_ctx, TLSSERVER_TEST_CERT_FILE) == 1 &&
                      SSL_CTX_use_PrivateKey_file(fixture->server_ctx, TLSSERVER_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1,
                  "failed to configure server lifecycle SSL contexts");
    SSL_CTX_set_record_padding_callback(fixture->server_ctx, tlsserverRecordPaddingCallback);
    SSL_CTX_set_msg_callback(fixture->server_ctx, tlsserverRecordMessageCallback);

    fixture->line = memoryAllocateCacheAlignedZero(sizeof(line_t) + fixture->tls->lstate_size);
    requireServer(fixture->line != NULL, "failed to allocate server lifecycle line");
    atomic_init(&fixture->line->refc, 1);
    fixture->line->alive = true;
    fixture->line->wid   = 0;

    tlsserver_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    requireServer(tlsserverLinestateInitialize(ls, fixture->server_ctx, fixture->pool, &config, false),
                  "failed to initialize server lifecycle state");
    ls->tunnel              = fixture->tls;
    ls->line                = fixture->line;
    ls->protected_init_sent = true;

    fixture->client  = SSL_new(fixture->client_ctx);
    BIO *client_rbio = BIO_new(BIO_s_mem());
    BIO *client_wbio = BIO_new(BIO_s_mem());
    requireServer(fixture->client != NULL && client_rbio != NULL && client_wbio != NULL,
                  "failed to allocate server lifecycle client");
    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(SSL_get_rbio(ls->ssl), -1);
    BIO_set_mem_eof_return(SSL_get_wbio(ls->ssl), -1);
    SSL_set_bio(fixture->client, client_rbio, client_wbio);
    SSL_set_connect_state(fixture->client);
    serverDriveHandshake(fixture, ls);
}

static bool serverStateIsZero(const server_delay_fixture_t *fixture)
{
    const uint8_t *state = lineGetState(fixture->line, fixture->tls);
    for (uint32_t i = 0; i < fixture->tls->lstate_size; ++i)
    {
        if (state[i] != 0)
        {
            return false;
        }
    }
    return true;
}

static void serverFixtureTeardown(server_delay_fixture_t *fixture)
{
    tlsserver_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    if (ls->tunnel == fixture->tls)
    {
        tlsserverLinestateDestroy(ls);
    }
    requireServer(serverStateIsZero(fixture), "server lifecycle state was not zeroed");
    requireServer(atomic_load(&fixture->line->refc) == 1, "server lifecycle line reference leaked");

    memoryFreeAligned(fixture->line);
    SSL_free(fixture->client);
    SSL_CTX_free(fixture->client_ctx);
    SSL_CTX_free(fixture->server_ctx);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->tls);
    tunnelDestroy(fixture->next);
    wloopDestroy(&fixture->loops[0]);
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large_master);
    masterpoolMakeEmpty(fixture->small_master);
    masterpoolDestroy(fixture->large_master);
    masterpoolDestroy(fixture->small_master);

    GSTATE.workers_count = fixture->saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
    GSTATE.shortcut_buffer_pools = fixture->saved_buffer_pools;
    GSTATE.shortcut_loops        = fixture->saved_loops;
}

static sbuf_t *serverMakeBytes(server_delay_fixture_t *fixture, const uint8_t *bytes, uint32_t length)
{
    sbuf_t *buf = length <= bufferpoolGetSmallBufferSize(fixture->pool) ? bufferpoolGetSmallBuffer(fixture->pool)
                                                                        : bufferpoolGetLargeBuffer(fixture->pool);
    requireServer(length <= sbufGetMaximumWriteableSize(buf), "server lifecycle buffer is too small");
    sbufSetLength(buf, length);
    if (length > 0)
    {
        memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    }
    return buf;
}

static sbuf_t *serverDrainBio(server_delay_fixture_t *fixture, BIO *bio)
{
    size_t  pending = BIO_ctrl_pending(bio);
    sbuf_t *buf     = bufferpoolGetLargeBuffer(fixture->pool);
    requireServer(pending > 0 && pending <= sbufGetMaximumWriteableSize(buf),
                  "server lifecycle BIO output did not fit one large buffer");

    size_t length = 0;
    while (length < pending)
    {
        int n = BIO_read(bio, sbufGetMutablePtr(buf) + length, (int) (pending - length));
        requireServer(n > 0, "failed to drain server lifecycle BIO output");
        length += (size_t) n;
    }
    sbufSetLength(buf, length);
    return buf;
}

static void serverQueueRecordWithDelay(server_delay_fixture_t *fixture, uint32_t body_length, uint32_t delay_ms)
{
    requireServer(body_length > 0 && body_length <= kTlsRecordShapingMaxRecordBody,
                  "invalid server lifecycle record length");
    tlsserver_lstate_t *ls  = lineGetState(fixture->line, fixture->tls);
    sbuf_t             *buf = bufferpoolGetLargeBuffer(fixture->pool);
    requireServer(body_length + kTlsRecordShapingRecordHeaderSize <= sbufGetMaximumWriteableSize(buf),
                  "server lifecycle record exceeds its buffer");

    uint8_t *bytes = sbufGetMutablePtr(buf);
    bytes[0]       = SSL3_RT_APPLICATION_DATA;
    bytes[1]       = 0x03;
    bytes[2]       = 0x03;
    bytes[3]       = (uint8_t) (body_length >> 8U);
    bytes[4]       = (uint8_t) body_length;
    memorySet(bytes + kTlsRecordShapingRecordHeaderSize, 0x6b, body_length);
    sbufSetLength(buf, body_length + kTlsRecordShapingRecordHeaderSize);

    char error[kTlsRecordShapingErrorSize];
    requireServer(tlsrecordshapingOutputQueuePushMetadata(&ls->shaping_output, delay_ms) &&
                      tlsrecordshapingOutputQueueFeed(&ls->shaping_output, buf, wloopNowMS(fixture->loops[0]), error),
                  "failed to queue server lifecycle TLS record");
}

static void serverQueueRecord(server_delay_fixture_t *fixture, uint32_t body_length)
{
    serverQueueRecordWithDelay(fixture, body_length, 1000);
}

static void testServerPausedWatermarksEmitOnePauseResumePair(void)
{
    server_delay_fixture_t fixture;
    serverFixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.tls);

    tlsserverTunnelUpStreamPause(fixture.tls, fixture.line);
    requireServer(ls->shaping_wire_paused && fixture.context.next_pause == 1,
                  "server external Pause was not forwarded exactly once");

    while (tlsrecordshapingOutputQueueBytes(&ls->shaping_output) < kTlsRecordShapingQueueHighWatermark)
    {
        serverQueueRecord(&fixture, 18000);
    }
    requireServer(tlsserverDrainShapedOutput(fixture.tls, fixture.line, ls, false) && ls->shaping_producer_paused &&
                      fixture.context.next_pause == 1,
                  "server paused drain did not record high-water backpressure without a duplicate Pause");

    tlsserverTunnelUpStreamResume(fixture.tls, fixture.line);
    ls = lineGetState(fixture.line, fixture.tls);
    requireServer(! ls->shaping_wire_paused && ls->shaping_producer_paused && fixture.context.next_pause == 1 &&
                      fixture.context.next_resume == 0,
                  "server external Resume broke the shaping Pause transition");

    tlsserverCancelShapedOutputTimer(ls);
    requireServer(tlsserverDrainShapedOutput(fixture.tls, fixture.line, ls, true),
                  "server high-water queue did not force-drain");
    requireServer(tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output) && ! ls->shaping_producer_paused &&
                      fixture.context.next_pause == 1 && fixture.context.next_resume == 1,
                  "server low-water transition did not emit exactly one Resume");

    tlsserverLinestateDestroy(ls);
    serverFixtureTeardown(&fixture);
}

static void testServerDeferredFinishSuppressesIncomingPayload(void)
{
    static const uint8_t   plaintext[] = "deferred-server-finish";
    static const uint8_t   incoming[]  = {0x17, 0x03, 0x03, 0x00, 0x01, 0x00};
    server_delay_fixture_t fixture;
    serverFixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.tls);

    requireServer(tlsserverEncryptAndSendApplicationData(
                      fixture.tls, fixture.line, ls, serverMakeBytes(&fixture, plaintext, sizeof(plaintext))),
                  "server lifecycle fixture could not queue application ciphertext");
    requireServer(! tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output) && ls->shaping_output_timer != NULL,
                  "server lifecycle fixture did not defer application ciphertext");

    tlsserverTunnelDownStreamFinish(fixture.tls, fixture.line);
    ls = lineGetState(fixture.line, fixture.tls);
    requireServer(ls->downstream_finishing && ls->downstream_finish_deferred &&
                      tlsrecordshapingOutputQueueCount(&ls->shaping_output) >= 2,
                  "server Finish was not deferred behind application data and close_notify");

    tlsserverTunnelUpStreamPayload(fixture.tls, fixture.line, serverMakeBytes(&fixture, incoming, sizeof(incoming)));
    requireServer(fixture.context.next_payload == 0 && fixture.context.next_est == 0 &&
                      fixture.context.next_pause == 0 && fixture.context.next_resume == 0 &&
                      fixture.context.next_finish == 0,
                  "server deferred Finish reflected a callback toward its finished cleartext side");

    tlsserverCancelShapedOutputTimer(ls);
    requireServer(tlsserverDrainShapedOutput(fixture.tls, fixture.line, ls, true),
                  "server deferred Finish queue did not force-drain");
    ls = lineGetState(fixture.line, fixture.tls);
    requireServer(! tlsserverTryCompleteDeferredFinish(fixture.tls, fixture.line, ls),
                  "server deferred Finish did not complete when its queue emptied");
    requireServer(fixture.context.prev_payload >= 2 && fixture.context.prev_finish == 1 &&
                      fixture.context.next_payload == 0 && fixture.context.next_finish == 0 &&
                      serverStateIsZero(&fixture),
                  "server deferred Finish ordering or directional suppression changed");

    serverFixtureTeardown(&fixture);
}

static void testServerReentrantPauseSuppressesStaleResume(void)
{
    server_delay_fixture_t fixture;
    serverFixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    serverQueueRecordWithDelay(&fixture, 32, 0);
    serverQueueRecordWithDelay(&fixture, 32, 0);

    tlsserverTunnelUpStreamPause(fixture.tls, fixture.line);
    fixture.context.pause_on_prev_payload = true;
    tlsserverTunnelUpStreamResume(fixture.tls, fixture.line);

    ls = lineGetState(fixture.line, fixture.tls);
    requireServer(ls->shaping_wire_paused && tlsrecordshapingOutputQueueCount(&ls->shaping_output) == 1 &&
                      fixture.context.prev_payload == 1 && fixture.context.next_pause == 2 &&
                      fixture.context.next_resume == 0,
                  "server forwarded a stale Resume after a re-entrant wire Pause");

    tlsserverTunnelUpStreamResume(fixture.tls, fixture.line);
    requireServer(! ls->shaping_wire_paused && tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output) &&
                      fixture.context.prev_payload == 2 && fixture.context.next_resume == 1,
                  "server did not forward Resume after the later genuine wire Resume");

    tlsserverLinestateDestroy(ls);
    serverFixtureTeardown(&fixture);
}

static void testServerPeerFinishSuppressesBackpressureCallbacks(void)
{
    static const uint8_t   incoming[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0x00};
    server_delay_fixture_t fixture;
    serverFixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    ls->upstream_finished  = true;

    tlsserverTunnelUpStreamPayload(fixture.tls, fixture.line, serverMakeBytes(&fixture, incoming, sizeof(incoming)));
    requireServer(fixture.context.next_payload == 0,
                  "server forwarded Payload toward the peer-finished cleartext side");

    while (tlsrecordshapingOutputQueueBytes(&ls->shaping_output) < kTlsRecordShapingQueueHighWatermark)
    {
        serverQueueRecord(&fixture, 18000);
    }
    requireServer(tlsserverDrainShapedOutput(fixture.tls, fixture.line, ls, false) && ls->shaping_producer_paused &&
                      fixture.context.next_pause == 0,
                  "server sent shaping Pause toward the peer-finished side");
    requireServer(tlsserverDrainShapedOutput(fixture.tls, fixture.line, ls, true) && ! ls->shaping_producer_paused &&
                      fixture.context.next_resume == 0,
                  "server sent shaping Resume toward the peer-finished side");

    ls->shaping_wire_paused = true;
    tlsserverTunnelUpStreamResume(fixture.tls, fixture.line);
    requireServer(! ls->shaping_wire_paused && fixture.context.next_resume == 0,
                  "server forwarded wire Resume toward the peer-finished side");

    tlsserverLinestateDestroy(ls);
    serverFixtureTeardown(&fixture);
}

static void testServerReentrantCloseNotifySuppressesDecryptedPayload(void)
{
    static const uint8_t   client_plaintext[] = "outer-decrypted-payload";
    static const uint8_t   server_plaintext[] = "flush-reentry-trigger";
    server_delay_fixture_t fixture;
    serverFixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.tls);

    requireServer(SSL_write(fixture.client, client_plaintext, (int) sizeof(client_plaintext)) ==
                      (int) sizeof(client_plaintext),
                  "client could not encrypt the outer application payload");
    sbuf_t *client_application = serverDrainBio(&fixture, SSL_get_wbio(fixture.client));

    int shutdown_result = SSL_shutdown(fixture.client);
    requireServer(shutdown_result == 0 || shutdown_result == 1, "client could not emit close_notify");
    fixture.context.upstream_payload_on_prev_payload = serverDrainBio(&fixture, SSL_get_wbio(fixture.client));

    tlsserver_tstate_t *ts                          = tunnelGetState(fixture.tls);
    ts->record_shaping.outcomes[0].delay_ms.minimum = 0;
    ts->record_shaping.outcomes[0].delay_ms.maximum = 0;
    ls->shaping_writing_application                 = true;
    int server_write                = SSL_write(ls->ssl, server_plaintext, (int) sizeof(server_plaintext));
    ls->shaping_writing_application = false;
    requireServer(server_write == (int) sizeof(server_plaintext) && BIO_ctrl_pending(SSL_get_wbio(ls->ssl)) > 0,
                  "server could not prepare the output that triggers flush re-entry");

    tlsserverTunnelUpStreamPayload(fixture.tls, fixture.line, client_application);
    ls = lineGetState(fixture.line, fixture.tls);
    requireServer(ls->upstream_finished && fixture.context.upstream_payload_on_prev_payload == NULL &&
                      fixture.context.prev_payload == 1 && fixture.context.next_finish == 1 &&
                      fixture.context.next_payload == 0,
                  "server forwarded outer decrypted Payload after re-entrant close_notify Finish");

    tlsserverLinestateDestroy(ls);
    serverFixtureTeardown(&fixture);
}

static void testServerKeyUpdateFlushSurvivesReentrantCloseNotify(void)
{
    static const uint8_t   server_plaintext[] = "pending-before-key-update";
    server_delay_fixture_t fixture;
    serverFixtureSetup(&fixture);
    tlsserver_lstate_t *ls = lineGetState(fixture.line, fixture.tls);

    tlsserver_tstate_t *ts                          = tunnelGetState(fixture.tls);
    ts->record_shaping.outcomes[0].delay_ms.minimum = 0;
    ts->record_shaping.outcomes[0].delay_ms.maximum = 0;
    ls->shaping_writing_application                 = true;
    int server_write                = SSL_write(ls->ssl, server_plaintext, (int) sizeof(server_plaintext));
    ls->shaping_writing_application = false;
    requireServer(server_write == (int) sizeof(server_plaintext) && BIO_ctrl_pending(SSL_get_wbio(ls->ssl)) > 0,
                  "server could not prepare pending output before KeyUpdate");

    requireServer(SSL_key_update(fixture.client, SSL_KEY_UPDATE_REQUESTED) == 1 &&
                      SSL_do_handshake(fixture.client) == 1,
                  "client could not emit a requested TLS 1.3 KeyUpdate");
    sbuf_t *key_update = serverDrainBio(&fixture, SSL_get_wbio(fixture.client));

    int shutdown_result = SSL_shutdown(fixture.client);
    requireServer(shutdown_result == 0 || shutdown_result == 1, "client could not emit close_notify after KeyUpdate");
    fixture.context.upstream_payload_on_prev_payload = serverDrainBio(&fixture, SSL_get_wbio(fixture.client));

    tlsserverTunnelUpStreamPayload(fixture.tls, fixture.line, key_update);
    ls = lineGetState(fixture.line, fixture.tls);
    requireServer(ls->upstream_finished && fixture.context.upstream_payload_on_prev_payload == NULL &&
                      fixture.context.prev_payload == 1 && fixture.context.next_finish == 1 &&
                      fixture.context.next_payload == 0,
                  "server misclassified KeyUpdate WANT_READ after re-entrant close_notify");

    tlsserverLinestateDestroy(ls);
    serverFixtureTeardown(&fixture);
}

int main(void)
{
    requireServer(wCryptoGlobalInit() == kWCryptoOk, "OpenSSL global initialization failed");
    testServerPausedWatermarksEmitOnePauseResumePair();
    testServerDeferredFinishSuppressesIncomingPayload();
    testServerReentrantPauseSuppressesStaleResume();
    testServerPeerFinishSuppressesBackpressureCallbacks();
    testServerReentrantCloseNotifySuppressesDecryptedPayload();
    testServerKeyUpdateFlushSurvivesReentrantCloseNotify();
    wCryptoGlobalCleanup();
    printf("tlsserver_record_delay_lifecycle_test: all cases passed\n");
    return 0;
}
