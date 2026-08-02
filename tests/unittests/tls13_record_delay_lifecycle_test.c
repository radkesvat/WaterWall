#include "TlsClient/structure.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

typedef struct client_delay_context_s
{
    tunnel_t *tls;
    uint32_t  prev_payload;
    uint32_t  prev_est;
    uint32_t  prev_pause;
    uint32_t  prev_resume;
    uint32_t  prev_finish;
    uint32_t  next_payload;
    uint32_t  next_finish;
    bool      reenter_finished_client;
    bool      pause_on_next_payload;
    bool      destroy_during_drain;
} client_delay_context_t;

typedef struct client_delay_fixture_s
{
    master_pool_t         *large_master;
    master_pool_t         *small_master;
    buffer_pool_t         *pool;
    buffer_pool_t        **saved_buffer_pools;
    buffer_pool_t         *buffer_pools[1];
    wloop_t              **saved_loops;
    wloop_t               *loops[1];
    uint32_t               saved_workers_count;
    SSL_CTX               *ssl_ctx;
    tunnel_t              *prev;
    tunnel_t              *tls;
    tunnel_t              *next;
    line_t                *line;
    client_delay_context_t context;
} client_delay_fixture_t;

int  __wrap_WW_BSSL_SSL_version(const SSL *ssl);
void tls13RecordDelayClientCases(void);

int __wrap_WW_BSSL_SSL_version(const SSL *ssl)
{
    discard ssl;
    return TLS1_3_VERSION;
}

static void requireClient(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static client_delay_context_t *clientContext(tunnel_t *t)
{
    return *(client_delay_context_t **) tunnelGetState(t);
}

static sbuf_t *clientMakeBytes(line_t *l, const uint8_t *bytes, uint32_t length)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *buf =
        length <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBuffer(pool) : bufferpoolGetLargeBuffer(pool);
    requireClient(length <= sbufGetMaximumWriteableSize(buf), "client lifecycle buffer is too small");
    sbufSetLength(buf, length);
    if (length > 0)
    {
        memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    }
    return buf;
}

static void clientPrevPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ++clientContext(t)->prev_payload;
    lineReuseBuffer(l, buf);
}

static void clientPrevEst(tunnel_t *t, line_t *l)
{
    discard l;
    ++clientContext(t)->prev_est;
}

static void clientPrevPause(tunnel_t *t, line_t *l)
{
    discard l;
    ++clientContext(t)->prev_pause;
}

static void clientPrevResume(tunnel_t *t, line_t *l)
{
    discard l;
    ++clientContext(t)->prev_resume;
}

static void clientPrevFinish(tunnel_t *t, line_t *l)
{
    discard l;
    ++clientContext(t)->prev_finish;
}

static void clientNextPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    static const uint8_t    incoming[] = {0xde, 0xad, 0xbe, 0xef};
    client_delay_context_t *context    = clientContext(t);
    ++context->next_payload;
    lineReuseBuffer(l, buf);

    if (context->reenter_finished_client)
    {
        context->reenter_finished_client = false;
        tlsclientTunnelDownStreamPayload(context->tls, l, clientMakeBytes(l, incoming, sizeof(incoming)));
        tlsclientTunnelDownStreamEst(context->tls, l);
        tlsclientTunnelDownStreamPause(context->tls, l);
        tlsclientTunnelDownStreamResume(context->tls, l);
    }

    if (context->pause_on_next_payload)
    {
        context->pause_on_next_payload = false;
        tlsclientTunnelDownStreamPause(context->tls, l);
    }

    if (context->destroy_during_drain)
    {
        context->destroy_during_drain = false;
        tlsclientLinestateDestroy(lineGetState(l, context->tls));
        l->alive = false;
    }
}

static void clientNextFinish(tunnel_t *t, line_t *l)
{
    discard l;
    ++clientContext(t)->next_finish;
}

static tlsrecordshaping_config_t clientDelayConfig(void)
{
    tlsrecordshaping_config_t config = {
        .first_application_records = 1024,
        .outcome_count             = 1,
        .sender_role               = kTlsRecordShapingSenderClient,
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

static void clientFixtureSetup(client_delay_fixture_t *fixture)
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
    requireClient(fixture->large_master != NULL && fixture->small_master != NULL && fixture->pool != NULL,
                  "failed to create client lifecycle pools");
    bufferpoolUpdateAllocationPaddings(fixture->pool, 64, 64);

    fixture->buffer_pools[0]     = fixture->pool;
    GSTATE.shortcut_buffer_pools = fixture->buffer_pools;
    fixture->loops[0]            = wloopCreate(0, fixture->pool, 0);
    GSTATE.shortcut_loops        = fixture->loops;
    requireClient(fixture->loops[0] != NULL, "failed to create client lifecycle loop");

    fixture->prev = tunnelCreate(NULL, sizeof(client_delay_context_t *), 0);
    fixture->tls  = tunnelCreate(NULL, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(client_delay_context_t *), 0);
    requireClient(fixture->prev != NULL && fixture->tls != NULL && fixture->next != NULL,
                  "failed to create client lifecycle tunnels");
    tunnelBind(fixture->prev, fixture->tls);
    tunnelBind(fixture->tls, fixture->next);

    fixture->context.tls                                       = fixture->tls;
    *(client_delay_context_t **) tunnelGetState(fixture->prev) = &fixture->context;
    *(client_delay_context_t **) tunnelGetState(fixture->next) = &fixture->context;
    fixture->prev->fnPayloadD                                  = clientPrevPayload;
    fixture->prev->fnEstD                                      = clientPrevEst;
    fixture->prev->fnPauseD                                    = clientPrevPause;
    fixture->prev->fnResumeD                                   = clientPrevResume;
    fixture->prev->fnFinD                                      = clientPrevFinish;
    fixture->next->fnPayloadU                                  = clientNextPayload;
    fixture->next->fnFinU                                      = clientNextFinish;

    tlsrecordshaping_config_t config                                      = clientDelayConfig();
    ((tlsclient_tstate_t *) tunnelGetState(fixture->tls))->record_shaping = config;

    fixture->ssl_ctx = SSL_CTX_new(TLS_client_method());
    requireClient(fixture->ssl_ctx != NULL, "failed to create client lifecycle SSL_CTX");

    fixture->line = memoryAllocateCacheAlignedZero(sizeof(line_t) + fixture->tls->lstate_size);
    requireClient(fixture->line != NULL, "failed to allocate client lifecycle line");
    atomic_init(&fixture->line->refc, 1);
    fixture->line->alive = true;
    fixture->line->wid   = 0;

    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    requireClient(tlsclientLinestateInitializeWithShaping(ls, fixture->ssl_ctx, fixture->pool, NULL, 0, &config, false),
                  "failed to initialize client lifecycle state");
    ls->tunnel              = fixture->tls;
    ls->line                = fixture->line;
    ls->handshake_completed = true;
}

static bool clientStateIsZero(const client_delay_fixture_t *fixture)
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

static void clientFixtureTeardown(client_delay_fixture_t *fixture)
{
    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    if (ls->tunnel == fixture->tls)
    {
        tlsclientLinestateDestroy(ls);
    }
    requireClient(clientStateIsZero(fixture), "client lifecycle state was not zeroed");
    requireClient(atomic_load(&fixture->line->refc) == 1, "client lifecycle line reference leaked");

    memoryFreeAligned(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->tls);
    tunnelDestroy(fixture->next);
    SSL_CTX_free(fixture->ssl_ctx);
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

static void clientQueueRecordWithDelay(client_delay_fixture_t *fixture, uint32_t body_length, uint32_t delay_ms)
{
    requireClient(body_length > 0 && body_length <= kTlsRecordShapingMaxRecordBody,
                  "invalid client lifecycle record length");
    tlsclient_lstate_t *ls  = lineGetState(fixture->line, fixture->tls);
    sbuf_t             *buf = bufferpoolGetLargeBuffer(fixture->pool);
    requireClient(body_length + kTlsRecordShapingRecordHeaderSize <= sbufGetMaximumWriteableSize(buf),
                  "client lifecycle record exceeds its buffer");

    uint8_t *bytes = sbufGetMutablePtr(buf);
    bytes[0]       = SSL3_RT_APPLICATION_DATA;
    bytes[1]       = 0x03;
    bytes[2]       = 0x03;
    bytes[3]       = (uint8_t) (body_length >> 8U);
    bytes[4]       = (uint8_t) body_length;
    memorySet(bytes + kTlsRecordShapingRecordHeaderSize, 0x5a, body_length);
    sbufSetLength(buf, body_length + kTlsRecordShapingRecordHeaderSize);

    char error[kTlsRecordShapingErrorSize];
    requireClient(tlsrecordshapingOutputQueuePushMetadata(&ls->shaping_output, delay_ms) &&
                      tlsrecordshapingOutputQueueFeed(&ls->shaping_output, buf, wloopNowMS(fixture->loops[0]), error),
                  "failed to queue client lifecycle TLS record");
}

static void clientQueueRecord(client_delay_fixture_t *fixture, uint32_t body_length)
{
    clientQueueRecordWithDelay(fixture, body_length, 1000);
}

static void testClientFinalDrainSuppressesReentrantCallbacks(void)
{
    client_delay_fixture_t fixture;
    clientFixtureSetup(&fixture);
    clientQueueRecord(&fixture, 32);

    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    requireClient(tlsclientScheduleShapedOutput(fixture.tls, fixture.line, ls) && ls->shaping_output_timer != NULL,
                  "client final-drain fixture did not arm its timer");
    fixture.context.reenter_finished_client = true;

    tlsclientTunnelUpStreamFinish(fixture.tls, fixture.line);

    requireClient(fixture.context.next_payload == 1 && fixture.context.next_finish == 1,
                  "client final drain did not send one record followed by Finish");
    requireClient(fixture.context.prev_payload == 0 && fixture.context.prev_est == 0 &&
                      fixture.context.prev_pause == 0 && fixture.context.prev_resume == 0 &&
                      fixture.context.prev_finish == 0,
                  "client final drain reflected a callback toward its finished owner");
    requireClient(clientStateIsZero(&fixture), "client final drain left timer or TLS state alive");
    clientFixtureTeardown(&fixture);
}

static void testClientPausedWatermarksEmitOnePauseResumePair(void)
{
    client_delay_fixture_t fixture;
    clientFixtureSetup(&fixture);
    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);

    tlsclientTunnelDownStreamPause(fixture.tls, fixture.line);
    requireClient(ls->shaping_wire_paused && fixture.context.prev_pause == 1,
                  "client external Pause was not forwarded exactly once");

    while (tlsrecordshapingOutputQueueBytes(&ls->shaping_output) < kTlsRecordShapingQueueHighWatermark)
    {
        clientQueueRecord(&fixture, 18000);
    }
    requireClient(tlsclientDrainShapedOutput(fixture.tls, fixture.line, ls, false) && ls->shaping_producer_paused &&
                      fixture.context.prev_pause == 1,
                  "client paused drain did not record high-water backpressure without a duplicate Pause");

    tlsclientTunnelDownStreamResume(fixture.tls, fixture.line);
    ls = lineGetState(fixture.line, fixture.tls);
    requireClient(! ls->shaping_wire_paused && ls->shaping_producer_paused && fixture.context.prev_pause == 1 &&
                      fixture.context.prev_resume == 0,
                  "client external Resume broke the shaping Pause transition");

    tlsclientCancelShapedOutputTimer(ls);
    requireClient(tlsclientDrainShapedOutput(fixture.tls, fixture.line, ls, true),
                  "client high-water queue did not force-drain");
    requireClient(tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output) && ! ls->shaping_producer_paused &&
                      fixture.context.prev_pause == 1 && fixture.context.prev_resume == 1,
                  "client low-water transition did not emit exactly one Resume");

    tlsclientLinestateDestroy(ls);
    clientFixtureTeardown(&fixture);
}

static void testClientDrainStopsAfterReentrantLineDeath(void)
{
    client_delay_fixture_t fixture;
    clientFixtureSetup(&fixture);
    clientQueueRecord(&fixture, 32);
    fixture.context.destroy_during_drain = true;

    tlsclientTunnelUpStreamFinish(fixture.tls, fixture.line);

    requireClient(! lineIsAlive(fixture.line) && fixture.context.next_payload == 1 &&
                      fixture.context.next_finish == 0 && clientStateIsZero(&fixture),
                  "client final drain touched destroyed state or forwarded Finish after line death");
    clientFixtureTeardown(&fixture);
}

static void testClientReentrantPauseSuppressesStaleResume(void)
{
    client_delay_fixture_t fixture;
    clientFixtureSetup(&fixture);
    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    clientQueueRecordWithDelay(&fixture, 32, 0);
    clientQueueRecordWithDelay(&fixture, 32, 0);

    tlsclientTunnelDownStreamPause(fixture.tls, fixture.line);
    fixture.context.pause_on_next_payload = true;
    tlsclientTunnelDownStreamResume(fixture.tls, fixture.line);

    ls = lineGetState(fixture.line, fixture.tls);
    requireClient(ls->shaping_wire_paused && tlsrecordshapingOutputQueueCount(&ls->shaping_output) == 1 &&
                      fixture.context.next_payload == 1 && fixture.context.prev_pause == 2 &&
                      fixture.context.prev_resume == 0,
                  "client forwarded a stale Resume after a re-entrant wire Pause");

    tlsclientTunnelDownStreamResume(fixture.tls, fixture.line);
    requireClient(! ls->shaping_wire_paused && tlsrecordshapingOutputQueueIsEmpty(&ls->shaping_output) &&
                      fixture.context.next_payload == 2 && fixture.context.prev_resume == 1,
                  "client did not forward Resume after the later genuine wire Resume");

    tlsclientLinestateDestroy(ls);
    clientFixtureTeardown(&fixture);
}

void tls13RecordDelayClientCases(void)
{
    testClientFinalDrainSuppressesReentrantCallbacks();
    testClientPausedWatermarksEmitOnePauseResumePair();
    testClientDrainStopsAfterReentrantLineDeath();
    testClientReentrantPauseSuppressesStaleResume();
}

int main(void)
{
    tls13RecordDelayClientCases();
    printf("tls13_record_delay_lifecycle_test: all cases passed\n");
    return 0;
}
