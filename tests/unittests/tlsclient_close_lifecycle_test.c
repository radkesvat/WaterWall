#include "TlsClient/structure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct tlsclient_lifecycle_context_s
{
    char events[16];
    size_t events_len;
    bool kill_on_next_finish;
    bool saw_payload;
    bool begin_takeover_on_est;
    bool begin_takeover_succeeded;
    bool finish_downstream_on_next_payload;
    uint32_t downstream_est_count;
    uint32_t upstream_payload_count;
    BIO *upstream_capture;
    sbuf_t *pending_raw;
    tunnel_t *upstream_tunnel;
    tunnel_t *takeover_tls;
    SSL *coalesced_ticket_server;
    uint32_t coalesced_ticket_records;
    bool append_coalesced_tickets;
} tlsclient_lifecycle_context_t;

typedef struct tlsclient_lifecycle_fixture_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *pool;
    buffer_pool_t **saved_shortcuts;
    buffer_pool_t *shortcut[1];
    SSL_CTX *ssl_ctx;
    tunnel_t *prev;
    tunnel_t *tls;
    tunnel_t *next;
    line_t *line;
    tlsclient_lifecycle_context_t context;
} tlsclient_lifecycle_fixture_t;

static void requireTlsClient(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static sbuf_t *makeBytes(tlsclient_lifecycle_fixture_t *fixture, const uint8_t *bytes, uint32_t len);

static uint32_t countCompleteTlsRecords(const uint8_t *bytes, uint32_t len)
{
    uint32_t offset = 0;
    uint32_t count = 0;
    while (offset < len)
    {
        requireTlsClient(len - offset >= kTlsClientRecordHeaderSize,
                         "TlsClient real flight ended in a partial record header");
        uint32_t body_len = ((uint32_t) bytes[offset + 3] << 8U) |
                            (uint32_t) bytes[offset + 4];
        uint32_t record_len = kTlsClientRecordHeaderSize + body_len;
        requireTlsClient(record_len <= len - offset,
                         "TlsClient real flight ended in a partial record body");
        offset += record_len;
        ++count;
    }
    return count;
}

static void recordEvent(tlsclient_lifecycle_context_t *context, char event)
{
    requireTlsClient(context->events_len + 1 < sizeof(context->events), "TlsClient lifecycle event overflow");
    context->events[context->events_len++] = event;
    context->events[context->events_len] = '\0';
}

static tlsclient_lifecycle_context_t *testContext(tunnel_t *t)
{
    return *(tlsclient_lifecycle_context_t **) tunnelGetState(t);
}

static void fakePrevFinish(tunnel_t *t, line_t *l)
{
    discard l;
    recordEvent(testContext(t), 'D');
}

static void fakeNextFinish(tunnel_t *t, line_t *l)
{
    tlsclient_lifecycle_context_t *context = testContext(t);
    recordEvent(context, 'U');
    if (context->kill_on_next_finish)
    {
        l->alive = false;
    }
}

static void fakePrevEst(tunnel_t *t, line_t *l)
{
    tlsclient_lifecycle_context_t *context = testContext(t);
    ++context->downstream_est_count;
    if (context->begin_takeover_on_est)
    {
        requireTlsClient(context->pending_raw == NULL,
                         "TlsClient owner received duplicate takeover Est");
        context->begin_takeover_succeeded =
            tlsclientTunnelBeginTakeoverDrain(t->next, l, &context->pending_raw);
    }
}

static void fakePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tlsclient_lifecycle_context_t *context = testContext(t);
    context->saw_payload = true;
    bool is_upstream = t == context->upstream_tunnel;
    if (is_upstream)
    {
        ++context->upstream_payload_count;
        if (context->upstream_capture != NULL)
        {
            int len = (int) sbufGetLength(buf);
            requireTlsClient(BIO_write(context->upstream_capture, sbufGetRawPtr(buf), len) == len,
                             "TlsClient test could not capture upstream TLS bytes");
        }

        /*
         * Model a single transport callback which contains the server's final
         * handshake flight followed by tickets that become available while
         * the client Finished is synchronously delivered. Appending here is
         * equivalent to those bytes already being the unread suffix of the
         * callback: the takeover loop must publish Est at the Finished record
         * boundary and return the distinct ticket records through BeginDrain.
         */
        if (context->append_coalesced_tickets)
        {
            context->append_coalesced_tickets = false;
            requireTlsClient(context->coalesced_ticket_server != NULL &&
                                 context->takeover_tls != NULL &&
                                 SSL_accept(context->coalesced_ticket_server) == 1 &&
                                 SSL_write(context->coalesced_ticket_server, NULL, 0) == 0,
                             "TlsClient coalesced fixture could not complete and flush the server");

            BIO *server_wbio = SSL_get_wbio(context->coalesced_ticket_server);
            size_t pending = BIO_ctrl_pending(server_wbio);
            requireTlsClient(pending > 0 && pending <= UINT32_MAX,
                             "TlsClient coalesced fixture emitted no ticket flight");
            sbuf_t *tickets = pending <= bufferpoolGetSmallBufferSize(lineGetBufferPool(l))
                                  ? bufferpoolGetSmallBuffer(lineGetBufferPool(l))
                                  : bufferpoolGetLargeBuffer(lineGetBufferPool(l));
            requireTlsClient(pending <= sbufGetMaximumWriteableSize(tickets),
                             "TlsClient coalesced ticket flight exceeds its pooled buffer");
            sbufSetLength(tickets, (uint32_t) pending);
            requireTlsClient(BIO_read(server_wbio,
                                      sbufGetMutablePtr(tickets),
                                      (int) pending) == (int) pending,
                             "TlsClient coalesced fixture could not drain tickets");
            context->coalesced_ticket_records =
                countCompleteTlsRecords(sbufGetRawPtr(tickets), (uint32_t) pending);
            bufferstreamPush(&((tlsclient_lstate_t *)
                                   lineGetState(l, context->takeover_tls))->takeover_stream,
                             tickets);
        }
    }
    lineReuseBuffer(l, buf);
    if (is_upstream && context->finish_downstream_on_next_payload)
    {
        context->finish_downstream_on_next_payload = false;
        tlsclientTunnelDownStreamFinish(t->prev, l);
    }
}

static void fixtureInitialize(tlsclient_lifecycle_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));

    fixture->large_master = masterpoolCreateWithCapacity(8);
    fixture->small_master = masterpoolCreateWithCapacity(8);
    fixture->pool = bufferpoolCreate(fixture->large_master, fixture->small_master, 8, 65536, 1024);
    fixture->saved_shortcuts = GSTATE.shortcut_buffer_pools;
    fixture->shortcut[0] = fixture->pool;
    GSTATE.shortcut_buffer_pools = fixture->shortcut;

    fixture->ssl_ctx = SSL_CTX_new(TLS_client_method());
    requireTlsClient(fixture->ssl_ctx != NULL, "failed to create TlsClient test SSL_CTX");

    fixture->prev = tunnelCreate(NULL, sizeof(tlsclient_lifecycle_context_t *), 0);
    fixture->tls = tunnelCreate(NULL, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));
    fixture->next = tunnelCreate(NULL, sizeof(tlsclient_lifecycle_context_t *), 0);
    requireTlsClient(fixture->prev != NULL && fixture->tls != NULL && fixture->next != NULL,
                     "failed to create TlsClient lifecycle tunnels");

    tunnelBind(fixture->prev, fixture->tls);
    tunnelBind(fixture->tls, fixture->next);

    *(tlsclient_lifecycle_context_t **) tunnelGetState(fixture->prev) = &fixture->context;
    *(tlsclient_lifecycle_context_t **) tunnelGetState(fixture->next) = &fixture->context;

    fixture->prev->fnFinD = fakePrevFinish;
    fixture->prev->fnEstD = fakePrevEst;
    fixture->prev->fnPayloadD = fakePayload;
    fixture->next->fnFinU = fakeNextFinish;
    fixture->next->fnPayloadU = fakePayload;
    fixture->context.upstream_tunnel = fixture->next;
    fixture->context.takeover_tls = fixture->tls;
    tlsclientTunnelEnableHandshakeTakeover(fixture->tls);

    uint32_t line_size = sizeof(line_t) + fixture->tls->lstate_size;
    fixture->line = memoryAllocateCacheAlignedZero(line_size);
    requireTlsClient(fixture->line != NULL, "failed to allocate TlsClient lifecycle line");
    atomic_init(&fixture->line->refc, 1);
    fixture->line->alive = true;
    fixture->line->wid = 0;

    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    tlsclientLinestateInitialize(ls, fixture->ssl_ctx, fixture->pool);
    requireTlsClient(tlsclientConfigureSslForConnect(ls->ssl, ls->rbio, ls->wbio, "example.com", NULL, 0),
                     "failed to configure TlsClient lifecycle SSL object");
}

static void fixtureDestroy(tlsclient_lifecycle_fixture_t *fixture)
{
    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    const uint8_t *state = (const uint8_t *) ls;
    for (uint32_t i = 0; i < fixture->tls->lstate_size; ++i)
    {
        requireTlsClient(state[i] == 0, "TlsClient terminal path did not zero line state");
    }

    requireTlsClient(atomic_load(&fixture->line->refc) == 1, "TlsClient lifecycle line reference leaked");

    memoryFreeAligned(fixture->line);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->tls);
    tunnelDestroy(fixture->next);
    SSL_CTX_free(fixture->ssl_ctx);
    GSTATE.shortcut_buffer_pools = fixture->saved_shortcuts;
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large_master);
    masterpoolMakeEmpty(fixture->small_master);
    masterpoolDestroy(fixture->large_master);
    masterpoolDestroy(fixture->small_master);
}

static void requireScenario(tlsclient_lifecycle_fixture_t *fixture, const char *expected_events)
{
    requireTlsClient(strcmp(fixture->context.events, expected_events) == 0,
                     "TlsClient terminal callback ordering mismatch");
    requireTlsClient(! fixture->context.saw_payload, "TlsClient terminal path emitted payload");
}

static void testUpstreamFinishIsDirectional(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclientTunnelUpStreamFinish(fixture.tls, fixture.line);
    requireScenario(&fixture, "U");
    fixtureDestroy(&fixture);
}

static void testDownstreamFinishIsDirectional(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclientTunnelDownStreamFinish(fixture.tls, fixture.line);
    requireScenario(&fixture, "D");
    fixtureDestroy(&fixture);
}

static void testFatalCloseFinishesUpstreamThenDownstream(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclientCloseLineBidirectional(fixture.tls, fixture.line);
    requireScenario(&fixture, "UD");
    fixtureDestroy(&fixture);
}

static void testFatalCloseStopsWhenFirstFinishKillsLine(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    fixture.context.kill_on_next_finish = true;
    tlsclientCloseLineBidirectional(fixture.tls, fixture.line);
    requireScenario(&fixture, "U");
    requireTlsClient(! lineIsAlive(fixture.line), "TlsClient fatal close ignored line death");
    fixtureDestroy(&fixture);
}

static void testHandshakeTakeoverFinishStaysPayloadFree(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);

    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    ls->handshake_completed = true;
    sbuf_t *pending_raw = NULL;
    requireTlsClient(tlsclientTunnelDeinitAfterHandshake(fixture.tls, fixture.line, &pending_raw),
                     "TlsClient handshake takeover deinit failed");
    requireTlsClient(pending_raw == NULL, "TlsClient handshake takeover unexpectedly drained raw bytes");
    requireTlsClient(ls->resources_released && ls->takeover_phase == kTlsClientTakeoverPassthrough,
                     "TlsClient handshake takeover did not enter passthrough mode");

    tlsclientTunnelUpStreamFinish(fixture.tls, fixture.line);
    requireScenario(&fixture, "U");
    fixtureDestroy(&fixture);
}

static void testRetainedDrainStateIsDestroyedOnFinish(void)
{
    static const uint8_t partial_record[] = {SSL3_RT_APPLICATION_DATA, 0x03, 0x03};
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);

    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    ls->handshake_completed = true;
    ls->takeover_phase = kTlsClientTakeoverDrain;
    bufferstreamPush(&ls->takeover_stream,
                     makeBytes(&fixture, partial_record, sizeof(partial_record)));

    tlsclientTunnelUpStreamFinish(fixture.tls, fixture.line);
    requireScenario(&fixture, "U");
    fixtureDestroy(&fixture);
}

static sbuf_t *makeBytes(tlsclient_lifecycle_fixture_t *fixture, const uint8_t *bytes, uint32_t len)
{
    sbuf_t *buf = len <= bufferpoolGetSmallBufferSize(fixture->pool)
                      ? bufferpoolGetSmallBuffer(fixture->pool)
                      : bufferpoolGetLargeBuffer(fixture->pool);
    requireTlsClient(len <= sbufGetMaximumWriteableSize(buf), "TlsClient test buffer is too small");
    sbufSetLength(buf, len);
    if (len > 0)
    {
        memoryCopy(sbufGetMutablePtr(buf), bytes, len);
    }
    return buf;
}

static void testTakeoverAccumulatorSplitsAndCoalescesRecords(void)
{
    static const uint8_t records[] = {
        SSL3_RT_HANDSHAKE, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc,
        SSL3_RT_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x02, 0x11, 0x22,
    };

    for (uint32_t split = 1; split < 8; ++split)
    {
        tlsclient_lifecycle_fixture_t fixture;
        fixtureInitialize(&fixture);
        tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);

        bufferstreamPush(&ls->takeover_stream, makeBytes(&fixture, records, split));
        sbuf_t *record = NULL;
        bool invalid = false;
        requireTlsClient(! tlsclientTakeoverTryReadRecord(ls, &record, &invalid) && record == NULL && ! invalid,
                         "TlsClient extracted a partial takeover record");

        bufferstreamPush(&ls->takeover_stream, makeBytes(&fixture, records + split, 8U - split));
        requireTlsClient(tlsclientTakeoverTryReadRecord(ls, &record, &invalid) && ! invalid && record != NULL,
                         "TlsClient did not extract a complete fragmented takeover record");
        requireTlsClient(sbufGetLength(record) == 8 && memcmp(sbufGetRawPtr(record), records, 8) == 0,
                         "TlsClient changed fragmented takeover record bytes");
        lineReuseBuffer(fixture.line, record);

        tlsclientLinestateDestroy(ls);
        fixtureDestroy(&fixture);
    }

    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    bufferstreamPush(&ls->takeover_stream, makeBytes(&fixture, records, sizeof(records)));

    sbuf_t *first = NULL;
    sbuf_t *second = NULL;
    bool invalid = false;
    requireTlsClient(tlsclientTakeoverTryReadRecord(ls, &first, &invalid) && ! invalid,
                     "TlsClient did not extract first coalesced record");
    requireTlsClient(bufferstreamGetBufLen(&ls->takeover_stream) == 7,
                     "TlsClient consumed beyond first coalesced record boundary");
    requireTlsClient(tlsclientTakeoverTryReadRecord(ls, &second, &invalid) && ! invalid,
                     "TlsClient did not extract second coalesced record");
    requireTlsClient(sbufGetLength(first) == 8 && sbufGetLength(second) == 7 &&
                         memcmp(sbufGetRawPtr(first), records, 8) == 0 &&
                         memcmp(sbufGetRawPtr(second), records + 8, 7) == 0,
                     "TlsClient coalesced record extraction changed bytes or lengths");
    requireTlsClient(bufferstreamIsEmpty(&ls->takeover_stream),
                     "TlsClient left bytes after complete coalesced records");
    lineReuseBuffer(fixture.line, first);
    lineReuseBuffer(fixture.line, second);
    tlsclientLinestateDestroy(ls);
    fixtureDestroy(&fixture);
}

static void testTakeoverAccumulatorRejectsInvalidHeader(void)
{
    static const uint8_t invalid_record[] = {0x19, 0x03, 0x03, 0x00, 0x01, 0x00};
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    bufferstreamPush(&ls->takeover_stream,
                     makeBytes(&fixture, invalid_record, sizeof(invalid_record)));

    sbuf_t *record = NULL;
    bool invalid = false;
    requireTlsClient(! tlsclientTakeoverTryReadRecord(ls, &record, &invalid) && invalid && record == NULL,
                     "TlsClient accepted an invalid takeover record type");
    requireTlsClient(bufferstreamGetBufLen(&ls->takeover_stream) == sizeof(invalid_record),
                     "TlsClient consumed invalid takeover bytes before failure cleanup");

    tlsclientLinestateDestroy(ls);
    fixtureDestroy(&fixture);
}

static void testDrainModeBypassesTlsInBothDirections(void)
{
    static const uint8_t raw[] = {0x17, 0x03, 0x03, 0x00, 0x00};

    tlsclient_lifecycle_fixture_t upstream;
    fixtureInitialize(&upstream);
    tlsclient_lstate_t *up_ls = lineGetState(upstream.line, upstream.tls);
    up_ls->handshake_completed = true;
    up_ls->takeover_phase = kTlsClientTakeoverDrain;
    tlsclientTunnelUpStreamPayload(upstream.tls,
                                   upstream.line,
                                   makeBytes(&upstream, raw, sizeof(raw)));
    requireTlsClient(upstream.context.saw_payload,
                     "TlsClient drain mode passed owner-formatted bytes to SSL_write");
    tlsclientLinestateDestroy(up_ls);
    fixtureDestroy(&upstream);

    tlsclient_lifecycle_fixture_t downstream;
    fixtureInitialize(&downstream);
    tlsclient_lstate_t *down_ls = lineGetState(downstream.line, downstream.tls);
    down_ls->handshake_completed = true;
    down_ls->takeover_phase = kTlsClientTakeoverDrain;
    tlsclientTunnelDownStreamPayload(downstream.tls,
                                     downstream.line,
                                     makeBytes(&downstream, raw, sizeof(raw)));
    requireTlsClient(downstream.context.saw_payload,
                     "TlsClient drain mode did not forward raw cover bytes to its owner");
    tlsclientLinestateDestroy(down_ls);
    fixtureDestroy(&downstream);
}

static bool transferBio(BIO *source, BIO *destination)
{
    uint8_t bytes[4096];
    while (BIO_ctrl_pending(source) > 0)
    {
        int n = BIO_read(source, bytes, sizeof(bytes));
        if (n <= 0 || BIO_write(destination, bytes, n) != n)
        {
            return false;
        }
    }
    return true;
}

static bool driveTls13Handshake(SSL *client, SSL *server)
{
    bool client_done = false;
    bool server_done = false;

    for (uint32_t step = 0; step < 1000; ++step)
    {
        if (! client_done)
        {
            int n = SSL_connect(client);
            if (n == 1)
            {
                client_done = true;
            }
            else
            {
                int error = SSL_get_error(client, n);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                {
                    return false;
                }
            }
        }
        if (! transferBio(SSL_get_wbio(client), SSL_get_rbio(server)))
        {
            return false;
        }

        if (! server_done)
        {
            int n = SSL_accept(server);
            if (n == 1)
            {
                server_done = true;
            }
            else
            {
                int error = SSL_get_error(server, n);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                {
                    return false;
                }
            }
        }
        if (! transferBio(SSL_get_wbio(server), SSL_get_rbio(client)))
        {
            return false;
        }

        if (client_done && server_done)
        {
            return true;
        }
    }
    return false;
}

static sbuf_t *drainBioToBuffer(tlsclient_lifecycle_fixture_t *fixture, BIO *bio)
{
    size_t pending = BIO_ctrl_pending(bio);
    if (pending == 0 || pending > UINT32_MAX)
    {
        return NULL;
    }

    sbuf_t *buf = pending <= bufferpoolGetSmallBufferSize(fixture->pool)
                      ? bufferpoolGetSmallBuffer(fixture->pool)
                      : bufferpoolGetLargeBuffer(fixture->pool);
    requireTlsClient(pending <= sbufGetMaximumWriteableSize(buf),
                     "TlsClient test TLS flight exceeded the pooled buffer");
    sbufSetLength(buf, (uint32_t) pending);
    requireTlsClient(BIO_read(bio, sbufGetMutablePtr(buf), (int) pending) == (int) pending,
                     "TlsClient test could not drain a TLS flight");
    return buf;
}

static bool consumeRawFlight(tlsclient_lifecycle_fixture_t *fixture, sbuf_t *flight)
{
    if (flight == NULL)
    {
        return true;
    }

    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    bufferstreamPush(&ls->takeover_stream, flight);
    while (! bufferstreamIsEmpty(&ls->takeover_stream))
    {
        sbuf_t *record = NULL;
        bool invalid = false;
        if (! tlsclientTakeoverTryReadRecord(ls, &record, &invalid) || invalid || record == NULL)
        {
            return false;
        }
        if (tlsclientTunnelConsumePostHandshakeRecord(fixture->tls, fixture->line, record) !=
            kTlsClientPostHandshakeNeedMore)
        {
            return false;
        }
    }
    return true;
}

typedef struct tlsclient_real_flight_stats_s
{
    uint32_t records;
    uint32_t split_boundaries;
} tlsclient_real_flight_stats_t;

/*
 * Feed a real encrypted flight through the raw-record accumulator one byte at
 * a time. For a record of N bytes, this exercises all N-1 possible non-empty
 * transport split boundaries and proves no prefix is released early.
 */
static tlsclient_real_flight_stats_t
consumeRealFlightAtEveryByteBoundary(tlsclient_lifecycle_fixture_t *fixture,
                                     sbuf_t *flight)
{
    tlsclient_real_flight_stats_t stats = {0};
    if (flight == NULL)
    {
        return stats;
    }

    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    const uint8_t *bytes = sbufGetRawPtr(flight);
    uint32_t flight_len = sbufGetLength(flight);
    uint32_t offset = 0;

    while (offset < flight_len)
    {
        requireTlsClient(flight_len - offset >= kTlsClientRecordHeaderSize,
                         "TlsClient byte-split flight has a partial header");
        uint32_t body_len = ((uint32_t) bytes[offset + 3] << 8U) |
                            (uint32_t) bytes[offset + 4];
        uint32_t record_len = kTlsClientRecordHeaderSize + body_len;
        requireTlsClient(record_len <= flight_len - offset &&
                             bytes[offset] == SSL3_RT_APPLICATION_DATA,
                         "TlsClient byte-split fixture expected a complete protected TLS 1.3 record");

        for (uint32_t i = 0; i < record_len; ++i)
        {
            bufferstreamPush(&ls->takeover_stream,
                             makeBytes(fixture, bytes + offset + i, 1));
            sbuf_t *record = NULL;
            bool invalid = false;
            bool complete = tlsclientTakeoverTryReadRecord(ls, &record, &invalid);
            if (i + 1U < record_len)
            {
                requireTlsClient(! complete && ! invalid && record == NULL,
                                 "TlsClient released a real TLS 1.3 record before its final byte");
                ++stats.split_boundaries;
                continue;
            }

            requireTlsClient(complete && ! invalid && record != NULL &&
                                 sbufGetLength(record) == record_len &&
                                 memcmp(sbufGetRawPtr(record), bytes + offset, record_len) == 0,
                             "TlsClient changed a byte-split real TLS 1.3 record");
            requireTlsClient(tlsclientTunnelConsumePostHandshakeRecord(fixture->tls,
                                                                        fixture->line,
                                                                        record) ==
                                 kTlsClientPostHandshakeNeedMore,
                             "TlsClient rejected a byte-split real post-handshake record");
        }

        offset += record_len;
        ++stats.records;
    }

    requireTlsClient(bufferstreamIsEmpty(&ls->takeover_stream),
                     "TlsClient left bytes after byte-split real records");
    lineReuseBuffer(fixture->line, flight);
    return stats;
}

static SSL *createTls13Server(SSL_CTX **server_ctx_out, size_t tickets)
{
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    requireTlsClient(server_ctx != NULL &&
                         SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION) == 1 &&
                         SSL_CTX_set_max_proto_version(server_ctx, TLS1_3_VERSION) == 1 &&
                         SSL_CTX_set_num_tickets(server_ctx, tickets) == 1 &&
                         SSL_CTX_use_certificate_chain_file(server_ctx, REALITY_TEST_CERT_FILE) == 1 &&
                         SSL_CTX_use_PrivateKey_file(server_ctx,
                                                     REALITY_TEST_KEY_FILE,
                                                     SSL_FILETYPE_PEM) == 1 &&
                         SSL_CTX_check_private_key(server_ctx) == 1,
                     "failed to configure TlsClient test TLS 1.3 server");

    SSL *server = SSL_new(server_ctx);
    BIO *server_rbio = BIO_new(BIO_s_mem());
    BIO *server_wbio = BIO_new(BIO_s_mem());
    requireTlsClient(server != NULL && server_rbio != NULL && server_wbio != NULL,
                     "failed to allocate TlsClient test TLS 1.3 server state");
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);
    SSL_set_bio(server, server_rbio, server_wbio);
    SSL_set_accept_state(server);
    *server_ctx_out = server_ctx;
    return server;
}

static bool completeServerHandshake(SSL *server)
{
    for (uint32_t step = 0; step < 16; ++step)
    {
        int n = SSL_accept(server);
        if (n == 1)
        {
            return true;
        }
        int error = SSL_get_error(server, n);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
        {
            return false;
        }
        if (error == SSL_ERROR_WANT_READ && BIO_ctrl_pending(SSL_get_rbio(server)) == 0)
        {
            return false;
        }
    }
    return false;
}

static void testServerFinishedAndRealTicketsShareOneCallback(void)
{
    static const size_t ticket_counts[] = {1, 3};
    for (size_t ticket_index = 0;
         ticket_index < sizeof(ticket_counts) / sizeof(ticket_counts[0]);
         ++ticket_index)
    {
        size_t ticket_count = ticket_counts[ticket_index];
        tlsclient_lifecycle_fixture_t fixture;
        fixtureInitialize(&fixture);
        SSL_CTX *server_ctx = NULL;
        SSL *server = createTls13Server(&server_ctx, ticket_count);
        requireTlsClient(SSL_set_max_send_fragment(server, 512) == 1,
                         "failed to bound coalesced TlsClient server records");
        tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
        BIO_set_mem_eof_return(ls->rbio, -1);
        BIO_set_mem_eof_return(ls->wbio, -1);
        requireTlsClient(SSL_set_min_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                             SSL_set_max_proto_version(ls->ssl, TLS1_3_VERSION) == 1,
                         "failed to restrict coalesced TlsClient fixture to TLS 1.3");

        int n = SSL_connect(ls->ssl);
        requireTlsClient(n < 0 && SSL_get_error(ls->ssl, n) == SSL_ERROR_WANT_READ &&
                             transferBio(ls->wbio, SSL_get_rbio(server)),
                         "coalesced TlsClient fixture did not produce ClientHello");
        n = SSL_accept(server);
        int server_error = SSL_get_error(server, n);
        requireTlsClient(n < 0 &&
                             (server_error == SSL_ERROR_WANT_READ ||
                              server_error == SSL_ERROR_WANT_WRITE),
                         "coalesced TlsClient fixture did not produce the server Finished flight");
        sbuf_t *server_finished_flight =
            drainBioToBuffer(&fixture, SSL_get_wbio(server));
        requireTlsClient(server_finished_flight != NULL &&
                             countCompleteTlsRecords(sbufGetRawPtr(server_finished_flight),
                                                     sbufGetLength(server_finished_flight)) > 1,
                         "coalesced TlsClient fixture did not retain distinct handshake records");

        fixture.context.begin_takeover_on_est = true;
        fixture.context.upstream_capture = SSL_get_rbio(server);
        fixture.context.coalesced_ticket_server = server;
        fixture.context.append_coalesced_tickets = true;
        tlsclientTunnelDownStreamPayload(fixture.tls,
                                         fixture.line,
                                         server_finished_flight);

        requireTlsClient(lineIsAlive(fixture.line) &&
                             fixture.context.downstream_est_count == 1 &&
                             fixture.context.begin_takeover_succeeded &&
                             ! fixture.context.append_coalesced_tickets,
                         "TlsClient did not publish one takeover boundary for the coalesced callback");
        requireTlsClient(fixture.context.coalesced_ticket_records ==
                             (ticket_count == 1 ? 1U : 2U),
                         "TlsClient coalesced fixture did not generate the expected distinct ticket records");
        requireTlsClient(fixture.context.pending_raw != NULL &&
                             countCompleteTlsRecords(sbufGetRawPtr(fixture.context.pending_raw),
                                                     sbufGetLength(fixture.context.pending_raw)) ==
                                 fixture.context.coalesced_ticket_records &&
                             bufferstreamIsEmpty(&ls->takeover_stream),
                         "TlsClient did not stop at Finished and return all coalesced ticket records");

        tlsclient_real_flight_stats_t stats =
            consumeRealFlightAtEveryByteBoundary(&fixture,
                                                  fixture.context.pending_raw);
        fixture.context.pending_raw = NULL;
        requireTlsClient(stats.records == fixture.context.coalesced_ticket_records &&
                             stats.split_boundaries >= stats.records,
                         "TlsClient did not consume every coalesced ticket as a distinct real record");
        requireTlsClient(tlsclientTunnelCompleteTakeover(fixture.tls, fixture.line) &&
                             ls->resources_released &&
                             ls->takeover_phase == kTlsClientTakeoverPassthrough,
                         "TlsClient did not complete the coalesced-ticket takeover");

        SSL_free(server);
        SSL_CTX_free(server_ctx);
        tlsclientLinestateDestroy(ls);
        fixtureDestroy(&fixture);
    }
}

static SSL *enterRealTls13Drain(tlsclient_lifecycle_fixture_t *fixture,
                                SSL_CTX **server_ctx_out)
{
    SSL *server = createTls13Server(server_ctx_out, 0);
    tlsclient_lstate_t *ls = lineGetState(fixture->line, fixture->tls);
    BIO_set_mem_eof_return(ls->rbio, -1);
    BIO_set_mem_eof_return(ls->wbio, -1);
    requireTlsClient(SSL_set_min_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                         SSL_set_max_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                         driveTls13Handshake(ls->ssl, server),
                     "failed to establish TlsClient failure-path TLS 1.3 peer");

    sbuf_t *tail = drainBioToBuffer(fixture, ls->rbio);
    if (tail != NULL)
    {
        bufferstreamPush(&ls->takeover_stream, tail);
    }
    ls->handshake_completed = true;

    sbuf_t *pending_raw = NULL;
    requireTlsClient(tlsclientTunnelBeginTakeoverDrain(fixture->tls,
                                                       fixture->line,
                                                       &pending_raw) &&
                         consumeRawFlight(fixture, pending_raw),
                     "failed to enter TlsClient failure-path drain phase");
    fixture->context.upstream_capture = SSL_get_rbio(server);
    fixture->context.saw_payload = false;
    fixture->context.upstream_payload_count = 0;
    return server;
}

static tlsclient_post_handshake_result_t
consumeSingleRealRecord(tlsclient_lifecycle_fixture_t *fixture, sbuf_t *record)
{
    requireTlsClient(record != NULL && sbufGetLength(record) >= kTlsClientRecordHeaderSize,
                     "TlsClient test peer did not emit a TLS record");
    const uint8_t *bytes = (const uint8_t *) sbufGetRawPtr(record);
    uint32_t declared_len = ((uint32_t) bytes[3] << 8U) | (uint32_t) bytes[4];
    requireTlsClient(sbufGetLength(record) == kTlsClientRecordHeaderSize + declared_len,
                     "TlsClient test expected one complete TLS record");
    return tlsclientTunnelConsumePostHandshakeRecord(fixture->tls, fixture->line, record);
}

static void testPostHandshakeCloseNotifyClosesDirectly(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    SSL_CTX *server_ctx = NULL;
    SSL *server = enterRealTls13Drain(&fixture, &server_ctx);

    requireTlsClient(SSL_shutdown(server) == 0,
                     "TlsClient test peer did not emit TLS 1.3 close_notify");
    tlsclient_post_handshake_result_t result =
        consumeSingleRealRecord(&fixture,
                                drainBioToBuffer(&fixture, SSL_get_wbio(server)));
    requireTlsClient(result == kTlsClientPostHandshakeClose,
                     "TlsClient did not classify peer close_notify as a clean cover close");
    requireScenario(&fixture, "UD");
    requireTlsClient(fixture.context.upstream_payload_count == 0,
                     "TlsClient answered peer close_notify during authenticated handoff");

    SSL_free(server);
    SSL_CTX_free(server_ctx);
    fixtureDestroy(&fixture);
}

static void testPostHandshakeCorruptionClosesFatally(void)
{
    static const uint8_t cover_application[] = "corrupt this cover record";
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    SSL_CTX *server_ctx = NULL;
    SSL *server = enterRealTls13Drain(&fixture, &server_ctx);

    requireTlsClient(SSL_write(server, cover_application, sizeof(cover_application)) ==
                         (int) sizeof(cover_application),
                     "TlsClient test peer did not emit cover application data");
    sbuf_t *record = drainBioToBuffer(&fixture, SSL_get_wbio(server));
    requireTlsClient(record != NULL && sbufGetLength(record) > kTlsClientRecordHeaderSize,
                     "TlsClient test peer emitted an invalid cover application record");
    uint8_t *record_bytes = (uint8_t *) sbufGetMutablePtr(record);
    record_bytes[sbufGetLength(record) - 1] ^= 0x80U;

    requireTlsClient(consumeSingleRealRecord(&fixture, record) ==
                         kTlsClientPostHandshakeFatal,
                     "TlsClient did not classify corrupt cover ciphertext as fatal");
    requireScenario(&fixture, "UD");
    requireTlsClient(fixture.context.upstream_payload_count == 0,
                     "TlsClient emitted TLS output for corrupt cover ciphertext");

    SSL_free(server);
    SSL_CTX_free(server_ctx);
    fixtureDestroy(&fixture);
}

static void testPostHandshakeOutputReentryDestroysStateSafely(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    SSL_CTX *server_ctx = NULL;
    SSL *server = enterRealTls13Drain(&fixture, &server_ctx);

    requireTlsClient(SSL_key_update(server, SSL_KEY_UPDATE_REQUESTED) == 1 &&
                         SSL_write(server, NULL, 0) == 0,
                     "TlsClient test peer did not emit a requested KeyUpdate");
    fixture.context.finish_downstream_on_next_payload = true;
    tlsclient_post_handshake_result_t result =
        consumeSingleRealRecord(&fixture,
                                drainBioToBuffer(&fixture, SSL_get_wbio(server)));
    requireTlsClient(! fixture.context.finish_downstream_on_next_payload,
                     "TlsClient did not emit protocol output for the requested KeyUpdate");
    requireTlsClient(result == kTlsClientPostHandshakeFatal,
                     "TlsClient did not stop after synchronous destruction during protocol output");
    requireTlsClient(strcmp(fixture.context.events, "D") == 0,
                     "TlsClient reflected Finish after re-entrant downstream destruction");
    requireTlsClient(fixture.context.saw_payload && fixture.context.upstream_payload_count == 1,
                     "TlsClient did not emit exactly one KeyUpdate response before re-entrant close");

    SSL_free(server);
    SSL_CTX_free(server_ctx);
    fixtureDestroy(&fixture);
}

static void testTakeoverDownstreamPathStopsAtRealTls13RecordBoundary(void)
{
    static const uint8_t trailing_owner_record[] = {
        SSL3_RT_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x01, 0x42,
    };

    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    SSL_CTX *server_ctx = NULL;
    SSL *server = createTls13Server(&server_ctx, 2);

    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    BIO_set_mem_eof_return(ls->rbio, -1);
    BIO_set_mem_eof_return(ls->wbio, -1);
    requireTlsClient(SSL_set_min_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                         SSL_set_max_proto_version(ls->ssl, TLS1_3_VERSION) == 1,
                     "failed to restrict TlsClient test client to TLS 1.3");

    int n = SSL_connect(ls->ssl);
    requireTlsClient(n < 0 && SSL_get_error(ls->ssl, n) == SSL_ERROR_WANT_READ &&
                         transferBio(ls->wbio, SSL_get_rbio(server)),
                     "TlsClient test client did not produce its initial ClientHello");

    n = SSL_accept(server);
    requireTlsClient(n < 0 &&
                         (SSL_get_error(server, n) == SSL_ERROR_WANT_READ ||
                          SSL_get_error(server, n) == SSL_ERROR_WANT_WRITE),
                     "TlsClient test server did not produce its handshake flight");
    sbuf_t *server_flight = drainBioToBuffer(&fixture, SSL_get_wbio(server));
    requireTlsClient(server_flight != NULL && sbufGetLength(server_flight) > kTlsClientRecordHeaderSize,
                     "TlsClient test server handshake flight was empty");

    uint32_t flight_len = sbufGetLength(server_flight);
    uint8_t *flight_bytes = malloc(flight_len);
    requireTlsClient(flight_bytes != NULL, "TlsClient test could not copy the server handshake flight");
    memoryCopy(flight_bytes, sbufGetRawPtr(server_flight), flight_len);
    lineReuseBuffer(fixture.line, server_flight);

    fixture.context.begin_takeover_on_est = true;
    fixture.context.upstream_capture = SSL_get_rbio(server);

    /* Every byte boundary in the genuine server flight is also a transport
     * callback boundary. The final callback additionally contains the first
     * owner-formatted record, so completion must stop before consuming it. */
    for (uint32_t i = 0; i + 1 < flight_len; ++i)
    {
        tlsclientTunnelDownStreamPayload(fixture.tls,
                                         fixture.line,
                                         makeBytes(&fixture, flight_bytes + i, 1));
        requireTlsClient(lineIsAlive(fixture.line),
                         "TlsClient closed during byte-split real TLS 1.3 handshake");
    }

    uint8_t final_callback[1 + sizeof(trailing_owner_record)];
    final_callback[0] = flight_bytes[flight_len - 1];
    memoryCopy(final_callback + 1, trailing_owner_record, sizeof(trailing_owner_record));
    tlsclientTunnelDownStreamPayload(fixture.tls,
                                     fixture.line,
                                     makeBytes(&fixture, final_callback, sizeof(final_callback)));
    free(flight_bytes);

    requireTlsClient(lineIsAlive(fixture.line) && fixture.context.downstream_est_count == 1 &&
                         fixture.context.begin_takeover_succeeded && ls->handshake_completed &&
                         ls->takeover_phase == kTlsClientTakeoverDrain &&
                         tlsclientSslReadBoundaryIsClean(ls),
                     "TlsClient did not publish one clean callback-driven takeover boundary");
    requireTlsClient(fixture.context.pending_raw != NULL &&
                         sbufGetLength(fixture.context.pending_raw) == sizeof(trailing_owner_record) &&
                         memcmp(sbufGetRawPtr(fixture.context.pending_raw),
                                trailing_owner_record,
                                sizeof(trailing_owner_record)) == 0 &&
                         bufferstreamIsEmpty(&ls->takeover_stream),
                     "TlsClient fed or changed bytes after the handshake-completing TLS record");
    lineReuseBuffer(fixture.line, fixture.context.pending_raw);
    fixture.context.pending_raw = NULL;

    requireTlsClient(fixture.context.upstream_payload_count > 0 && completeServerHandshake(server),
                     "TlsClient callback-driven client Finished did not complete the server handshake");
    requireTlsClient(SSL_write(server, NULL, 0) == 0,
                     "TlsClient test server did not flush configured post-handshake tickets");
    sbuf_t *ticket_flight = drainBioToBuffer(&fixture, SSL_get_wbio(server));
    requireTlsClient(ticket_flight != NULL,
                     "TlsClient test server did not emit configured post-handshake tickets");
    fixture.context.saw_payload = false;
    requireTlsClient(consumeRawFlight(&fixture, ticket_flight) && ! fixture.context.saw_payload,
                     "TlsClient exposed or rejected post-handshake tickets after callback takeover");

    requireTlsClient(tlsclientTunnelCompleteTakeover(fixture.tls, fixture.line) &&
                         ls->resources_released && ls->ssl == NULL && ls->rbio == NULL &&
                         ls->wbio == NULL && bufferstreamIsEmpty(&ls->takeover_stream) &&
                         ls->takeover_phase == kTlsClientTakeoverPassthrough,
                     "TlsClient did not completely release callback-driven TLS 1.3 state");

    SSL_free(server);
    SSL_CTX_free(server_ctx);
    tlsclientLinestateDestroy(ls);
    fixtureDestroy(&fixture);
}

static void testPhasedTakeoverApisWithRealTls13(void)
{
    static const uint8_t cover_application[] = "cover application payload";
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);

    SSL_CTX *server_ctx = NULL;
    SSL *server = createTls13Server(&server_ctx, 2);

    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    BIO_set_mem_eof_return(ls->rbio, -1);
    BIO_set_mem_eof_return(ls->wbio, -1);
    requireTlsClient(SSL_set_min_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                         SSL_set_max_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                         driveTls13Handshake(ls->ssl, server),
                     "failed to complete TlsClient test TLS 1.3 handshake");

    /* The final server flight may contain post-handshake tickets. Keep those
     * bytes outside BoringSSL, exactly as the record-at-a-time path does. */
    sbuf_t *tail = drainBioToBuffer(&fixture, ls->rbio);
    if (tail != NULL)
    {
        bufferstreamPush(&ls->takeover_stream, tail);
    }
    ls->handshake_completed = true;

    sbuf_t *pending_raw = NULL;
    requireTlsClient(tlsclientTunnelBeginTakeoverDrain(fixture.tls, fixture.line, &pending_raw) &&
                         ls->takeover_phase == kTlsClientTakeoverDrain && ! ls->resources_released,
                     "TlsClient BeginTakeoverDrain did not retain TLS 1.3 state");
    sbuf_t *duplicate_begin = (sbuf_t *) (uintptr_t) 1;
    requireTlsClient(! tlsclientTunnelBeginTakeoverDrain(fixture.tls,
                                                         fixture.line,
                                                         &duplicate_begin) &&
                         duplicate_begin == NULL,
                     "TlsClient BeginTakeoverDrain was not one-shot");
    requireTlsClient(consumeRawFlight(&fixture, pending_raw),
                     "TlsClient did not consume queued TLS 1.3 post-handshake records");
    requireTlsClient(SSL_write(server, NULL, 0) == 0,
                     "TlsClient test server did not flush configured NewSessionTickets");
    fixture.context.saw_payload = false;
    requireTlsClient(consumeRawFlight(&fixture,
                                      drainBioToBuffer(&fixture, SSL_get_wbio(server))) &&
                         ! fixture.context.saw_payload,
                     "TlsClient did not consume configured NewSessionTickets without plaintext");

    requireTlsClient(SSL_write(server, cover_application, sizeof(cover_application)) ==
                         (int) sizeof(cover_application),
                     "TlsClient test server did not write cover application data");
    requireTlsClient(consumeRawFlight(&fixture, drainBioToBuffer(&fixture, SSL_get_wbio(server))),
                     "TlsClient did not discard cover application plaintext during drain");
    requireTlsClient(! fixture.context.saw_payload,
                     "TlsClient exposed cover application plaintext during drain");

    requireTlsClient(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED) == 1 &&
                         SSL_write(server, NULL, 0) == 0,
                     "TlsClient test server did not generate an unrequested KeyUpdate");
    fixture.context.saw_payload = false;
    requireTlsClient(consumeRawFlight(&fixture, drainBioToBuffer(&fixture, SSL_get_wbio(server))) &&
                         ! fixture.context.saw_payload,
                     "TlsClient emitted protocol output for an unrequested KeyUpdate");

    static const uint8_t application_after_key_update[] = "cover after key update";
    requireTlsClient(SSL_write(server,
                               application_after_key_update,
                               sizeof(application_after_key_update)) ==
                         (int) sizeof(application_after_key_update) &&
                         consumeRawFlight(&fixture,
                                          drainBioToBuffer(&fixture, SSL_get_wbio(server))),
                     "TlsClient did not advance read keys for an unrequested KeyUpdate");
    requireTlsClient(! fixture.context.saw_payload,
                     "TlsClient exposed cover plaintext after an unrequested KeyUpdate");

    requireTlsClient(SSL_key_update(server, SSL_KEY_UPDATE_REQUESTED) == 1 &&
                         SSL_write(server, NULL, 0) == 0,
                     "TlsClient test server did not generate a requested KeyUpdate");
    fixture.context.upstream_capture = SSL_get_rbio(server);
    fixture.context.saw_payload = false;
    requireTlsClient(consumeRawFlight(&fixture, drainBioToBuffer(&fixture, SSL_get_wbio(server))),
                     "TlsClient did not process a requested KeyUpdate");
    requireTlsClient(fixture.context.saw_payload,
                     "TlsClient did not flush the requested KeyUpdate response upstream");
    uint8_t server_plaintext[1];
    int server_read = SSL_read(server, server_plaintext, sizeof(server_plaintext));
    requireTlsClient(server_read < 0 &&
                         SSL_get_error(server, server_read) == SSL_ERROR_WANT_READ,
                     "TlsClient requested-KeyUpdate response was not valid for the TLS peer");

    ls->post_handshake_consume_in_progress = true;
    requireTlsClient(! tlsclientTunnelCompleteTakeover(fixture.tls, fixture.line) &&
                         ! ls->resources_released && ls->ssl != NULL,
                     "TlsClient completed takeover beneath an active cover-record consume");
    ls->post_handshake_consume_in_progress = false;
    requireTlsClient(tlsclientTunnelCompleteTakeover(fixture.tls, fixture.line) &&
                         ls->resources_released &&
                         ls->takeover_phase == kTlsClientTakeoverPassthrough,
                     "TlsClient CompleteTakeover did not release retained TLS state");
    requireTlsClient(! tlsclientTunnelCompleteTakeover(fixture.tls, fixture.line),
                     "TlsClient CompleteTakeover was not one-shot");

    static const uint8_t owner_raw[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0x7a};
    uint32_t upstream_before = fixture.context.upstream_payload_count;
    fixture.context.saw_payload = false;
    tlsclientTunnelUpStreamPayload(fixture.tls,
                                   fixture.line,
                                   makeBytes(&fixture, owner_raw, sizeof(owner_raw)));
    requireTlsClient(fixture.context.saw_payload &&
                         fixture.context.upstream_payload_count == upstream_before + 1U,
                     "TlsClient did not pass owner bytes upstream after CompleteTakeover");
    fixture.context.saw_payload = false;
    tlsclientTunnelDownStreamPayload(fixture.tls,
                                     fixture.line,
                                     makeBytes(&fixture, owner_raw, sizeof(owner_raw)));
    requireTlsClient(fixture.context.saw_payload &&
                         fixture.context.upstream_payload_count == upstream_before + 1U,
                     "TlsClient did not pass owner bytes downstream after CompleteTakeover");

    SSL_free(server);
    SSL_CTX_free(server_ctx);
    tlsclientLinestateDestroy(ls);
    fixtureDestroy(&fixture);
}

static void testRealTicketsAndKeyUpdatesAtEveryByteBoundary(void)
{
    tlsclient_lifecycle_fixture_t fixture;
    fixtureInitialize(&fixture);
    SSL_CTX *server_ctx = NULL;
    SSL *server = createTls13Server(&server_ctx, 3);
    requireTlsClient(SSL_set_max_send_fragment(server, 512) == 1,
                     "failed to bound byte-split TlsClient server records");
    tlsclient_lstate_t *ls = lineGetState(fixture.line, fixture.tls);
    BIO_set_mem_eof_return(ls->rbio, -1);
    BIO_set_mem_eof_return(ls->wbio, -1);
    requireTlsClient(SSL_set_min_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                         SSL_set_max_proto_version(ls->ssl, TLS1_3_VERSION) == 1 &&
                         driveTls13Handshake(ls->ssl, server),
                     "failed to establish byte-split TLS 1.3 fixture");

    /* Any ticket bytes already transferred after the client completed are raw
     * transport bytes. Drain them before Begin so the clean-boundary contract
     * is checked and each record can be replayed through the public consumer. */
    sbuf_t *ticket_tail = drainBioToBuffer(&fixture, ls->rbio);
    ls->handshake_completed = true;
    sbuf_t *pending_raw = NULL;
    requireTlsClient(tlsclientTunnelBeginTakeoverDrain(fixture.tls,
                                                       fixture.line,
                                                       &pending_raw) &&
                         pending_raw == NULL,
                     "TlsClient byte-split fixture did not enter drain mode once");

    tlsclient_real_flight_stats_t ticket_stats =
        consumeRealFlightAtEveryByteBoundary(&fixture, ticket_tail);
    requireTlsClient(SSL_write(server, NULL, 0) == 0,
                     "TlsClient byte-split fixture could not flush tickets");
    tlsclient_real_flight_stats_t flushed_ticket_stats =
        consumeRealFlightAtEveryByteBoundary(&fixture,
                                              drainBioToBuffer(&fixture,
                                                               SSL_get_wbio(server)));
    ticket_stats.records += flushed_ticket_stats.records;
    ticket_stats.split_boundaries += flushed_ticket_stats.split_boundaries;
    requireTlsClient(ticket_stats.records == 2 && ticket_stats.split_boundaries > 2,
                     "TlsClient byte-split fixture did not exercise both distinct ticket-bearing records");

    uint32_t output_before = fixture.context.upstream_payload_count;
    requireTlsClient(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED) == 1 &&
                         SSL_write(server, NULL, 0) == 0,
                     "TlsClient byte-split fixture could not emit unrequested KeyUpdate");
    tlsclient_real_flight_stats_t unrequested_stats =
        consumeRealFlightAtEveryByteBoundary(&fixture,
                                              drainBioToBuffer(&fixture,
                                                               SSL_get_wbio(server)));
    requireTlsClient(unrequested_stats.records == 1 &&
                         unrequested_stats.split_boundaries > 0 &&
                         fixture.context.upstream_payload_count == output_before,
                     "TlsClient byte-split unrequested KeyUpdate emitted a response");

    static const uint8_t after_unrequested[] = "read keys advanced";
    requireTlsClient(SSL_write(server,
                               after_unrequested,
                               sizeof(after_unrequested)) ==
                             (int) sizeof(after_unrequested),
                     "TlsClient byte-split fixture could not write after KeyUpdate");
    tlsclient_real_flight_stats_t application_stats =
        consumeRealFlightAtEveryByteBoundary(&fixture,
                                              drainBioToBuffer(&fixture,
                                                               SSL_get_wbio(server)));
    requireTlsClient(application_stats.records == 1 &&
                         fixture.context.upstream_payload_count == output_before,
                     "TlsClient byte-split fixture did not advance read keys or discard cover plaintext");

    requireTlsClient(SSL_key_update(server, SSL_KEY_UPDATE_REQUESTED) == 1 &&
                         SSL_write(server, NULL, 0) == 0,
                     "TlsClient byte-split fixture could not emit requested KeyUpdate");
    fixture.context.upstream_capture = SSL_get_rbio(server);
    tlsclient_real_flight_stats_t requested_stats =
        consumeRealFlightAtEveryByteBoundary(&fixture,
                                              drainBioToBuffer(&fixture,
                                                               SSL_get_wbio(server)));
    requireTlsClient(requested_stats.records == 1 &&
                         requested_stats.split_boundaries > 0 &&
                         fixture.context.upstream_payload_count == output_before + 1U,
                     "TlsClient byte-split requested KeyUpdate did not flush one response");
    uint8_t unused[1];
    int read_result = SSL_read(server, unused, sizeof(unused));
    requireTlsClient(read_result < 0 &&
                         SSL_get_error(server, read_result) == SSL_ERROR_WANT_READ,
                     "TlsClient byte-split KeyUpdate response was invalid at the real peer");

    requireTlsClient(tlsclientTunnelCompleteTakeover(fixture.tls, fixture.line) &&
                         ls->resources_released && ls->ssl == NULL && ls->rbio == NULL &&
                         ls->wbio == NULL && bufferstreamIsEmpty(&ls->takeover_stream),
                     "TlsClient byte-split fixture did not release all retained state");
    SSL_free(server);
    SSL_CTX_free(server_ctx);
    tlsclientLinestateDestroy(ls);
    fixtureDestroy(&fixture);
}

int main(void)
{
    testUpstreamFinishIsDirectional();
    testDownstreamFinishIsDirectional();
    testFatalCloseFinishesUpstreamThenDownstream();
    testFatalCloseStopsWhenFirstFinishKillsLine();
    testHandshakeTakeoverFinishStaysPayloadFree();
    testRetainedDrainStateIsDestroyedOnFinish();
    testTakeoverAccumulatorSplitsAndCoalescesRecords();
    testTakeoverAccumulatorRejectsInvalidHeader();
    testDrainModeBypassesTlsInBothDirections();
    testServerFinishedAndRealTicketsShareOneCallback();
    testTakeoverDownstreamPathStopsAtRealTls13RecordBoundary();
    testPhasedTakeoverApisWithRealTls13();
    testRealTicketsAndKeyUpdatesAtEveryByteBoundary();
    testPostHandshakeCloseNotifyClosesDirectly();
    testPostHandshakeCorruptionClosesFatally();
    testPostHandshakeOutputReentryDestroysStateSafely();
    return 0;
}
