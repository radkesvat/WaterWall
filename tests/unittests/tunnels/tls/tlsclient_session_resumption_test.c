/*
 * Covers: Ordinary TlsClient session reuse, cache bounds and authentication, fresh raw ClientHellos,
 * and TLS 1.3 ticket processing during handshake takeover.
 * Setup: Real constructor/Init/payload paths, one registered worker, owned scratch normal lines, and
 * an in-memory BoringSSL server. Neighbors copy wire output into the peer BIO and settle buffers.
 * Cases: TLS 1.2/1.3 reuse and refusal, single-use eviction, expiration and future timestamps,
 * context/SNI/verify isolation, trust removal, oversized tickets, static-RSA exclusion, and takeover
 * with/without tickets.
 * Checks: Offered ticket bytes, actual SSL_session_reused on both peers, application payloads,
 * certificate rejection, fresh matching takeover bindings, and clean TLS release.
 * Limits: No network timing, persistent cache, 0-RTT, or whole Reality control exchange is modeled.
 * CTest: waterwall.tlsclient_session_resumption_unit
 */
#include "TlsClient/structure.h"

#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"
#include "tls_client_hello.h"

#include <openssl/bytestring.h>
#include <openssl/x509.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct session_fixture_s
{
    test_worker_registry_t        registry;
    uint32_t                      saved_workers;
    wid_t                         saved_wid;
    buffer_pool_t               **saved_pools;
    master_pool_t                *masters[4];
    buffer_pool_t                *pools[1];
    cJSON                        *settings;
    node_t                        node;
    tunnel_t                     *tls;
    tunnel_t                     *prev;
    tunnel_t                     *next;
    SSL_CTX                      *client_context;
    SSL_CTX                      *server_context;
    SSL                          *server;
    line_t                       *line;
    sbuf_t                       *hello;
    SSL_new_session_cb            cache_callback;
    SSL_SESSION                  *sessions[12];
    size_t                        session_count;
    uint32_t                      plaintext_bytes;
    uint32_t                      ready_count;
    bool                          takeover;
    tlsclient_handshake_binding_t binding;
} session_fixture_t;

/* This suite drives one connection synchronously on its registered worker. */
static session_fixture_t *active_fixture;

static int rememberSession(SSL *ssl, SSL_SESSION *session)
{
    session_fixture_t *f = active_fixture;
    require(f->session_count < ARRAY_SIZE(f->sessions) && SSL_SESSION_up_ref(session) == 1,
            "session fixture exhausted its retained callback references");
    f->sessions[f->session_count++] = session;
    /* Preserve the real callback's reference-ownership decision. */
    return f->cache_callback(ssl, session);
}

static void nextInit(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

static void nextPayload(tunnel_t *t, line_t *line, sbuf_t *buffer)
{
    discard            t;
    session_fixture_t *f   = active_fixture;
    uint32_t           len = sbufGetLength(buffer);
    if (f->hello == NULL)
    {
        f->hello = bufferpoolGetBestFit(f->pools[0], len, 0);
        sbufWrite(f->hello, sbufGetRawPtr(buffer), len);
        sbufSetLength(f->hello, len);
    }
    require(BIO_write(SSL_get_rbio(f->server), sbufGetRawPtr(buffer), (int) len) == (int) len,
            "server BIO rejected client wire output");
    lineReuseBuffer(line, buffer);
}

static void prevPayload(tunnel_t *t, line_t *line, sbuf_t *buffer)
{
    discard t;
    active_fixture->plaintext_bytes += sbufGetLength(buffer);
    require(sbufGetLength(buffer) == 4 && memoryCompare(sbufGetRawPtr(buffer), "pong", 4) == 0,
            "ordinary TLS connection delivered incorrect application data");
    lineReuseBuffer(line, buffer);
}

static void nextFinish(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

static void prevFinish(tunnel_t *t, line_t *line)
{
    discard t;
    /* The fixture is the normal-line owner and retains its allocation until cleanup. */
    line->alive = false;
}

static void handshakeReady(tunnel_t *owner, line_t *line)
{
    discard            owner;
    session_fixture_t *f       = active_fixture;
    sbuf_t            *pending = NULL;
    ++f->ready_count;
    require(tlsclientTunnelGetHandshakeBinding(f->tls, line, &f->binding),
            "takeover could not read the completed TLS binding");
    require(tlsclientTunnelBeginTakeoverDrain(f->tls, line, &pending) && pending == NULL,
            "record-bounded handshake could not begin clean takeover drain");
}

static SSL_CTX *newServerContext(uint16_t version)
{
    SSL_CTX             *context       = SSL_CTX_new(TLS_server_method());
    static const uint8_t sid_context[] = "tlsclient-session-unit";
    require(context != NULL && SSL_CTX_set_min_proto_version(context, version) == 1 &&
                SSL_CTX_set_max_proto_version(context, version) == 1 &&
                SSL_CTX_use_certificate_chain_file(context, TLSCLIENT_TEST_CERT_FILE) == 1 &&
                SSL_CTX_use_PrivateKey_file(context, TLSCLIENT_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1 &&
                SSL_CTX_set_session_id_context(context, sid_context, sizeof(sid_context) - 1) == 1 &&
                SSL_CTX_set_num_tickets(context, 2) == 1,
            "failed to configure the session-resumption server");
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_SERVER);
    return context;
}

static void fixtureSetupWithLargeAlpn(session_fixture_t *f, uint16_t version, bool takeover, bool large_alpn)
{
    memoryZero(f, sizeof(*f));
    f->saved_workers = GSTATE.workers_count;
    f->saved_pools   = GSTATE.shortcut_buffer_pools;
    f->saved_wid     = getWID();
    for (size_t i = 0; i < ARRAY_SIZE(f->masters); ++i)
    {
        f->masters[i] = masterpoolCreateWithCapacity(8);
        require(f->masters[i] != NULL, "failed to allocate session fixture master pool");
    }
    f->pools[0] = bufferpoolCreate(
        f->masters[0], f->masters[1], f->masters[2], 4, 32768, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024, 32768, 32768);
    require(f->pools[0] != NULL, "failed to allocate session fixture buffer pool");
    bufferpoolUpdateAllocationPaddings(f->pools[0], 96, 96, 96, 96);
    GSTATE.workers_count         = 1;
    GSTATE.shortcut_buffer_pools = f->pools;
    testWorkerRegistryInstall(&f->registry);
    testWorkerBindWID(0);
    active_fixture = f;

    f->settings = cJSON_Parse("{\"sni\":\"tls.integration.test\",\"verify\":true,"
                              "\"alpns\":[\"http/1.1\"],\"x25519mlkem768\":false}");
    require(f->settings != NULL, "failed to parse session fixture settings");
    if (large_alpn)
    {
        cJSON *alpns = cJSON_GetObjectItemCaseSensitive(f->settings, "alpns");
        for (uint32_t i = 0; i < 32; ++i)
        {
            char protocol[UINT8_MAX + 1U];
            int  prefix_length = snprintf(protocol, sizeof(protocol), "session-test-%02u-", i);
            require(prefix_length > 0 && prefix_length < UINT8_MAX, "failed to create large ALPN fixture name");
            memorySet(protocol + prefix_length, 'x', UINT8_MAX - (size_t) prefix_length);
            protocol[UINT8_MAX] = '\0';
            require(cJSON_AddItemToArray(alpns, cJSON_CreateString(protocol)), "failed to append large ALPN entry");
        }
    }
    f->node.node_settings_json = f->settings;
    f->tls                     = tlsclientTunnelCreate(&f->node);
    f->prev                    = tunnelCreate(NULL, 0, 0);
    f->next                    = tunnelCreate(NULL, 0, 0);
    require(f->tls != NULL && f->prev != NULL && f->next != NULL, "failed to create session fixture tunnels");
    tlsclient_tstate_t *ts = tunnelGetState(f->tls);
    f->client_context      = ts->threadlocal_ssl_contexts[0];
    require(SSL_CTX_set_min_proto_version(f->client_context, version) == 1 &&
                SSL_CTX_set_max_proto_version(f->client_context, version) == 1 &&
                SSL_CTX_load_verify_locations(f->client_context, TLSCLIENT_TEST_CERT_FILE, NULL) == 1,
            "failed to configure authenticated session fixture client");
    f->cache_callback = SSL_CTX_sess_get_new_cb(f->client_context);
    require(f->cache_callback != NULL, "ordinary TlsClient constructor did not install a session cache callback");
    SSL_CTX_sess_set_new_cb(f->client_context, rememberSession);
    f->server_context = newServerContext(version);
    tunnelBind(f->prev, f->tls);
    tunnelBind(f->tls, f->next);
    f->next->fnInitU    = nextInit;
    f->next->fnPayloadU = nextPayload;
    f->next->fnFinU     = nextFinish;
    f->prev->fnPayloadD = prevPayload;
    f->prev->fnFinD     = prevFinish;
    f->takeover         = takeover;
    if (takeover)
        require(tlsclientTunnelEnableHandshakeTakeover(f->tls, f->prev, handshakeReady),
                "failed to enable session fixture handshake takeover");
}

static void fixtureSetup(session_fixture_t *f, uint16_t version, bool takeover)
{
    fixtureSetupWithLargeAlpn(f, version, takeover, false);
}

static void connectionStart(session_fixture_t *f)
{
    require(f->line == NULL && f->server == NULL && f->hello == NULL, "previous connection was not released");
    f->server = SSL_new(f->server_context);
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    require(f->server != NULL && rbio != NULL && wbio != NULL, "failed to allocate session fixture peer");
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(f->server, rbio, wbio);
    SSL_set_accept_state(f->server);
    /* This fixture owns the normal line; the production TlsClient borrows it. */
    f->line = memoryAllocateCacheAlignedZero(sizeof(line_t) + f->tls->lstate_size);
    require(f->line != NULL, "failed to allocate session fixture line");
    atomic_init(&f->line->refc, 1);
    f->line->alive     = true;
    f->line->wid       = 0;
    f->plaintext_bytes = 0;
    f->ready_count     = 0;
    tlsclientTunnelUpStreamInit(f->tls, f->line);
    require(lineIsAlive(f->line) && f->hello != NULL, "ordinary Init failed to emit a ClientHello");
}

static void connectionDestroy(session_fixture_t *f)
{
    if (f->line != NULL)
    {
        tlsclient_lstate_t *ls = lineGetState(f->line, f->tls);
        if (ls->tunnel != NULL)
            tlsclientLinestateDestroy(ls);
        require(atomicLoadU32(&f->line->refc) == 1, "session connection leaked a line reference");
        f->line->alive = false;
        memoryFreeAligned(f->line);
        f->line = NULL;
    }
    SSL_free(f->server);
    f->server = NULL;
    if (f->hello != NULL)
        bufferpoolReuseBuffer(f->pools[0], f->hello);
    f->hello = NULL;
}

static void fixtureDestroy(session_fixture_t *f)
{
    connectionDestroy(f);
    for (size_t i = 0; i < f->session_count; ++i)
        SSL_SESSION_free(f->sessions[i]);
    tlsclientTunnelDestroy(f->tls, wwLifecycleStartupRollback());
    tunnelDestroy(f->prev);
    tunnelDestroy(f->next);
    SSL_CTX_free(f->server_context);
    cJSON_Delete(f->settings);
    GSTATE.workers_count         = f->saved_workers;
    GSTATE.shortcut_buffer_pools = f->saved_pools;
    testWorkerRegistryRestore(&f->registry);
    testWorkerBindWID(f->saved_wid);
    bufferpoolDestroy(f->pools[0]);
    for (size_t i = 0; i < ARRAY_SIZE(f->masters); ++i)
    {
        masterpoolMakeEmpty(f->masters[i]);
        masterpoolDestroy(f->masters[i]);
    }
    active_fixture = NULL;
}

static CBS offeredTicket(const sbuf_t *hello)
{
    tls_client_hello_view_t view;
    const uint8_t          *bytes = (const uint8_t *) sbufGetRawPtr(hello);
    require(tlsclienthelloParseRecord(bytes, sbufGetLength(hello), &view) == kTlsClientHelloFound,
            "session fixture emitted an invalid ClientHello");
    CBS extensions, ticket;
    CBS_init(&extensions, bytes + view.extensions_offset, view.extensions_length);
    CBS_init(&ticket, NULL, 0);
    while (CBS_len(&extensions) != 0)
    {
        uint16_t type;
        CBS      contents;
        require(CBS_get_u16(&extensions, &type) && CBS_get_u16_length_prefixed(&extensions, &contents),
                "session ClientHello extension framing is invalid");
        require(type != TLSEXT_TYPE_early_data, "session resumption unexpectedly enabled 0-RTT");
        if (type == TLSEXT_TYPE_session_ticket)
            ticket = contents;
        else if (type == TLSEXT_TYPE_pre_shared_key)
        {
            CBS      identities, binders, binder;
            uint32_t age;
            require(CBS_get_u16_length_prefixed(&contents, &identities) &&
                        CBS_get_u16_length_prefixed(&identities, &ticket) && CBS_get_u32(&identities, &age) &&
                        CBS_len(&identities) == 0,
                    "session ClientHello did not contain exactly one PSK identity");
            require(CBS_len(&extensions) == 0 && CBS_get_u16_length_prefixed(&contents, &binders) &&
                        CBS_get_u8_length_prefixed(&binders, &binder) && CBS_len(&binders) == 0 &&
                        CBS_len(&contents) == 0 && (CBS_len(&binder) == 32 || CBS_len(&binder) == 48),
                    "PSK extension was not last or did not contain exactly one framed binder");
        }
    }
    return ticket;
}

static void requireTicket(const sbuf_t *hello, const SSL_SESSION *session)
{
    CBS            actual       = offeredTicket(hello);
    const uint8_t *expected     = NULL;
    size_t         expected_len = 0;
    if (session != NULL)
        SSL_SESSION_get0_ticket(session, &expected, &expected_len);
    require((session == NULL || expected_len > 0) && CBS_len(&actual) == expected_len &&
                (expected_len == 0 || memoryCompare(CBS_data(&actual), expected, expected_len) == 0),
            "ClientHello offered the wrong cached ticket or failed to remain fresh");
}

static void feedServerOutput(session_fixture_t *f)
{
    BIO *wire = SSL_get_wbio(f->server);
    while (BIO_ctrl_pending(wire) > 0 && lineIsAlive(f->line))
    {
        uint8_t header[SSL3_RT_HEADER_LENGTH];
        require(BIO_read(wire, header, sizeof(header)) == sizeof(header), "partial server TLS record header");
        uint32_t body_len = ((uint32_t) header[3] << 8U) | header[4];
        sbuf_t  *record   = bufferpoolGetBestFit(f->pools[0], sizeof(header) + body_len, 0);
        sbufWrite(record, header, sizeof(header));
        require(BIO_read(wire, sbufGetMutablePtr(record) + sizeof(header), (int) body_len) == (int) body_len,
                "partial server TLS record body");
        sbufSetLength(record, sizeof(header) + body_len);
        tlsclient_lstate_t *ls = lineGetState(f->line, f->tls);
        if (f->takeover && ls->takeover_phase == kTlsClientTakeoverDrain)
            require(tlsclientTunnelConsumePostHandshakeRecord(f->tls, f->line, record) ==
                        kTlsClientPostHandshakeNeedMore,
                    "takeover drain rejected a genuine post-handshake ticket record");
        else
            tlsclientTunnelDownStreamPayload(f->tls, f->line, record);
    }
}

static bool handshake(session_fixture_t *f)
{
    for (uint32_t step = 0; step < 100 && lineIsAlive(f->line); ++step)
    {
        int result = SSL_do_handshake(f->server);
        int error  = SSL_get_error(f->server, result);
        if (result != 1 && error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            return false;
        feedServerOutput(f);
        if (! lineIsAlive(f->line))
            return false;
        tlsclient_lstate_t *ls = lineGetState(f->line, f->tls);
        if (SSL_is_init_finished(f->server) && ls->handshake_completed)
            return true;
    }
    return false;
}

static void requireHandshake(session_fixture_t *f, bool resumed)
{
    require(handshake(f), "ordinary TlsClient handshake failed");
    tlsclient_lstate_t *ls = lineGetState(f->line, f->tls);
    require(SSL_session_reused(ls->ssl) == resumed && SSL_session_reused(f->server) == resumed,
            "client/server resumption result did not match the offered session");
    require(! SSL_early_data_accepted(ls->ssl), "session handshake accepted unexpected early data");
}

static void collectTickets(session_fixture_t *f)
{
    require(SSL_write(f->server, NULL, 0) == 0, "failed to flush queued TLS 1.3 tickets");
    feedServerOutput(f);
    require(lineIsAlive(f->line), "connection closed while processing session tickets");
}

static void exchangePayload(session_fixture_t *f)
{
    sbuf_t *payload = bufferpoolGetSmallBuffer(f->pools[0]);
    sbufWrite(payload, "ping", 4);
    sbufSetLength(payload, 4);
    tlsclientTunnelUpStreamPayload(f->tls, f->line, payload);
    uint8_t received[4];
    require(SSL_read(f->server, received, sizeof(received)) == sizeof(received) &&
                memoryCompare(received, "ping", sizeof(received)) == 0,
            "server could not read application data after the handshake");
    require(SSL_write(f->server, "pong", 4) == 4, "server could not send application data");
    feedServerOutput(f);
    require(f->plaintext_bytes == 4, "client did not deliver the server application response");
}

static void requireRawFresh(session_fixture_t *f)
{
    static const uint8_t hostname[] = "tls.integration.test";
    line_t               caller     = {.wid = 0};
    for (size_t i = 0; i < 2; ++i)
    {
        sbuf_t *hello = tlsclientTunnelGenerateClientHello(f->tls, &caller, hostname, sizeof(hostname) - 1);
        require(hello != NULL, "raw generation failed with a populated session cache");
        requireTicket(hello, NULL);
        bufferpoolReuseBuffer(f->pools[0], hello);
    }
}

static void testReuseAndRefusal(uint16_t version)
{
    session_fixture_t f;
    fixtureSetup(&f, version, false);
    connectionStart(&f);
    requireTicket(f.hello, NULL);
    requireHandshake(&f, false);
    exchangePayload(&f);
    collectTickets(&f);
    require(f.session_count > 0, "successful handshake did not deliver any resumable session");
    connectionDestroy(&f);
    requireRawFresh(&f);
    connectionStart(&f);
    requireTicket(f.hello, f.sessions[f.session_count - 1]);
    requireHandshake(&f, true);
    exchangePayload(&f);
    collectTickets(&f);
    connectionDestroy(&f);

    /* A fresh server context has different ticket keys and must decline the offered ticket. */
    SSL_CTX_free(f.server_context);
    f.server_context = newServerContext(version);
    connectionStart(&f);
    CBS ticket = offeredTicket(f.hello);
    require(CBS_len(&ticket) > 0, "server-refusal case did not actually offer a cached ticket");
    requireHandshake(&f, false);
    exchangePayload(&f);
    fixtureDestroy(&f);
}

static void testSingleUseAndEviction(void)
{
    session_fixture_t f;
    fixtureSetup(&f, TLS1_3_VERSION, false);
    require(SSL_CTX_set_num_tickets(f.server_context, 3) == 1, "failed to request three fixture tickets");
    connectionStart(&f);
    requireHandshake(&f, false);
    collectTickets(&f);
    require(f.session_count == 3, "server did not deliver three distinct TLS 1.3 tickets");
    connectionDestroy(&f);
    requireRawFresh(&f);
    for (size_t i = 0; i < 3; ++i)
    {
        connectionStart(&f);
        requireTicket(f.hello, i < 2 ? f.sessions[2 - i] : NULL);
        /* Abandon after the offer: single-use tickets must still be consumed. */
        connectionDestroy(&f);
    }
    fixtureDestroy(&f);
}

static void testInvalidLifetime(uint16_t version, bool future)
{
    session_fixture_t f;
    fixtureSetup(&f, version, false);
    connectionStart(&f);
    requireHandshake(&f, false);
    collectTickets(&f);
    require(f.session_count > 0, "lifetime case has no cached session");
    for (size_t i = 0; i < f.session_count; ++i)
    {
        SSL_SESSION_set_time(f.sessions[i], future ? (uint64_t) time(NULL) + 86400U : 1U);
        SSL_SESSION_set_timeout(f.sessions[i], future ? 3600U : 1U);
    }
    connectionDestroy(&f);
    connectionStart(&f);
    requireTicket(f.hello, NULL);
    requireHandshake(&f, false);
    fixtureDestroy(&f);
}

static void testOversizedTicket(uint16_t version, bool large_alpn)
{
    session_fixture_t f;
    fixtureSetupWithLargeAlpn(&f, version, false, large_alpn);
    connectionStart(&f);
    requireHandshake(&f, false);
    collectTickets(&f);
    require(f.session_count > 0, "oversized-ticket case has no cached session");

    /* 60,000 bytes fits a ticket field in isolation, but the additional 8 KiB
     * ALPN list leaves insufficient space in this context's extension block. */
    const size_t ticket_length = large_alpn ? 60000U : UINT16_MAX;
    uint8_t     *ticket        = memoryAllocate(ticket_length);
    require(ticket != NULL, "failed to allocate oversized fixture ticket");
    memorySet(ticket, 0xa5, ticket_length);
    for (size_t i = 0; i < f.session_count; ++i)
        require(SSL_SESSION_set_ticket(f.sessions[i], ticket, ticket_length) == 1,
                "BoringSSL rejected the individually representable fixture ticket");
    memoryFree(ticket);
    connectionDestroy(&f);

    connectionStart(&f);
    requireTicket(f.hello, NULL);
    requireHandshake(&f, false);
    exchangePayload(&f);
    fixtureDestroy(&f);
}

static void requireStandaloneFresh(SSL_CTX *context, const char *hostname, bool change_verify)
{
    SSL *ssl  = SSL_new(context);
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    require(ssl != NULL && rbio != NULL && wbio != NULL, "failed to allocate cache-isolation SSL");
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    if (change_verify)
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    require(tlsclientConfigureSslForConnect(ssl, rbio, wbio, hostname, NULL, 0) && tlsclientPrepareSession(ssl),
            "cache mismatch did not permit a fresh handshake");
    int result = SSL_connect(ssl);
    require(SSL_get_error(ssl, result) == SSL_ERROR_WANT_READ, "isolated SSL did not emit a fresh ClientHello");
    uint32_t wire_len = (uint32_t) BIO_ctrl_pending(wbio);
    sbuf_t  *hello    = bufferpoolGetBestFit(active_fixture->pools[0], wire_len, 0);
    require(wire_len > 0 && BIO_read(wbio, sbufGetMutablePtr(hello), (int) wire_len) == (int) wire_len,
            "failed to capture isolated ClientHello");
    sbufSetLength(hello, wire_len);
    requireTicket(hello, NULL);
    bufferpoolReuseBuffer(active_fixture->pools[0], hello);
    SSL_free(ssl);
}

static void testCacheIsolation(void)
{
    session_fixture_t f;
    fixtureSetup(&f, TLS1_3_VERSION, false);
    connectionStart(&f);
    requireHandshake(&f, false);
    collectTickets(&f);
    connectionDestroy(&f);
    requireStandaloneFresh(f.client_context, "unrelated.integration.test", false);
    requireStandaloneFresh(f.client_context, "tls.integration.test", true);
    SSL_CTX *other = SSL_CTX_new(TLS_client_method());
    require(other != NULL, "failed to allocate independent cache context");
    SSL_CTX_set_verify(other, SSL_VERIFY_PEER, NULL);
    require(tlsclientConfigureSessionCache(other, "tls.integration.test", 1024),
            "failed to configure independent cache");
    requireStandaloneFresh(other, "tls.integration.test", false);
    SSL_CTX_free(other);
    connectionStart(&f);
    requireTicket(f.hello, f.sessions[f.session_count - 1]);
    requireHandshake(&f, true);
    fixtureDestroy(&f);
}

static void testTrustRemoval(uint16_t version)
{
    session_fixture_t f;
    fixtureSetup(&f, version, false);
    connectionStart(&f);
    requireHandshake(&f, false);
    collectTickets(&f);
    connectionDestroy(&f);
    X509_STORE *untrusted = X509_STORE_new();
    require(untrusted != NULL, "failed to allocate an empty trust store");
    SSL_CTX_set_cert_store(f.client_context, untrusted);
    connectionStart(&f);
    requireTicket(f.hello, NULL);
    require(! handshake(&f) && ! lineIsAlive(f.line), "removed trust still authenticated a cached connection");
    connectionDestroy(&f);
    require(SSL_CTX_load_verify_locations(f.client_context, TLSCLIENT_TEST_CERT_FILE, NULL) == 1,
            "failed to restore fixture root trust");
    connectionStart(&f);
    requireTicket(f.hello, NULL);
    requireHandshake(&f, false);
    fixtureDestroy(&f);
}

static void testStaticRsaIsNotCached(void)
{
    session_fixture_t f;
    fixtureSetup(&f, TLS1_2_VERSION, false);
    require(SSL_CTX_set_strict_cipher_list(f.server_context, "AES128-GCM-SHA256") == 1,
            "failed to constrain the server to static RSA");
    connectionStart(&f);
    requireHandshake(&f, false);
    require(SSL_CIPHER_get_kx_nid(SSL_get_current_cipher(f.server)) == NID_kx_rsa,
            "static-RSA cache exclusion case negotiated an ephemeral key exchange");
    collectTickets(&f);
    connectionDestroy(&f);
    connectionStart(&f);
    requireTicket(f.hello, NULL);
    requireHandshake(&f, false);
    fixtureDestroy(&f);
}

static void testTakeover(bool tickets)
{
    session_fixture_t f;
    fixtureSetup(&f, TLS1_3_VERSION, true);
    require(SSL_CTX_set_num_tickets(f.server_context, tickets ? 2 : 0) == 1,
            "failed to configure takeover ticket delivery");
    tlsclient_handshake_binding_t first = {0};
    for (size_t i = 0; i < 2; ++i)
    {
        connectionStart(&f);
        requireTicket(f.hello, i == 1 && tickets ? f.sessions[f.session_count - 1] : NULL);
        requireHandshake(&f, i == 1 && tickets);
        require(f.ready_count == 1 && f.binding.tls_version == TLS1_3_VERSION,
                "takeover owner did not receive exactly one TLS 1.3 completion");
        uint8_t client_random[SSL3_RANDOM_SIZE], server_random[SSL3_RANDOM_SIZE];
        require(SSL_get_client_random(f.server, client_random, sizeof(client_random)) == sizeof(client_random) &&
                    SSL_get_server_random(f.server, server_random, sizeof(server_random)) == sizeof(server_random) &&
                    memoryCompare(f.binding.client_random, client_random, sizeof(client_random)) == 0 &&
                    memoryCompare(f.binding.server_random, server_random, sizeof(server_random)) == 0 &&
                    f.binding.cipher_suite == SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(f.server)),
                "takeover binding disagrees with the full or resumed TLS peer");
        if (i == 0)
            first = f.binding;
        else
            require(memoryCompare(first.client_random, f.binding.client_random, sizeof(client_random)) != 0 &&
                        memoryCompare(first.server_random, f.binding.server_random, sizeof(server_random)) != 0,
                    "resumed takeover reused the previous connection's random binding");
        collectTickets(&f);
        require(! tickets || f.session_count > 0, "takeover drain did not process genuine NewSessionTickets");
        require(tlsclientTunnelCompleteTakeover(f.tls, f.line), "takeover could not release TLS at a clean boundary");
        tlsclient_lstate_t *ls = lineGetState(f.line, f.tls);
        require(ls->ssl == NULL && ls->takeover_phase == kTlsClientTakeoverPassthrough,
                "completed takeover retained the TLS object");
        connectionDestroy(&f);
    }
    fixtureDestroy(&f);
}

int main(void)
{
    static const uint16_t versions[] = {TLS1_2_VERSION, TLS1_3_VERSION};
    for (size_t i = 0; i < ARRAY_SIZE(versions); ++i)
    {
        testCaseSet(i == 0 ? "tls12_reuse_and_refusal" : "tls13_reuse_and_refusal");
        testReuseAndRefusal(versions[i]);
        testCaseSet(i == 0 ? "tls12_expired_session" : "tls13_expired_session");
        testInvalidLifetime(versions[i], false);
        testCaseSet(i == 0 ? "tls12_future_session" : "tls13_future_session");
        testInvalidLifetime(versions[i], true);
        testCaseSet(i == 0 ? "tls12_removed_trust" : "tls13_removed_trust");
        testTrustRemoval(versions[i]);
        testCaseSet(i == 0 ? "tls12_oversized_ticket" : "tls13_oversized_ticket");
        testOversizedTicket(versions[i], false);
        testCaseSet(i == 0 ? "tls12_ticket_with_large_alpn" : "tls13_ticket_with_large_alpn");
        testOversizedTicket(versions[i], true);
    }
    testCaseSet("tls13_single_use_and_eviction");
    testSingleUseAndEviction();
    testCaseSet("cache_context_sni_and_verify_isolation");
    testCacheIsolation();
    testCaseSet("static_rsa_cache_exclusion");
    testStaticRsaIsNotCached();
    testCaseSet("tls13_takeover_with_tickets");
    testTakeover(true);
    testCaseSet("tls13_takeover_without_tickets");
    testTakeover(false);
    return 0;
}
