#include "TlsClient/structure.h"

#include "tls_client_hello.h"

enum
{
    kTestLargeBufferSize   = 32768,
    kTestSmallBufferSize   = 1024,
    kTestBufferLeftPadding = 96,
    kTestLargeAlpnWireSize = 40000,
};

typedef struct tlsclient_test_worker_env_s
{
    uint32_t        saved_workers_count;
    buffer_pool_t **saved_buffer_pools;
    wid_t           saved_wid;
    master_pool_t  *large_master;
    master_pool_t  *small_master;
    buffer_pool_t  *pool;
    buffer_pool_t  *buffer_pools[1];
} tlsclient_test_worker_env_t;

static void require(bool condition, const char *message);

static sbuf_t  *ordinary_init_flight;
static uint32_t ordinary_init_count;

static void captureOrdinaryInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ordinary_init_count += 1U;
}

static void captureOrdinaryPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    require(ordinary_init_flight == NULL, "ordinary TlsClient Init emitted more than one initial-flight buffer");
    ordinary_init_flight = buf;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static cJSON *parseSettings(const char *text)
{
    cJSON *settings = cJSON_Parse(text);
    require(settings != NULL && cJSON_IsObject(settings), "failed to parse ALPN test settings");
    return settings;
}

static void workerEnvSetup(tlsclient_test_worker_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->saved_workers_count = GSTATE.workers_count;
    env->saved_buffer_pools  = GSTATE.shortcut_buffer_pools;
    env->saved_wid           = getWID();

    env->large_master = masterpoolCreateWithCapacity(8);
    env->small_master = masterpoolCreateWithCapacity(8);
    require(env->large_master != NULL && env->small_master != NULL, "failed to create ClientHello test master pools");

    env->pool = bufferpoolCreate(env->large_master, env->small_master, 4, kTestLargeBufferSize, kTestSmallBufferSize);
    require(env->pool != NULL, "failed to create ClientHello test buffer pool");
    bufferpoolUpdateAllocationPaddings(env->pool, kTestBufferLeftPadding, kTestBufferLeftPadding);

    env->buffer_pools[0]         = env->pool;
    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.workers_count         = 2;
    testWorkerBindWID(0);
}

static void workerEnvTeardown(tlsclient_test_worker_env_t *env)
{
    GSTATE.shortcut_buffer_pools = env->saved_buffer_pools;
    GSTATE.workers_count         = env->saved_workers_count;
    testWorkerBindWID(env->saved_wid);

    bufferpoolDestroy(env->pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static void requireWire(const tlsclient_tstate_t *ts, const uint8_t *expected, size_t expected_len, const char *message)
{
    require(ts->alpn_wire_len == expected_len, message);
    require(expected_len == 0 || memoryCompare(ts->alpn_wire, expected, expected_len) == 0, message);
}

static void releaseParsedAlpns(tlsclient_tstate_t *ts)
{
    memoryFree(ts->alpn_wire);
    ts->alpn_wire     = NULL;
    ts->alpn_wire_len = 0;
}

static void testDefaultOrder(void)
{
    static const uint8_t expected[] = {
        2,
        'h',
        '2',
        8,
        'h',
        't',
        't',
        'p',
        '/',
        '1',
        '.',
        '1',
    };

    cJSON             *settings = parseSettings("{}");
    tlsclient_tstate_t ts       = {0};

    require(tlsclientParseAlpnSetting(&ts, settings), "default ALPN parsing failed");
    requireWire(&ts, expected, sizeof(expected), "default ALPN order changed");

    releaseParsedAlpns(&ts);
    cJSON_Delete(settings);
}

static void testConfiguredOrder(void)
{
    static const uint8_t expected[] = {
        8,
        'h',
        't',
        't',
        'p',
        '/',
        '1',
        '.',
        '1',
        2,
        'h',
        '2',
        3,
        'f',
        'o',
        'o',
    };

    cJSON             *settings = parseSettings("{\"alpns\":[\"http/1.1\",\"h2\",\"foo\"]}");
    tlsclient_tstate_t ts       = {0};

    require(tlsclientParseAlpnSetting(&ts, settings), "configured ALPN parsing failed");
    requireWire(&ts, expected, sizeof(expected), "configured ALPN order was not preserved");

    releaseParsedAlpns(&ts);
    cJSON_Delete(settings);
}

static void testEmptyListDisablesAlpn(void)
{
    cJSON             *settings = parseSettings("{\"alpns\":[]}");
    tlsclient_tstate_t ts       = {0};

    require(tlsclientParseAlpnSetting(&ts, settings), "empty ALPN list was rejected");
    requireWire(&ts, NULL, 0, "empty ALPN list did not disable ALPN");
    require(ts.alpn_wire == NULL, "empty ALPN list unexpectedly allocated wire data");

    cJSON_Delete(settings);
}

static void testInvalidListsAreRejected(void)
{
    static const char *invalid_settings[] = {
        "{\"alpns\":\"h2\"}",
        "{\"alpns\":[\"\"]}",
        "{\"alpns\":[2]}",
        "{\"alpns\":[\"h2\",\"h2\"]}",
    };

    for (size_t i = 0; i < ARRAY_SIZE(invalid_settings); ++i)
    {
        cJSON             *settings = parseSettings(invalid_settings[i]);
        tlsclient_tstate_t ts       = {0};

        require(! tlsclientParseAlpnSetting(&ts, settings), "invalid ALPN setting was accepted");
        require(ts.alpn_wire == NULL && ts.alpn_wire_len == 0, "invalid ALPN setting left allocated state behind");

        cJSON_Delete(settings);
    }
}

static cJSON *createAlpnSettingsWithWireLength(size_t wire_len)
{
    cJSON *settings = cJSON_CreateObject();
    cJSON *alpns    = cJSON_AddArrayToObject(settings, "alpns");
    require(settings != NULL && alpns != NULL, "failed to create ALPN boundary settings");

    int index = 0;
    while (wire_len > 0)
    {
        require(wire_len > 1, "ALPN boundary test requested an unrepresentable wire length");

        const size_t entry_len = wire_len > UINT8_MAX + 1U ? UINT8_MAX + 1U : wire_len;
        const size_t name_len  = entry_len - 1U;
        char         name[UINT8_MAX + 1U];

        int prefix_len = snprintf(name, name_len + 1U, "protocol-%03d-", index);
        require(prefix_len > 0 && (size_t) prefix_len < name_len, "failed to create a unique ALPN boundary protocol");
        memorySet(name + prefix_len, 'x', name_len - (size_t) prefix_len);
        name[name_len] = '\0';

        require(cJSON_AddItemToArray(alpns, cJSON_CreateString(name)), "failed to append an ALPN boundary protocol");

        wire_len -= entry_len;
        ++index;
    }

    return settings;
}

static void testTotalWireLengthBounds(void)
{
    cJSON             *settings = createAlpnSettingsWithWireLength(kTlsClientMaxAlpnWireLength);
    tlsclient_tstate_t ts       = {0};

    require(tlsclientParseAlpnSetting(&ts, settings), "maximum encodable ALPN wire list was rejected");
    require(ts.alpn_wire_len == kTlsClientMaxAlpnWireLength, "maximum encodable ALPN wire list changed length");
    releaseParsedAlpns(&ts);
    cJSON_Delete(settings);

    settings = createAlpnSettingsWithWireLength(kTlsClientMaxAlpnWireLength + 1U);
    require(! tlsclientParseAlpnSetting(&ts, settings), "oversized ALPN wire list was accepted");
    require(ts.alpn_wire == NULL && ts.alpn_wire_len == 0, "oversized ALPN wire list left allocated state behind");
    cJSON_Delete(settings);
}

static void fillServerName(char *sni, size_t length)
{
    memorySet(sni, 'a', length);
    sni[length] = '\0';
}

static cJSON *createTlsSettings(const char *sni, const char *ech_sni)
{
    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL && cJSON_AddStringToObject(settings, "sni", sni) != NULL &&
                cJSON_AddBoolToObject(settings, "verify", false) != NULL &&
                cJSON_AddBoolToObject(settings, "x25519mlkem768", false) != NULL,
            "failed to create TlsClient boundary settings");

    if (ech_sni != NULL)
    {
        require(cJSON_AddStringToObject(settings, "ech-sni-trick", ech_sni) != NULL,
                "failed to create ECH SNI boundary setting");
    }

    return settings;
}

static tunnel_t *createTlsClientFromSettings(node_t *node, cJSON *settings)
{
    *node = (node_t) {.node_settings_json = settings};
    return tlsclientTunnelCreate(node);
}

static void testConfiguredSniLengthBounds(void)
{
    const uint32_t saved_workers_count = GSTATE.workers_count;
    char           maximum_sni[kTlsClientMaxSniLength + 1U];
    char           oversized_sni[kTlsClientMaxSniLength + 2U];

    GSTATE.workers_count = 2;
    fillServerName(maximum_sni, kTlsClientMaxSniLength);
    fillServerName(oversized_sni, kTlsClientMaxSniLength + 1U);

    node_t    node     = {0};
    cJSON    *settings = createTlsSettings(maximum_sni, NULL);
    tunnel_t *tunnel   = createTlsClientFromSettings(&node, settings);
    require(tunnel != NULL, "maximum-length TlsClient SNI was rejected");
    tlsclientTunnelDestroy(tunnel);
    cJSON_Delete(settings);

    settings = createTlsSettings(oversized_sni, NULL);
    require(createTlsClientFromSettings(&node, settings) == NULL, "oversized TlsClient SNI was accepted");
    cJSON_Delete(settings);

    settings = createTlsSettings("example.com", oversized_sni);
    require(createTlsClientFromSettings(&node, settings) == NULL, "oversized TlsClient ECH SNI was accepted");
    cJSON_Delete(settings);

    GSTATE.workers_count = saved_workers_count;
}

static bool tlsFlightIsComplete(const sbuf_t *flight)
{
    const uint8_t *bytes   = (const uint8_t *) sbufGetRawPtr(flight);
    const size_t   length  = sbufGetLength(flight);
    size_t         offset  = 0;
    uint32_t       records = 0;

    while (offset < length)
    {
        if (length - offset < SSL3_RT_HEADER_LENGTH)
        {
            return false;
        }

        const size_t body_len   = ((size_t) bytes[offset + 3U] << 8U) | bytes[offset + 4U];
        const size_t record_len = SSL3_RT_HEADER_LENGTH + body_len;
        if (record_len > length - offset)
        {
            return false;
        }

        offset += record_len;
        ++records;
    }

    return records > 0;
}

typedef struct aux_thread_args_s
{
    SSL_CTX       *ssl_ctx;
    const uint8_t *alpn_wire;
    size_t         alpn_wire_len;
    atomic_bool    success;
} aux_thread_args_t;

static WTHREAD_ROUTINE(tlsclientAuxiliaryThreadRoutine)
{
    aux_thread_args_t *args = userdata;

    require(getWID() == kInvalidWID, "auxiliary thread did not observe kInvalidWID");
    require(! currentThreadHasRegisteredWID(), "auxiliary thread reported registered WID");

    sbuf_t *hello = (sbuf_t *) (uintptr_t) 0x1;
    bool    ok    = tlsclientCreateClientHelloFromContext(
        args->ssl_ctx, "example.com", NULL, 0, args->alpn_wire, args->alpn_wire_len, &hello);

    require(! ok && hello == NULL, "TlsClient helper from unregistered thread did not reject call cleanly");

    atomic_store(&args->success, true);
    return 0;
}

static void testGeneratedLargeClientHelloIsComplete(void)
{
    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);

    uint8_t *alpn_wire = memoryAllocate(kTestLargeAlpnWireSize);
    for (size_t offset = 0; offset < kTestLargeAlpnWireSize; offset += 2U)
    {
        alpn_wire[offset]      = 1;
        alpn_wire[offset + 1U] = (uint8_t) ('a' + ((offset / 2U) % 26U));
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    require(ssl_ctx != NULL && SSL_CTX_set_alpn_protos(ssl_ctx, alpn_wire, kTestLargeAlpnWireSize) == 0,
            "failed to configure the large-ClientHello SSL context");

    sbuf_t *hello = NULL;
    require(tlsclientCreateClientHelloFromContext(
                ssl_ctx, "example.com", NULL, 0, alpn_wire, kTestLargeAlpnWireSize, &hello),
            "failed to generate a large ClientHello");
    require(hello != NULL && sbufGetLength(hello) > kTestLargeBufferSize,
            "large ClientHello did not exceed the worker buffer");
    require(sbufGetLeftPadding(hello) == kTestBufferLeftPadding,
            "generated ClientHello did not preserve worker-buffer padding");
    require(tlsFlightIsComplete(hello), "generated ClientHello contains a truncated TLS record");

    bufferpoolReuseBuffer(env.pool, hello);

    // Test calling TlsClient helper from a genuine unregistered background thread (getWID() == kInvalidWID)
    aux_thread_args_t aux_args = {
        .ssl_ctx       = ssl_ctx,
        .alpn_wire     = alpn_wire,
        .alpn_wire_len = kTestLargeAlpnWireSize,
    };
    atomic_init(&aux_args.success, false);

    wthread_t       aux_thread;
    wthread_error_t thread_err = threadCreate(&aux_thread, tlsclientAuxiliaryThreadRoutine, &aux_args);
    require(thread_err == kWThreadErrorNone, "failed to spawn auxiliary test thread for TlsClient");
    require(threadJoin(aux_thread) == 0, "failed to join auxiliary test thread for TlsClient");
    require(atomic_load(&aux_args.success), "auxiliary thread TlsClient rejection test failed");

    hello = (sbuf_t *) (uintptr_t) 0x1;
    testWorkerBindWID(1);
    require(! tlsclientCreateClientHelloFromContext(
                ssl_ctx, "example.com", NULL, 0, alpn_wire, kTestLargeAlpnWireSize, &hello) &&
                hello == NULL,
            "private ClientHello helper mapped an additional thread onto worker 0");
    testWorkerBindWID(0);

    SSL_CTX           *inner_contexts[] = {ssl_ctx};
    tlsclient_tstate_t ts               = {
                      .threadlocal_ech_grease_inner_ssl_contexts = inner_contexts,
                      .alpn_wire                                 = alpn_wire,
                      .alpn_wire_len                             = kTestLargeAlpnWireSize,
                      .ech_grease_sni_override                   = (char *) (uintptr_t) "inner.example.com",
    };
    hello = (sbuf_t *) (uintptr_t) 0x1;
    require(! tlsclientCreateEchGreaseInnerClientHello(&ts, 1, &hello) && hello == NULL,
            "private ECH helper mapped an invalid worker onto worker 0");

    SSL_CTX_free(ssl_ctx);
    memoryFree(alpn_wire);
    workerEnvTeardown(&env);
}

static sbuf_t *createGenerateRequest(buffer_pool_t *pool, const char *sni, size_t sni_len)
{
    static const char kPrefix[] = "generateTlsHello:";

    sbuf_t      *request = bufferpoolGetLargeBuffer(pool);
    const size_t length  = sizeof(kPrefix) - 1U + sni_len;
    require(length <= sbufGetMaximumWriteableSize(request), "ClientHello API test request exceeds its buffer");

    memoryCopy(sbufGetMutablePtr(request), kPrefix, sizeof(kPrefix) - 1U);
    memoryCopy(sbufGetMutablePtr(request) + sizeof(kPrefix) - 1U, sni, sni_len);
    sbufSetLength(request, (uint32_t) length);
    return request;
}

static void testApiSniLengthBounds(void)
{
    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);

    node_t    node     = {0};
    cJSON    *settings = createTlsSettings("example.com", NULL);
    tunnel_t *tunnel   = createTlsClientFromSettings(&node, settings);
    require(tunnel != NULL, "failed to create TlsClient for API SNI boundary test");

    char maximum_sni[kTlsClientMaxSniLength + 1U];
    char oversized_sni[kTlsClientMaxSniLength + 2U];
    fillServerName(maximum_sni, kTlsClientMaxSniLength);
    fillServerName(oversized_sni, kTlsClientMaxSniLength + 1U);

    api_result_t result =
        tlsclientTunnelApi(tunnel, createGenerateRequest(env.pool, maximum_sni, kTlsClientMaxSniLength));
    require(result.result_code == kApiResultOk && result.buffer != NULL,
            "ClientHello API rejected a maximum-length SNI");
    require(tlsFlightIsComplete(result.buffer), "ClientHello API returned an incomplete TLS flight");
    bufferpoolReuseBuffer(env.pool, result.buffer);

    result = tlsclientTunnelApi(tunnel, createGenerateRequest(env.pool, oversized_sni, kTlsClientMaxSniLength + 1U));
    require(result.result_code == kApiResultError && result.buffer == NULL,
            "ClientHello API accepted an oversized SNI");

    tlsclientTunnelDestroy(tunnel);
    cJSON_Delete(settings);
    workerEnvTeardown(&env);
}

static void testTypedClientHelloGeneration(void)
{
    static const uint8_t hostname[] = "typed.example.test";

    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);

    node_t    node     = {0};
    cJSON    *settings = createTlsSettings("example.com", NULL);
    tunnel_t *tunnel   = createTlsClientFromSettings(&node, settings);
    require(tunnel != NULL, "failed to create TlsClient for typed generation test");

    line_t  caller_line = {.wid = 0};
    sbuf_t *hello =
        tlsclientTunnelGenerateClientHello(tunnel, &caller_line, hostname, (uint32_t) sizeof(hostname) - 1U);
    require(hello != NULL && tlsFlightIsComplete(hello), "typed ClientHello generation failed");

    tls_client_hello_view_t parsed = {0};
    require(tlsclienthelloParseRecord(sbufGetRawPtr(hello), sbufGetLength(hello), &parsed) == kTlsClientHelloFound,
            "typed generation returned an invalid ClientHello");
    require(parsed.sni_name_length == sizeof(hostname) - 1U &&
                memoryCompare((const uint8_t *) sbufGetRawPtr(hello) + parsed.sni_name_offset,
                              hostname,
                              sizeof(hostname) - 1U) == 0,
            "typed generation did not preserve the exact hostname bytes");
    bufferpoolReuseBuffer(env.pool, hello);

    const uint8_t embedded_nul[] = {'a', '\0', 'b'};
    require(tlsclientTunnelGenerateClientHello(tunnel, &caller_line, embedded_nul, sizeof(embedded_nul)) == NULL,
            "typed generation accepted an embedded NUL");
    require(tlsclientTunnelGenerateClientHello(tunnel, &caller_line, hostname, 0) == NULL,
            "typed generation accepted an empty hostname");

    line_t additional_thread_line = {.wid = 1};
    testWorkerBindWID(1);
    require(tlsclientTunnelGenerateClientHello(
                tunnel, &additional_thread_line, hostname, (uint32_t) sizeof(hostname) - 1U) == NULL,
            "typed generation mapped an additional thread onto worker 0");
    require(tlsclientTunnelGenerateClientHello(tunnel, &caller_line, hostname, (uint32_t) sizeof(hostname) - 1U) ==
                NULL,
            "typed generation accessed another worker's line");
    testWorkerBindWID(0);

    tlsclientTunnelDestroy(tunnel);
    cJSON_Delete(settings);
    workerEnvTeardown(&env);
}

static int selectHttp11(SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in, unsigned int in_len,
                        void *arg)
{
    static const uint8_t supported[] = {
        8,
        'h',
        't',
        't',
        'p',
        '/',
        '1',
        '.',
        '1',
    };

    uint8_t *selected     = NULL;
    uint8_t  selected_len = 0;

    discard ssl;
    discard arg;

    if (SSL_select_next_proto(&selected, &selected_len, in, in_len, supported, (unsigned int) sizeof(supported)) !=
        OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    *out     = selected;
    *out_len = selected_len;
    return SSL_TLSEXT_ERR_OK;
}

static bool transferBio(BIO *source, BIO *destination)
{
    uint8_t bytes[4096];

    while (BIO_ctrl_pending(source) > 0)
    {
        int read_len = BIO_read(source, bytes, (int) sizeof(bytes));
        if (read_len <= 0)
        {
            return false;
        }

        int written = 0;
        while (written < read_len)
        {
            int write_len = BIO_write(destination, bytes + written, read_len - written);
            if (write_len <= 0)
            {
                return false;
            }
            written += write_len;
        }
    }

    return true;
}

static bool advanceHandshake(SSL *ssl, bool *complete)
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

static bool driveHandshake(SSL *client, SSL *server)
{
    bool client_complete = false;
    bool server_complete = false;

    for (uint32_t step = 0; step < 100; ++step)
    {
        if (! advanceHandshake(client, &client_complete) || ! transferBio(SSL_get_wbio(client), SSL_get_rbio(server)) ||
            ! advanceHandshake(server, &server_complete) || ! transferBio(SSL_get_wbio(server), SSL_get_rbio(client)))
        {
            return false;
        }

        if (client_complete && server_complete)
        {
            return true;
        }
    }

    return false;
}

static void testOrdinaryLargeClientHelloIsCompletelyDrained(void)
{
    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);

    uint8_t *alpn_wire = memoryAllocate(kTestLargeAlpnWireSize);
    for (size_t offset = 0; offset < kTestLargeAlpnWireSize; offset += 2U)
    {
        alpn_wire[offset]      = 1;
        alpn_wire[offset + 1U] = (uint8_t) ('a' + ((offset / 2U) % 26U));
    }

    SSL_CTX *client_context = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_context = SSL_CTX_new(TLS_server_method());
    require(client_context != NULL && server_context != NULL,
            "failed to allocate ordinary oversized-Init TLS contexts");
    SSL_CTX_set_verify(server_context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_max_cert_list(server_context, UINT16_MAX);
    require(SSL_CTX_set_alpn_protos(client_context, alpn_wire, kTestLargeAlpnWireSize) == 0 &&
                SSL_CTX_use_certificate_chain_file(server_context, REALITY_TEST_CERT_FILE) == 1 &&
                SSL_CTX_use_PrivateKey_file(server_context, REALITY_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1 &&
                SSL_CTX_check_private_key(server_context) == 1,
            "failed to configure ordinary oversized-Init TLS contexts");

    SSL_CTX  *context_slots[] = {client_context};
    tunnel_t *prev            = tunnelCreate(NULL, 0, 0);
    tunnel_t *tls             = tunnelCreate(NULL, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));
    tunnel_t *next            = tunnelCreate(NULL, 0, 0);
    require(prev != NULL && tls != NULL && next != NULL, "failed to allocate ordinary oversized-Init tunnels");
    tunnelBind(prev, tls);
    tunnelBind(tls, next);
    next->fnInitU    = captureOrdinaryInit;
    next->fnPayloadU = captureOrdinaryPayload;

    tlsclient_tstate_t *ts       = tunnelGetState(tls);
    ts->threadlocal_ssl_contexts = context_slots;
    ts->alpn_wire                = alpn_wire;
    ts->alpn_wire_len            = kTestLargeAlpnWireSize;
    ts->sni                      = (char *) (uintptr_t) "example.com";

    uint32_t line_size = (uint32_t) sizeof(line_t) + tls->lstate_size;
    line_t  *line      = memoryAllocateCacheAlignedZero(line_size);
    require(line != NULL, "failed to allocate ordinary oversized-Init line");
    atomic_init(&line->refc, 1);
    line->alive = true;
    line->wid   = 0;

    ordinary_init_flight = NULL;
    ordinary_init_count  = 0;
    tlsclientTunnelUpStreamInit(tls, line);

    tlsclient_lstate_t *ls = lineGetState(line, tls);
    require(ordinary_init_count == 1U, "ordinary TlsClient Init did not initialize its next tunnel exactly once");
    require(ordinary_init_flight != NULL && sbufGetLength(ordinary_init_flight) > kTestLargeBufferSize,
            "ordinary TlsClient Init did not emit a flight larger than the 32 KiB pool buffer");
    require(tlsFlightIsComplete(ordinary_init_flight), "ordinary TlsClient Init emitted a truncated TLS flight");
    require(BIO_ctrl_pending(ls->wbio) == 0, "ordinary TlsClient Init left bytes pending in its write BIO");

    SSL *server      = SSL_new(server_context);
    BIO *server_rbio = BIO_new(BIO_s_mem());
    BIO *server_wbio = BIO_new(BIO_s_mem());
    require(server != NULL && server_rbio != NULL && server_wbio != NULL,
            "failed to allocate the ordinary oversized-Init peer");
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);
    SSL_set_bio(server, server_rbio, server_wbio);
    SSL_set_accept_state(server);

    uint32_t flight_len = sbufGetLength(ordinary_init_flight);
    require(BIO_write(SSL_get_rbio(server), sbufGetRawPtr(ordinary_init_flight), (int) flight_len) == (int) flight_len,
            "the peer could not consume the ordinary oversized initial flight");
    bufferpoolReuseBuffer(env.pool, ordinary_init_flight);
    ordinary_init_flight = NULL;

    if (! driveHandshake(ls->ssl, server))
    {
        ERR_print_errors_fp(stderr);
        require(false, "the peer could not continue the ordinary oversized-Init handshake");
    }

    SSL_free(server);
    tlsclientLinestateDestroy(ls);
    memoryFreeAligned(line);
    tunnelDestroy(prev);
    tunnelDestroy(tls);
    tunnelDestroy(next);
    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);
    memoryFree(alpn_wire);
    workerEnvTeardown(&env);
}

static void testHttp11Negotiation(void)
{
    static const uint8_t expected[] = "http/1.1";

    const uint32_t saved_workers_count = GSTATE.workers_count;
    cJSON *settings = parseSettings("{\"sni\":\"tls.integration.test\",\"alpns\":[\"http/1.1\"],\"verify\":false}");
    node_t node     = {.node_settings_json = settings};

    GSTATE.workers_count = 2; // one regular worker plus WaterWall's additional lwIP worker

    tunnel_t *tunnel = tlsclientTunnelCreate(&node);
    require(tunnel != NULL, "failed to create HTTP/1.1-only TlsClient");

    tlsclient_tstate_t *ts             = tunnelGetState(tunnel);
    SSL_CTX            *client_context = ts->threadlocal_ssl_contexts[0];
    SSL_CTX            *server_context = SSL_CTX_new(TLS_server_method());

    require(client_context != NULL && server_context != NULL &&
                SSL_CTX_set_min_proto_version(client_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(client_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_min_proto_version(server_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(server_context, TLS1_2_VERSION) == 1 &&
                SSL_CTX_use_certificate_chain_file(server_context, REALITY_TEST_CERT_FILE) == 1 &&
                SSL_CTX_use_PrivateKey_file(server_context, REALITY_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1 &&
                SSL_CTX_check_private_key(server_context) == 1,
            "failed to configure ALPN negotiation contexts");

    SSL_CTX_set_alpn_select_cb(server_context, selectHttp11, NULL);

    SSL *client      = SSL_new(client_context);
    SSL *server      = SSL_new(server_context);
    BIO *client_rbio = BIO_new(BIO_s_mem());
    BIO *client_wbio = BIO_new(BIO_s_mem());
    BIO *server_rbio = BIO_new(BIO_s_mem());
    BIO *server_wbio = BIO_new(BIO_s_mem());

    require(client != NULL && server != NULL && client_rbio != NULL && client_wbio != NULL && server_rbio != NULL &&
                server_wbio != NULL,
            "failed to allocate ALPN negotiation state");

    BIO_set_mem_eof_return(client_rbio, -1);
    BIO_set_mem_eof_return(client_wbio, -1);
    BIO_set_mem_eof_return(server_rbio, -1);
    BIO_set_mem_eof_return(server_wbio, -1);
    SSL_set_bio(client, client_rbio, client_wbio);
    SSL_set_bio(server, server_rbio, server_wbio);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    require(driveHandshake(client, server), "HTTP/1.1-only ALPN handshake failed");

    const uint8_t *client_alpn     = NULL;
    const uint8_t *server_alpn     = NULL;
    unsigned int   client_alpn_len = 0;
    unsigned int   server_alpn_len = 0;

    SSL_get0_alpn_selected(client, &client_alpn, &client_alpn_len);
    SSL_get0_alpn_selected(server, &server_alpn, &server_alpn_len);
    require(client_alpn_len == sizeof(expected) - 1 && server_alpn_len == sizeof(expected) - 1 &&
                memoryCompare(client_alpn, expected, sizeof(expected) - 1) == 0 &&
                memoryCompare(server_alpn, expected, sizeof(expected) - 1) == 0,
            "HTTP/1.1-only TlsClient did not negotiate http/1.1");

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(server_context);
    tlsclientTunnelDestroy(tunnel);
    GSTATE.workers_count = saved_workers_count;
    cJSON_Delete(settings);
}

int main(void)
{
    testDefaultOrder();
    testConfiguredOrder();
    testEmptyListDisablesAlpn();
    testInvalidListsAreRejected();
    testTotalWireLengthBounds();
    testConfiguredSniLengthBounds();
    testGeneratedLargeClientHelloIsComplete();
    testOrdinaryLargeClientHelloIsCompletelyDrained();
    testApiSniLengthBounds();
    testTypedClientHelloGeneration();
    testHttp11Negotiation();
    return 0;
}
