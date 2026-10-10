/*
 * Covers: Explicit ECH configuration, authenticated acceptance/rejection, private resumption,
 * GREASE-only raw generation, ticket-size fallback, and visible Reality handshake bindings.
 * Setup: One registered worker, fixture-owned scratch normal lines, production TlsClient callbacks,
 * in-memory BoringSSL peer, generated HPKE keys, and synthetic root/leaf certificates.
 * Checks: Public outer SNI, decrypted inner SNI/PSK, application traffic, verification and cache behavior.
 * Limits: No DNS discovery, transport reconnect, network timing, or complete Reality control exchange.
 * CTest: waterwall.tlsclient_ech_unit
 */
#include "TlsClient/structure.h"
#ifdef TLSCLIENT_ECH_REALITY_BINDING
#include "RealityServer/structure.h"
#endif

#include "fixtures/worker_registry_fixture.h"
#include "test_assert.h"
#include "tls_client_hello.h"

#include <openssl/base64.h>
#include <openssl/bytestring.h>
#include <openssl/hpke.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static const char kSecretName[] = "secret.ech.integration.test";
static const char kPublicName[] = "public.ech.integration.test";

typedef struct ech_fixture_s
{
    test_worker_registry_t registry;
    uint32_t               saved_workers;
    wid_t                  saved_wid;
    buffer_pool_t        **saved_pools;
    master_pool_t         *masters[4];
    buffer_pool_t         *pools[1];
    cJSON                 *settings;
    node_t                 node;
    tunnel_t              *tls;
    tunnel_t              *prev;
    tunnel_t              *next;
    SSL_CTX               *client_context;
    SSL_CTX               *server_context;
    SSL                   *server;
    line_t                *line;
    sbuf_t                *hello;
    sbuf_t                *server_hello;
    SSL_new_session_cb     cache_callback;
    SSL_SESSION           *sessions[12];
    size_t                 session_count;
    uint32_t               plaintext_bytes;
    uint32_t               init_count;
    long                   verify_result;
    bool                   verified_public_name;
    bool                   inner_psk;
    bool                   server_accepted;
} ech_fixture_t;

/* All callbacks execute synchronously on this fixture's registered worker. */
static ech_fixture_t *active_fixture;

static int rememberSession(SSL *ssl, SSL_SESSION *session)
{
    ech_fixture_t *f = active_fixture;
    require(f->session_count < ARRAY_SIZE(f->sessions) && SSL_SESSION_up_ref(session) == 1,
            "ECH fixture exhausted its retained callback references");
    f->sessions[f->session_count++] = session;
    /* Preserve the real callback's reference-ownership decision. */
    return f->cache_callback(ssl, session);
}

static void nextInit(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    ++active_fixture->init_count;
}

static void nextPayload(tunnel_t *t, line_t *line, sbuf_t *buffer)
{
    discard        t;
    ech_fixture_t *f   = active_fixture;
    uint32_t       len = sbufGetLength(buffer);
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

static void fixtureEnvironment(ech_fixture_t *f)
{
    memoryZero(f, sizeof(*f));
    f->saved_workers = GSTATE.workers_count;
    f->saved_pools   = GSTATE.shortcut_buffer_pools;
    f->saved_wid     = getWID();
    for (size_t i = 0; i < ARRAY_SIZE(f->masters); ++i)
    {
        f->masters[i] = masterpoolCreateWithCapacity(8);
        require(f->masters[i] != NULL, "failed to allocate ECH fixture master pool");
    }
    f->pools[0] = bufferpoolCreate(
        f->masters[0], f->masters[1], f->masters[2], 4, 32768, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024, 32768, 32768);
    require(f->pools[0] != NULL, "failed to allocate ECH fixture buffer pool");
    bufferpoolUpdateAllocationPaddings(f->pools[0], 96, 96, 96, 96);
    GSTATE.workers_count         = 1;
    GSTATE.shortcut_buffer_pools = f->pools;
    testWorkerRegistryInstall(&f->registry);
    testWorkerBindWID(0);
    active_fixture = f;
}

static void connectionStart(ech_fixture_t *f)
{
    require(f->line == NULL && f->server == NULL && f->hello == NULL, "previous connection was not released");
    f->server = SSL_new(f->server_context);
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    require(f->server != NULL && rbio != NULL && wbio != NULL, "failed to allocate ECH fixture peer");
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(f->server, rbio, wbio);
    SSL_set_accept_state(f->server);
    /* This fixture owns the normal line; the production TlsClient borrows it. */
    f->line = memoryAllocateCacheAlignedZero(sizeof(line_t) + f->tls->lstate_size);
    require(f->line != NULL, "failed to allocate ECH fixture line");
    atomic_init(&f->line->refc, 1);
    f->line->alive          = true;
    f->line->wid            = 0;
    f->plaintext_bytes      = 0;
    f->verify_result        = -1;
    f->verified_public_name = false;
    f->inner_psk            = false;
    f->server_accepted      = false;
    tlsclientTunnelUpStreamInit(f->tls, f->line);
    require(lineIsAlive(f->line) && f->hello != NULL, "ordinary Init failed to emit a ClientHello");
}

static void connectionDestroy(ech_fixture_t *f)
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
    if (f->server_hello != NULL)
        bufferpoolReuseBuffer(f->pools[0], f->server_hello);
    f->server_hello = NULL;
}

static void fixtureDestroy(ech_fixture_t *f)
{
    connectionDestroy(f);
    for (size_t i = 0; i < f->session_count; ++i)
        SSL_SESSION_free(f->sessions[i]);
    if (f->tls != NULL)
        tlsclientTunnelDestroy(f->tls, wwLifecycleStartupRollback());
    if (f->prev != NULL)
        tunnelDestroy(f->prev);
    if (f->next != NULL)
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

static void feedServerOutput(ech_fixture_t *f)
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
        if (f->server_hello == NULL)
        {
            f->server_hello = bufferpoolGetBestFit(f->pools[0], sizeof(header) + body_len, 0);
            sbufWrite(f->server_hello, sbufGetRawPtr(record), sbufGetLength(record));
            sbufSetLength(f->server_hello, sbufGetLength(record));
        }
        tlsclientTunnelDownStreamPayload(f->tls, f->line, record);
    }
}

static bool handshake(ech_fixture_t *f)
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

static void collectTickets(ech_fixture_t *f)
{
    require(SSL_write(f->server, NULL, 0) == 0, "failed to flush queued TLS 1.3 tickets");
    feedServerOutput(f);
    require(lineIsAlive(f->line), "connection closed while processing session tickets");
}

static void exchangePayload(ech_fixture_t *f)
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

static void addExtension(X509 *certificate, int identifier, const char *value)
{
    X509_EXTENSION *extension = X509V3_EXT_nconf_nid(NULL, NULL, identifier, value);
    require(extension != NULL && X509_add_ext(certificate, extension, -1) == 1,
            "failed to add an ECH fixture certificate extension");
    X509_EXTENSION_free(extension);
}

static X509 *newCertificate(EVP_PKEY *key, X509 *issuer, const char *hostname)
{
    X509 *certificate = X509_new();
    require(certificate != NULL && X509_set_version(certificate, X509_VERSION_3) == 1 &&
                ASN1_INTEGER_set(X509_get_serialNumber(certificate), hostname == NULL ? 1 : 2) == 1 &&
                X509_gmtime_adj(X509_getm_notBefore(certificate), -3600) != NULL &&
                X509_gmtime_adj(X509_getm_notAfter(certificate), 86400) != NULL &&
                X509_NAME_add_entry_by_txt(X509_get_subject_name(certificate),
                                           "CN",
                                           MBSTRING_ASC,
                                           (const uint8_t *) (hostname != NULL ? hostname : "ECH fixture root"),
                                           -1,
                                           -1,
                                           0) == 1 &&
                X509_set_issuer_name(certificate, X509_get_subject_name(issuer != NULL ? issuer : certificate)) == 1 &&
                X509_set_pubkey(certificate, key) == 1,
            "failed to construct an ECH fixture certificate");
    addExtension(certificate, NID_basic_constraints, hostname == NULL ? "critical,CA:TRUE" : "critical,CA:FALSE");
    addExtension(
        certificate, NID_key_usage, hostname == NULL ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    if (hostname != NULL)
    {
        char san[128];
        require(snprintf(san, sizeof(san), "DNS:%s", hostname) > 0, "failed to format fixture DNS SAN");
        addExtension(certificate, NID_subject_alt_name, san);
        addExtension(certificate, NID_ext_key_usage, "serverAuth");
    }
    require(X509_sign(certificate, key, EVP_sha256()) > 0, "failed to sign an ECH fixture certificate");
    return certificate;
}

static SSL_ECH_KEYS *newEchKeys(uint8_t identifier)
{
    EVP_HPKE_KEY *key           = EVP_HPKE_KEY_new();
    SSL_ECH_KEYS *keys          = SSL_ECH_KEYS_new();
    uint8_t      *config        = NULL;
    size_t        config_length = 0;
    require(key != NULL && keys != NULL && EVP_HPKE_KEY_generate(key, EVP_hpke_x25519_hkdf_sha256()) == 1 &&
                SSL_marshal_ech_config(&config, &config_length, identifier, key, kPublicName, 64) == 1 &&
                SSL_ECH_KEYS_add(keys, 1, config, config_length, key) == 1,
            "failed to create a real ECH key and configuration");
    OPENSSL_free(config);
    EVP_HPKE_KEY_free(key);
    return keys;
}

static char *encodeBase64(const uint8_t *data, size_t length)
{
    size_t encoded_length;
    require(EVP_EncodedLength(&encoded_length, length) == 1, "invalid fixture base64 length");
    char *encoded = memoryAllocate(encoded_length);
    require(encoded != NULL && EVP_EncodeBlock((uint8_t *) encoded, data, length) + 1 == encoded_length,
            "failed to encode the ECHConfigList");
    return encoded;
}

static char *encodedEchKeys(const SSL_ECH_KEYS *keys)
{
    uint8_t *list   = NULL;
    size_t   length = 0;
    require(SSL_ECH_KEYS_marshal_retry_configs(keys, &list, &length) == 1, "failed to marshal the ECHConfigList");
    char *encoded = encodeBase64(list, length);
    OPENSSL_free(list);
    return encoded;
}

static cJSON *newSettings(const char *config, bool verify, bool large_alpn)
{
    cJSON *settings =
        cJSON_Parse("{\"sni\":\"secret.ech.integration.test\",\"alpns\":[\"http/1.1\"],\"x25519mlkem768\":false}");
    require(settings != NULL && cJSON_AddBoolToObject(settings, "verify", verify) != NULL &&
                cJSON_AddStringToObject(settings, "ech-config-list", config) != NULL,
            "failed to create configured ECH settings");
    if (large_alpn)
    {
        cJSON *alpns = cJSON_GetObjectItemCaseSensitive(settings, "alpns");
        for (uint32_t i = 0; i < 32; ++i)
        {
            char protocol[UINT8_MAX + 1U];
            int  prefix = snprintf(protocol, sizeof(protocol), "ech-%02u-", i);
            require(prefix > 0 && prefix < UINT8_MAX, "failed to format large ALPN entry");
            memorySet(protocol + prefix, 'x', UINT8_MAX - (size_t) prefix);
            protocol[UINT8_MAX] = '\0';
            require(cJSON_AddItemToArray(alpns, cJSON_CreateString(protocol)), "failed to add large ALPN entry");
        }
    }
    return settings;
}

static int captureVerification(int ok, X509_STORE_CTX *context)
{
    ech_fixture_t *f   = active_fixture;
    f->verify_result   = X509_STORE_CTX_get_error(context);
    SSL        *ssl    = X509_STORE_CTX_get_ex_data(context, SSL_get_ex_data_X509_STORE_CTX_idx());
    const char *name   = NULL;
    size_t      length = 0;
    SSL_get0_ech_name_override(ssl, &name, &length);
    f->verified_public_name = length == sizeof(kPublicName) - 1 && memoryCompare(name, kPublicName, length) == 0;
    return ok;
}

static enum ssl_select_cert_result_t inspectServerHello(const SSL_CLIENT_HELLO *hello)
{
    ech_fixture_t *f   = active_fixture;
    f->server_accepted = SSL_ech_accepted(hello->ssl) != 0;
    const char *name   = SSL_get_servername(hello->ssl, TLSEXT_NAMETYPE_host_name);
    require(name != NULL && stringCompare(name, f->server_accepted ? kSecretName : kPublicName) == 0,
            "server observed the wrong decrypted or public SNI");
    const uint8_t *psk;
    size_t         psk_length;
    f->inner_psk = SSL_early_callback_ctx_extension_get(hello, TLSEXT_TYPE_pre_shared_key, &psk, &psk_length) != 0;
    return ssl_select_cert_success;
}

static void fixtureSetup(ech_fixture_t *f, bool correct_keys, bool secret_certificate, bool verify, bool large_alpn)
{
    fixtureEnvironment(f);
    SSL_ECH_KEYS *keys    = newEchKeys(1);
    char         *encoded = encodedEchKeys(keys);
    f->settings           = newSettings(encoded, verify, large_alpn);
    memoryFree(encoded);
    f->node.node_settings_json = f->settings;
    f->tls                     = tlsclientTunnelCreate(&f->node);
    f->prev                    = tunnelCreate(NULL, 0, 0);
    f->next                    = tunnelCreate(NULL, 0, 0);
    require(f->tls != NULL && f->prev != NULL && f->next != NULL, "failed to create configured ECH tunnels");
    tlsclient_tstate_t *ts    = tunnelGetState(f->tls);
    f->client_context         = ts->threadlocal_ssl_contexts[0];
    f->server_context         = SSL_CTX_new(TLS_server_method());
    EVP_PKEY *certificate_key = EVP_PKEY_generate_from_alg(EVP_pkey_ec_p256());
    require(certificate_key != NULL && f->server_context != NULL, "failed to allocate fixture authentication state");
    X509                *root = newCertificate(certificate_key, NULL, NULL);
    X509                *leaf = newCertificate(certificate_key, root, secret_certificate ? kSecretName : kPublicName);
    static const uint8_t sid_context[] = "tlsclient-ech-unit";
    require(X509_STORE_add_cert(SSL_CTX_get_cert_store(f->client_context), root) == 1 &&
                SSL_CTX_set_min_proto_version(f->server_context, TLS1_3_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(f->server_context, TLS1_3_VERSION) == 1 &&
                SSL_CTX_use_certificate(f->server_context, leaf) == 1 &&
                SSL_CTX_use_PrivateKey(f->server_context, certificate_key) == 1 &&
                SSL_CTX_set_session_id_context(f->server_context, sid_context, sizeof(sid_context) - 1) == 1 &&
                SSL_CTX_set_num_tickets(f->server_context, 2) == 1,
            "failed to configure authenticated ECH peers");
    if (! correct_keys)
    {
        SSL_ECH_KEYS_free(keys);
        keys = newEchKeys(2);
    }
    require(SSL_CTX_set1_ech_keys(f->server_context, keys) == 1, "failed to install server ECH keys");
    SSL_ECH_KEYS_free(keys);
    X509_free(root);
    X509_free(leaf);
    EVP_PKEY_free(certificate_key);
    SSL_CTX_set_verify(f->client_context, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, captureVerification);
    SSL_CTX_set_session_cache_mode(f->server_context, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_select_certificate_cb(f->server_context, inspectServerHello);
    f->cache_callback = SSL_CTX_sess_get_new_cb(f->client_context);
    require(f->cache_callback != NULL, "configured ECH context did not install its session cache");
    SSL_CTX_sess_set_new_cb(f->client_context, rememberSession);
    tunnelBind(f->prev, f->tls);
    tunnelBind(f->tls, f->next);
    f->next->fnInitU    = nextInit;
    f->next->fnPayloadU = nextPayload;
    f->next->fnFinU     = nextFinish;
    f->prev->fnPayloadD = prevPayload;
    f->prev->fnFinD     = prevFinish;
    f->prev->fnPauseD   = nextFinish;
    f->prev->fnResumeD  = nextFinish;
}

static void requireWireHello(const sbuf_t *hello, const char *expected_name)
{
    tls_client_hello_view_t view;
    const uint8_t          *bytes = (const uint8_t *) sbufGetRawPtr(hello);
    require(tlsclienthelloParseRecord(bytes, sbufGetLength(hello), &view) == kTlsClientHelloFound,
            "configured ECH produced a malformed outer ClientHello");
    CBS extensions;
    CBS_init(&extensions, bytes + view.extensions_offset, view.extensions_length);
    bool saw_name = false;
    bool saw_ech  = false;
    while (CBS_len(&extensions) != 0)
    {
        uint16_t type;
        CBS      contents;
        require(CBS_get_u16(&extensions, &type) && CBS_get_u16_length_prefixed(&extensions, &contents),
                "invalid outer ClientHello extension framing");
        require(type != TLSEXT_TYPE_pre_shared_key && type != TLSEXT_TYPE_early_data,
                "outer ClientHello exposed the inner PSK or enabled early data");
        if (type == TLSEXT_TYPE_server_name)
        {
            CBS     names, name;
            uint8_t name_type;
            require(CBS_get_u16_length_prefixed(&contents, &names) && CBS_get_u8(&names, &name_type) &&
                        name_type == 0 && CBS_get_u16_length_prefixed(&names, &name) && CBS_len(&names) == 0 &&
                        CBS_len(&contents) == 0 && CBS_len(&name) == strlen(expected_name) &&
                        memoryCompare(CBS_data(&name), expected_name, CBS_len(&name)) == 0,
                    "outer ClientHello exposed the wrong server name");
            saw_name = true;
        }
        if (type == TLSEXT_TYPE_encrypted_client_hello)
            saw_ech = CBS_len(&contents) > 0;
    }
    require(saw_name && saw_ech, "ClientHello omitted its public name or ECH extension");
    if (stringCompare(expected_name, kPublicName) == 0)
    {
        for (size_t offset = 0; offset + sizeof(kSecretName) - 1 <= sbufGetLength(hello); ++offset)
            require(memoryCompare(bytes + offset, kSecretName, sizeof(kSecretName) - 1) != 0,
                    "outer wire flight contains the secret hostname in plaintext");
    }
}

static void requireAccepted(ech_fixture_t *f, bool resumed)
{
    require(handshake(f), "configured real ECH handshake failed");
    tlsclient_lstate_t *ls = lineGetState(f->line, f->tls);
    require(SSL_ech_accepted(ls->ssl) && SSL_ech_accepted(f->server) && f->server_accepted,
            "handshake succeeded without accepting the configured real ECH");
    require(SSL_session_reused(ls->ssl) == resumed && SSL_session_reused(f->server) == resumed &&
                f->inner_psk == resumed,
            "decrypted inner PSK or actual ECH resumption does not match expectations");
    require(! f->verified_public_name && ! SSL_early_data_accepted(ls->ssl),
            "accepted ECH used the public certificate identity or early data");
    requireWireHello(f->hello, kPublicName);
}

static void requireWireBinding(ech_fixture_t *f)
{
#ifdef TLSCLIENT_ECH_REALITY_BINDING
    realityserver_tls_capture_t capture = {0};
    realityserver_tls_parser_t  client_parser, server_parser;
    realityserverTlsParserInitialize(&client_parser, kRealityServerTlsParserClientHello);
    realityserverTlsParserInitialize(&server_parser, kRealityServerTlsParserServerHello);
    require(f->server_hello != NULL &&
                realityserverTlsParserFeed(
                    &client_parser, (const uint8_t *) sbufGetRawPtr(f->hello), sbufGetLength(f->hello), &capture) &&
                realityserverTlsParserFeed(&server_parser,
                                           (const uint8_t *) sbufGetRawPtr(f->server_hello),
                                           sbufGetLength(f->server_hello),
                                           &capture) &&
                client_parser.complete && server_parser.complete && capture.client_ready && capture.server_ready,
            "Reality parser could not capture the visible ECH handshake");
    tlsclient_handshake_binding_t binding;
    require(tlsclientTunnelGetHandshakeBinding(f->tls, f->line, &binding) &&
                binding.tls_version == capture.binding.tls_version &&
                binding.cipher_suite == capture.binding.cipher_suite &&
                memoryEqual(binding.client_random, capture.binding.client_random, sizeof(binding.client_random)) &&
                memoryEqual(binding.server_random, capture.binding.server_random, sizeof(binding.server_random)),
            "TlsClient binding does not match the visible Reality handshake");
    uint8_t             inner_random[SSL3_RANDOM_SIZE];
    tlsclient_lstate_t *ls = lineGetState(f->line, f->tls);
    require(SSL_get_client_random(ls->ssl, inner_random, sizeof(inner_random)) == sizeof(inner_random) &&
                ! memoryEqual(inner_random, binding.client_random, sizeof(inner_random)),
            "ECH binding fixture did not distinguish the private and visible client randoms");
    realityserverTlsParserDestroy(&client_parser);
    realityserverTlsParserDestroy(&server_parser);
#else
    discard f;
#endif
}

static void testAcceptedAndResumed(void)
{
    ech_fixture_t f;
    fixtureSetup(&f, true, true, true, false);
    connectionStart(&f);
    requireAccepted(&f, false);
    require(f.verify_result == X509_V_OK, "accepted ECH did not authenticate the inner name");
    requireWireBinding(&f);
    exchangePayload(&f);
    collectTickets(&f);
    require(f.session_count > 0, "accepted ECH did not produce a resumable session");
    connectionDestroy(&f);

    /* Raw generation keeps its arbitrary-name, GREASE-only API and does not consume tickets. */
    line_t      caller  = {.wid = 0};
    const char *names[] = {kSecretName, "raw.ech.integration.test"};
    for (size_t i = 0; i < ARRAY_SIZE(names); ++i)
    {
        sbuf_t *hello =
            tlsclientTunnelGenerateClientHello(f.tls, &caller, (const uint8_t *) names[i], strlen(names[i]));
        require(hello != NULL, "raw GREASE generation failed on an ECH-configured node");
        requireWireHello(hello, names[i]);
        bufferpoolReuseBuffer(f.pools[0], hello);
    }
    connectionStart(&f);
    requireAccepted(&f, true);
    requireWireBinding(&f);
    exchangePayload(&f);
    fixtureDestroy(&f);
}

static void testRejected(bool correct_keys, bool verify)
{
    ech_fixture_t f;
    fixtureSetup(&f, correct_keys, false, verify, false);
    connectionStart(&f);
    requireWireHello(f.hello, kPublicName);
    sbuf_t *pending = bufferpoolGetSmallBuffer(f.pools[0]);
    sbufWrite(pending, "ping", 4);
    sbufSetLength(pending, 4);
    tlsclientTunnelUpStreamPayload(f.tls, f.line, pending);
    require(! handshake(&f) && ! lineIsAlive(f.line) && f.plaintext_bytes == 0 && f.init_count == 1,
            "rejected ECH leaked application data or silently retried a cleartext connection");
    if (correct_keys)
        require(f.verify_result == X509_V_ERR_HOSTNAME_MISMATCH && ! f.verified_public_name,
                "accepted ECH did not reject a certificate for the public rather than inner name");
    else
        require(f.verify_result == X509_V_OK && f.verified_public_name && ! f.server_accepted,
                "ECH rejection did not authenticate the public hostname before failing closed");
    uint8_t plaintext[4];
    require(SSL_read(f.server, plaintext, sizeof(plaintext)) <= 0 && f.session_count == 0,
            "rejected connection delivered queued application data or cached a session");
    fixtureDestroy(&f);
}

static void testOversizedTicket(void)
{
    ech_fixture_t f;
    fixtureSetup(&f, true, true, true, true);
    connectionStart(&f);
    requireAccepted(&f, false);
    collectTickets(&f);
    require(f.session_count > 0, "ECH ticket budget case did not cache a session");
    const size_t length = 60000;
    uint8_t     *ticket = memoryAllocate(length);
    require(ticket != NULL, "failed to allocate the oversized ECH ticket");
    memorySet(ticket, 0xa5, length);
    for (size_t i = 0; i < f.session_count; ++i)
        require(SSL_SESSION_set_ticket(f.sessions[i], ticket, length) == 1,
                "failed to install an individually representable ECH ticket");
    memoryFree(ticket);
    connectionDestroy(&f);
    connectionStart(&f);
    requireAccepted(&f, false);
    exchangePayload(&f);
    fixtureDestroy(&f);
}

static void testInvalidConfigs(void)
{
    static const uint8_t unsupported[]      = {0, 4, 0xff, 0xff, 0, 0};
    char                *unsupported_base64 = encodeBase64(unsupported, sizeof(unsupported));
    SSL_ECH_KEYS        *keys               = newEchKeys(1);
    char                *valid              = encodedEchKeys(keys);
    SSL_ECH_KEYS_free(keys);
    const char *configs[] = {"!invalid-base64!", "", "AAAA", unsupported_base64, valid};
    const char *cases[]   = {
        "invalid_base64", "empty_config", "malformed_config_list", "unsupported_config", "conflicting_grease_trick"};
    for (size_t i = 0; i < ARRAY_SIZE(configs); ++i)
    {
        testCaseSet(cases[i]);
        ech_fixture_t f;
        fixtureEnvironment(&f);
        f.settings = newSettings(configs[i], true, false);
        if (i == ARRAY_SIZE(configs) - 1)
            require(cJSON_AddStringToObject(f.settings, "ech-sni-trick", "trick.integration.test") != NULL,
                    "failed to construct the ECH conflict case");
        f.node.node_settings_json = f.settings;
        f.tls                     = tlsclientTunnelCreate(&f.node);
        require(f.tls == NULL, "constructor accepted malformed, unusable, or conflicting ECH configuration");
        fixtureDestroy(&f);
    }
    memoryFree(valid);
    memoryFree(unsupported_base64);
}

int main(void)
{
    testInvalidConfigs();
    testCaseSet("accepted_resumed_raw_and_visible_binding");
    testAcceptedAndResumed();
    testCaseSet("wrong_inner_certificate");
    testRejected(true, true);
    testCaseSet("authenticated_ech_rejection");
    testRejected(false, true);
    testCaseSet("ech_rejection_with_verify_disabled");
    testRejected(false, false);
    testCaseSet("ech_oversized_ticket_large_alpn");
    testOversizedTicket();
    return 0;
}
