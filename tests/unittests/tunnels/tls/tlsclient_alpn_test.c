/*
 * Covers: Verifies TlsClient's ordered `alpns` encoding, Chrome-like absent-setting default, explicit
 * empty-list disable mode, malformed-list rejection, serialized ALPS protocol offers, and in-memory
 * BoringSSL negotiations with empty client ALPS settings and peers that decline ALPS. Also verifies the
 * serialized supported groups and key shares with default, enabled, and disabled X25519MLKEM768, while
 * retaining the configured cipher ordering and matching Chrome's GREASE/ML-DSA signature offer.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testDefaultOrder, testConfiguredOrder, testEmptyListDisablesAlpn, testInvalidListsAreRejected,
 * testTotalWireLengthBounds, testConfiguredSniLengthBounds, testConfiguredClientHelloFramingBounds,
 * testGeneratedLargeClientHelloIsComplete; the driver lists the remaining cases
 * Checks: Assertion labels include: ordinary TlsClient Init emitted more than one initial-flight buffer;
 * default ALPN parsing failed; default ALPN order changed; configured ALPN parsing failed
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tlsclient_alpn_unit
 */
#include "TlsClient/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "fixtures/worker_registry_fixture.h"
#include "tls_client_hello.h"

#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

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
    master_pool_t  *medium_master;
    master_pool_t  *splice_master;
    buffer_pool_t  *pool;
    buffer_pool_t  *buffer_pools[1];
} tlsclient_test_worker_env_t;


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
    env->medium_master = masterpoolCreateWithCapacity(8);
    env->splice_master = masterpoolCreateWithCapacity(8);
    require(env->large_master != NULL && env->small_master != NULL, "failed to create ClientHello test master pools");

    env->pool = bufferpoolCreate(env->large_master,
                                 env->medium_master,
                                 env->small_master,
                                 env->splice_master,
                                 4,
                                 kTestLargeBufferSize,
                                 MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                 kTestSmallBufferSize,
                                 min((uint32_t) (kTestLargeBufferSize), (uint32_t) SPLICE_PAYLOAD_LIMIT),
                                 kTestLargeBufferSize);
    require(env->pool != NULL, "failed to create ClientHello test buffer pool");
    bufferpoolUpdateAllocationPaddings(
        env->pool, kTestBufferLeftPadding, kTestBufferLeftPadding, kTestBufferLeftPadding, kTestBufferLeftPadding);

    env->buffer_pools[0]         = env->pool;
    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.workers_count         = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);
}

static void workerEnvTeardown(tlsclient_test_worker_env_t *env)
{
    GSTATE.shortcut_buffer_pools = env->saved_buffer_pools;
    GSTATE.workers_count         = env->saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
    testWorkerBindWID(env->saved_wid);

    bufferpoolDestroy(env->pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->medium_master);
    masterpoolMakeEmpty(env->splice_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->medium_master);
    masterpoolDestroy(env->splice_master);
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

static cJSON *createTlsSettingsWithAlpnWireLength(size_t alpn_wire_len, const char *ech_sni)
{
    cJSON *settings      = createTlsSettings("example.com", ech_sni);
    cJSON *alpn_settings = createAlpnSettingsWithWireLength(alpn_wire_len);
    cJSON *alpns         = cJSON_GetObjectItemCaseSensitive(alpn_settings, "alpns");
    cJSON *alpn_copy     = cJSON_Duplicate(alpns, true);

    require(alpn_copy != NULL && cJSON_AddItemToObject(settings, "alpns", alpn_copy),
            "failed to install the ClientHello framing ALPN fixture");
    cJSON_Delete(alpn_settings);
    return settings;
}

static tunnel_t *createTlsClientFromSettings(node_t *node, cJSON *settings)
{
    *node = (node_t) {.node_settings_json = settings};
    return tlsclientTunnelCreate(node);
}

static cJSON *createTlsSettingsWithAlpns(const char *alpns)
{
    cJSON *settings = createTlsSettings("tls.integration.test", NULL);
    if (alpns != NULL)
    {
        cJSON *list = cJSON_Parse(alpns);
        require(list != NULL && cJSON_IsArray(list) && cJSON_AddItemToObject(settings, "alpns", list),
                "failed to configure the ALPS fixture protocol list");
    }
    return settings;
}

static void requireClientHelloAlps(const sbuf_t *hello, const uint8_t *expected_alpn, size_t expected_alpn_len,
                                   bool expect_alps)
{
    static const uint8_t    kH2Protocol[] = {2, 'h', '2'};
    tls_client_hello_view_t parsed        = {0};
    const uint8_t          *wire          = sbufGetRawPtr(hello);
    require(tlsclienthelloParseRecord(wire, sbufGetLength(hello), &parsed) == kTlsClientHelloFound,
            "ALPS fixture did not produce a complete ClientHello");

    CBS extensions;
    CBS_init(&extensions, wire + parsed.extensions_offset, parsed.extensions_length);
    bool found_alpn = false;
    bool found_alps = false;
    while (CBS_len(&extensions) > 0)
    {
        uint16_t type = 0;
        CBS      contents;
        require(CBS_get_u16(&extensions, &type) && CBS_get_u16_length_prefixed(&extensions, &contents),
                "ClientHello contains an invalid extension length");
        require(type != 17513, "TlsClient advertised the old ALPS codepoint");
        if (type != 16 && type != 17613)
        {
            continue;
        }

        CBS protocols;
        require(CBS_get_u16_length_prefixed(&contents, &protocols) && CBS_len(&contents) == 0,
                "ClientHello contains an invalid ALPN or ALPS protocol list");
        if (type == 16)
        {
            require(! found_alpn && CBS_len(&protocols) == expected_alpn_len &&
                        memoryCompare(CBS_data(&protocols), expected_alpn, expected_alpn_len) == 0,
                    "ClientHello changed the configured ALPN offer");
            found_alpn = true;
        }
        else
        {
            require(! found_alps && CBS_len(&protocols) == sizeof(kH2Protocol) &&
                        memoryCompare(CBS_data(&protocols), kH2Protocol, sizeof(kH2Protocol)) == 0,
                    "ClientHello ALPS must advertise only h2");
            found_alps = true;
        }
    }
    require(found_alpn == (expected_alpn_len != 0), "ClientHello ALPN presence differs from its configuration");
    require(found_alps == expect_alps, "ClientHello ALPS must be present exactly when h2 is configured");
}

static void testClientHelloAlpsProtocols(void)
{
    static const struct
    {
        const char *name;
        const char *alpns;
        const char *wire;
        bool        expect_alps;
    } cases[] = {
        {"alps_default",
         NULL,
         "\x02"
         "h2"
         "\x08"
         "http/1.1",
         true},
        {"alps_h2",
         "[\"h2\"]",
         "\x02"
         "h2",
         true},
        {"alps_http11",
         "[\"http/1.1\"]",
         "\x08"
         "http/1.1",
         false},
        {"alps_empty", "[]", "", false},
        {"alps_custom",
         "[\"foo\"]",
         "\x03"
         "foo",
         false},
        {"alps_custom_h2",
         "[\"foo\",\"h2\"]",
         "\x03"
         "foo"
         "\x02"
         "h2",
         true},
        {"alps_reordered",
         "[\"http/1.1\",\"h2\",\"foo\"]",
         "\x08"
         "http/1.1"
         "\x02"
         "h2"
         "\x03"
         "foo",
         true},
    };
    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        cJSON    *settings = createTlsSettingsWithAlpns(cases[i].alpns);
        node_t    node     = {0};
        tunnel_t *tunnel   = createTlsClientFromSettings(&node, settings);
        require(tunnel != NULL, "failed to create the ClientHello ALPS fixture");

        tlsclient_tstate_t *ts    = tunnelGetState(tunnel);
        sbuf_t             *hello = NULL;
        require(tlsclientCreateClientHelloFromContext(
                    ts->threadlocal_ssl_contexts[0], ts->sni, NULL, 0, ts->alpn_wire, ts->alpn_wire_len, &hello),
                "failed to generate the ClientHello ALPS fixture");
        requireClientHelloAlps(
            hello, (const uint8_t *) cases[i].wire, stringLength(cases[i].wire), cases[i].expect_alps);
        bufferpoolReuseBuffer(env.pool, hello);
        tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
        cJSON_Delete(settings);
    }
    workerEnvTeardown(&env);
    testCaseSet("tlsclient_alpn_test");
}

static void requireClientHelloGroups(const sbuf_t *hello, bool mlkem_enabled)
{
    static const uint16_t   kExpectedGroups[]       = {4588, 29, 23, 24};
    static const size_t     kExpectedShareLengths[] = {1216, 32};
    tls_client_hello_view_t parsed                  = {0};
    const uint8_t          *wire                    = sbufGetRawPtr(hello);
    require(tlsclienthelloParseRecord(wire, sbufGetLength(hello), &parsed) == kTlsClientHelloFound,
            "group fixture did not produce a complete ClientHello");

    CBS extensions, groups = {0}, shares = {0};
    CBS_init(&extensions, wire + parsed.extensions_offset, parsed.extensions_length);
    bool found_groups = false;
    bool found_shares = false;
    while (CBS_len(&extensions) > 0)
    {
        uint16_t type = 0;
        CBS      contents;
        require(CBS_get_u16(&extensions, &type) && CBS_get_u16_length_prefixed(&extensions, &contents),
                "ClientHello contains an invalid extension length");
        if (type == 10)
        {
            require(! found_groups && CBS_get_u16_length_prefixed(&contents, &groups) && CBS_len(&contents) == 0,
                    "ClientHello contains invalid supported_groups");
            found_groups = true;
        }
        else if (type == 51)
        {
            require(! found_shares && CBS_get_u16_length_prefixed(&contents, &shares) && CBS_len(&contents) == 0,
                    "ClientHello contains invalid key_share");
            found_shares = true;
        }
    }
    require(found_groups && found_shares, "ClientHello omitted supported_groups or key_share");

    uint16_t grease_group = 0;
    require(CBS_get_u16(&groups, &grease_group) && (grease_group & 0x0f0fU) == 0x0a0aU &&
                (grease_group >> 8U) == (grease_group & 0xffU),
            "supported_groups must start with a valid GREASE group");
    const size_t first_group = mlkem_enabled ? 0 : 1;
    for (size_t i = first_group; i < ARRAY_SIZE(kExpectedGroups); ++i)
    {
        uint16_t group = 0;
        require(CBS_get_u16(&groups, &group) && group == kExpectedGroups[i],
                "ClientHello supported_groups order or membership differs from the configured policy");
    }
    require(CBS_len(&groups) == 0, "ClientHello advertised an extra supported group, including P-521");

    uint16_t share_group = 0;
    CBS      key;
    require(CBS_get_u16(&shares, &share_group) && share_group == grease_group &&
                CBS_get_u16_length_prefixed(&shares, &key) && CBS_len(&key) == 1 && CBS_data(&key)[0] == 0,
            "key_share must start with the supported GREASE group and its one-byte dummy key");
    for (size_t i = first_group; i < ARRAY_SIZE(kExpectedShareLengths); ++i)
    {
        require(CBS_get_u16(&shares, &share_group) && share_group == kExpectedGroups[i] &&
                    CBS_get_u16_length_prefixed(&shares, &key) && CBS_len(&key) == kExpectedShareLengths[i],
                "ClientHello key-share group, order, or encoded key length differs from the configured policy");
    }
    require(CBS_len(&shares) == 0, "ClientHello advertised an unexpected additional key share");
}

static void requireClientHelloCipherAndSignatureProfile(const sbuf_t *hello)
{
    static const uint16_t kExpectedCiphers[] = {
        0x1301,
        0x1302,
        0x1303,
        0xc02b,
        0xc02f,
        0xc02c,
        0xc030,
        0xcca9,
        0xcca8,
        0xc013,
        0xc014,
        0x009c,
        0x009d,
        0x002f,
        0x0035,
    };
    static const uint16_t kExpectedSignatures[] = {
        0x0904,
        0x0905,
        0x0906,
        0x0403,
        0x0804,
        0x0401,
        0x0503,
        0x0805,
        0x0501,
        0x0806,
        0x0601,
    };
    tls_client_hello_view_t parsed = {0};
    const uint8_t          *wire   = sbufGetRawPtr(hello);
    require(tlsclienthelloParseRecord(wire, sbufGetLength(hello), &parsed) == kTlsClientHelloFound,
            "cipher and signature fixture did not produce a complete ClientHello");

    CBS body, session_id, ciphers;
    CBS_init(&body, wire + parsed.handshake_body_offset, parsed.handshake_body_length);
    require(CBS_skip(&body, 2U + SSL3_RANDOM_SIZE) && CBS_get_u8_length_prefixed(&body, &session_id) &&
                CBS_get_u16_length_prefixed(&body, &ciphers),
            "ClientHello contains an invalid cipher-suite list");
    uint16_t cipher = 0;
    require(CBS_get_u16(&ciphers, &cipher) && (cipher & 0x0f0fU) == 0x0a0aU && (cipher >> 8U) == (cipher & 0xffU),
            "ClientHello cipher list must start with one valid GREASE value");
    for (size_t i = 0; i < ARRAY_SIZE(kExpectedCiphers); ++i)
    {
        require(CBS_get_u16(&ciphers, &cipher) && cipher == kExpectedCiphers[i],
                "ClientHello changed the configured AES-first TLS 1.3 or TLS 1.2 cipher order");
    }
    require(CBS_len(&ciphers) == 0, "ClientHello advertised an unexpected additional cipher suite");

    CBS extensions, signatures = {0};
    CBS_init(&extensions, wire + parsed.extensions_offset, parsed.extensions_length);
    bool found_signatures = false;
    while (CBS_len(&extensions) > 0)
    {
        uint16_t type = 0;
        CBS      contents;
        require(CBS_get_u16(&extensions, &type) && CBS_get_u16_length_prefixed(&extensions, &contents),
                "ClientHello contains an invalid extension length");
        if (type == 13)
        {
            require(! found_signatures && CBS_get_u16_length_prefixed(&contents, &signatures) &&
                        CBS_len(&contents) == 0,
                    "ClientHello contains invalid signature_algorithms");
            found_signatures = true;
        }
    }
    require(found_signatures, "ClientHello omitted signature_algorithms");
    uint16_t signature = 0;
    require(CBS_get_u16(&signatures, &signature) && (signature & 0x0f0fU) == 0x0a0aU &&
                (signature >> 8U) == (signature & 0xffU),
            "ClientHello signature algorithms must start with one valid GREASE value");
    for (size_t i = 0; i < ARRAY_SIZE(kExpectedSignatures); ++i)
    {
        require(CBS_get_u16(&signatures, &signature) && signature == kExpectedSignatures[i],
                "ClientHello signature algorithms must match Chrome's ML-DSA and classical order");
    }
    require(CBS_len(&signatures) == 0, "ClientHello advertised an unexpected additional signature algorithm");
}

static void requireOrdinaryClientHelloProfile(tunnel_t *tls, buffer_pool_t *pool, bool mlkem_enabled)
{
    tunnel_t *prev = tunnelCreate(NULL, 0, 0);
    tunnel_t *next = tunnelCreate(NULL, 0, 0);
    require(prev != NULL && next != NULL, "failed to allocate ordinary ClientHello profile neighbors");
    tunnelBind(prev, tls);
    tunnelBind(tls, next);
    next->fnInitU    = captureOrdinaryInit;
    next->fnPayloadU = captureOrdinaryPayload;

    /* The fixture owns this scratch normal line; TlsClient only borrows it. */
    line_t *line = memoryAllocateCacheAlignedZero(sizeof(line_t) + tls->lstate_size);
    require(line != NULL, "failed to allocate ordinary ClientHello profile line");
    atomic_init(&line->refc, 1);
    line->alive          = true;
    line->wid            = 0;
    ordinary_init_count  = 0;
    ordinary_init_flight = NULL;
    tlsclientTunnelUpStreamInit(tls, line);
    require(ordinary_init_count == 1 && ordinary_init_flight != NULL,
            "ordinary TlsClient Init did not emit its initial flight");
    requireClientHelloGroups(ordinary_init_flight, mlkem_enabled);
    requireClientHelloCipherAndSignatureProfile(ordinary_init_flight);
    bufferpoolReuseBuffer(pool, ordinary_init_flight);
    ordinary_init_flight = NULL;
    tlsclientLinestateDestroy(lineGetState(line, tls));
    require(atomicLoadU32(&line->refc) == 1, "ordinary ClientHello profile leaked a line reference");
    memoryFreeAligned(line);
    tls->prev = NULL;
    tls->next = NULL;
    tunnelDestroy(prev);
    tunnelDestroy(next);
}

static void testClientHelloGroups(void)
{
    static const struct
    {
        const char *name;
        int         mlkem_setting;
    } cases[] = {
        {"groups_default", -1},
        {"groups_mlkem_enabled", 1},
        {"groups_mlkem_disabled", 0},
    };
    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        cJSON *settings = createTlsSettings("tls.integration.test", NULL);
        cJSON_DeleteItemFromObjectCaseSensitive(settings, "x25519mlkem768");
        if (cases[i].mlkem_setting >= 0)
        {
            require(cJSON_AddBoolToObject(settings, "x25519mlkem768", cases[i].mlkem_setting != 0) != NULL,
                    "failed to configure the supported-group fixture");
        }
        node_t    node   = {0};
        tunnel_t *tunnel = createTlsClientFromSettings(&node, settings);
        require(tunnel != NULL, "failed to create the supported-group TlsClient fixture");
        tlsclient_tstate_t *ts    = tunnelGetState(tunnel);
        sbuf_t             *hello = NULL;
        require(tlsclientCreateClientHelloFromContext(
                    ts->threadlocal_ssl_contexts[0], ts->sni, NULL, 0, ts->alpn_wire, ts->alpn_wire_len, &hello),
                "failed to generate the supported-group ClientHello fixture");
        requireClientHelloGroups(hello, cases[i].mlkem_setting != 0);
        requireClientHelloCipherAndSignatureProfile(hello);
        bufferpoolReuseBuffer(env.pool, hello);
        requireOrdinaryClientHelloProfile(tunnel, env.pool, cases[i].mlkem_setting != 0);
        tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
        cJSON_Delete(settings);
    }
    workerEnvTeardown(&env);
    testCaseSet("tlsclient_alpn_test");
}

static void testChromeReference(void)
{
    static const uint8_t        kChromeAlpn[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);
    testCaseSet("chrome_reference");

    FILE *capture = fopen(TLSCLIENT_CHROME_REFERENCE_FILE, "rb");
    require(capture != NULL, "failed to open the captured Chrome ClientHello");
    sbuf_t *hello  = bufferpoolGetLargeBuffer(env.pool);
    size_t  length = fread(sbufGetMutablePtr(hello), 1, sbufGetMaximumWriteableSize(hello), capture);
    require(length > 0 && fgetc(capture) == EOF && ! ferror(capture),
            "failed to read the complete captured Chrome ClientHello");
    require(fclose(capture) == 0, "failed to close the captured Chrome ClientHello");
    sbufSetLength(hello, (uint32_t) length);

    // Compare the scoped policies to real Chrome bytes. Other extensions remain
    // available in the fixture for subsequent fingerprint work.
    requireClientHelloAlps(hello, kChromeAlpn, sizeof(kChromeAlpn), true);
    requireClientHelloGroups(hello, true);
    requireClientHelloCipherAndSignatureProfile(hello);

    bufferpoolReuseBuffer(env.pool, hello);
    workerEnvTeardown(&env);
    testCaseSet("tlsclient_alpn_test");
}

static void testConfiguredSniLengthBounds(void)
{
    const uint32_t saved_workers_count = GSTATE.workers_count;
    char           maximum_sni[kTlsClientMaxSniLength + 1U];
    char           oversized_sni[kTlsClientMaxSniLength + 2U];

    GSTATE.workers_count = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);
    fillServerName(maximum_sni, kTlsClientMaxSniLength);
    fillServerName(oversized_sni, kTlsClientMaxSniLength + 1U);

    node_t    node     = {0};
    cJSON    *settings = createTlsSettings(maximum_sni, NULL);
    tunnel_t *tunnel   = createTlsClientFromSettings(&node, settings);
    require(tunnel != NULL, "maximum-length TlsClient SNI was rejected");
    tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    cJSON_Delete(settings);

    settings = createTlsSettings(oversized_sni, NULL);
    require(createTlsClientFromSettings(&node, settings) == NULL, "oversized TlsClient SNI was accepted");
    cJSON_Delete(settings);

    settings = createTlsSettings("example.com", oversized_sni);
    require(createTlsClientFromSettings(&node, settings) == NULL, "oversized TlsClient ECH SNI was accepted");
    cJSON_Delete(settings);

    GSTATE.workers_count = saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
}

static void testConfiguredClientHelloFramingBounds(void)
{
    const uint32_t saved_workers_count = GSTATE.workers_count;

    GSTATE.workers_count = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);

    node_t    node     = {0};
    cJSON    *settings = createTlsSettingsWithAlpnWireLength(kTestLargeAlpnWireSize, NULL);
    tunnel_t *tunnel   = createTlsClientFromSettings(&node, settings);
    require(tunnel != NULL, "a frameable large ALPN configuration was rejected");
    tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    cJSON_Delete(settings);

    settings = createTlsSettingsWithAlpnWireLength(kTlsClientMaxAlpnWireLength, NULL);
    require(createTlsClientFromSettings(&node, settings) == NULL,
            "an ALPN list that cannot fit the complete ClientHello was accepted");
    cJSON_Delete(settings);

    settings = createTlsSettingsWithAlpnWireLength(kTestLargeAlpnWireSize, "inner.example.com");
    require(createTlsClientFromSettings(&node, settings) == NULL,
            "an ECH override containing an oversized ClientHello was accepted");
    cJSON_Delete(settings);

    settings = createTlsSettingsWithAlpnWireLength(16, "inner.example.com");
    tunnel   = createTlsClientFromSettings(&node, settings);
    require(tunnel != NULL, "a frameable ECH ClientHello configuration was rejected");
    tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    cJSON_Delete(settings);

    GSTATE.workers_count = saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
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

    tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
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

    /*
     * The out-of-range identity is unregistered and has no
     * slot in the getWorkersCount()-sized SSL context arrays. It must be
     * rejected outright rather than falling back to worker 0's context.
     */
    const wid_t unregistered_wid         = getTotalWorkersCount();
    line_t      unregistered_worker_line = {.wid = unregistered_wid};
    testWorkerBindWID(unregistered_wid);
    require(tlsclientTunnelGenerateClientHello(
                tunnel, &unregistered_worker_line, hostname, (uint32_t) sizeof(hostname) - 1U) == NULL,
            "typed generation accepted the out-of-range identity");
    require(tlsclientTunnelGenerateClientHello(tunnel, &caller_line, hostname, (uint32_t) sizeof(hostname) - 1U) ==
                NULL,
            "typed generation let the out-of-range identity use worker 0's context");
    testWorkerBindWID(0);

    tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    cJSON_Delete(settings);
    workerEnvTeardown(&env);
}

static int selectProtocol(SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in, unsigned int in_len,
                          void *arg)
{
    const char  *protocol     = arg;
    const size_t protocol_len = stringLength(protocol);
    uint8_t      supported[UINT8_MAX + 1U];
    require(protocol_len > 0 && protocol_len <= UINT8_MAX, "invalid fixture ALPN selection");
    supported[0] = (uint8_t) protocol_len;
    memoryCopy(supported + 1, protocol, protocol_len);

    uint8_t *selected     = NULL;
    uint8_t  selected_len = 0;

    discard ssl;
    if (SSL_select_next_proto(&selected, &selected_len, in, in_len, supported, (unsigned int) protocol_len + 1U) !=
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

static void installMldsaCertificate(SSL_CTX *context, const EVP_PKEY_ALG *algorithm)
{
    EVP_PKEY *key         = EVP_PKEY_generate_from_alg(algorithm);
    X509     *certificate = X509_new();
    require(key != NULL && certificate != NULL, "failed to allocate the ML-DSA certificate fixture");
    require(X509_set_version(certificate, 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1 &&
                X509_gmtime_adj(X509_getm_notBefore(certificate), -60) != NULL &&
                X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) != NULL &&
                X509_NAME_add_entry_by_txt(X509_get_subject_name(certificate),
                                           "CN",
                                           MBSTRING_ASC,
                                           (const uint8_t *) "tls.integration.test",
                                           -1,
                                           -1,
                                           0) == 1 &&
                X509_set_issuer_name(certificate, X509_get_subject_name(certificate)) == 1 &&
                X509_set_pubkey(certificate, key) == 1 && X509_sign(certificate, key, NULL) > 0 &&
                SSL_CTX_use_certificate(context, certificate) == 1 && SSL_CTX_use_PrivateKey(context, key) == 1,
            "failed to create the ML-DSA certificate fixture");
    X509_free(certificate);
    EVP_PKEY_free(key);
}

static void testTls13AlpsAndSignatureNegotiation(void)
{
    static const struct
    {
        const char *name;
        const char *alpns;
        const char *selected;
        bool        server_alps;
        bool        expect_alps;
        const EVP_PKEY_ALG *(*key_algorithm)(void);
        uint16_t peer_signature;
    } cases[] = {
        {"alps_negotiated_empty_settings", NULL, "h2", true, true, NULL, 0},
        {"alps_declined_by_server", "[\"h2\"]", "h2", false, false, NULL, 0},
        {"alps_http11_selected", NULL, "http/1.1", true, false, NULL, 0},
        {"mldsa44_certificate_verify", "[\"h2\"]", "h2", false, false, EVP_pkey_ml_dsa_44, SSL_SIGN_ML_DSA_44},
        {"mldsa65_certificate_verify", "[\"h2\"]", "h2", false, false, EVP_pkey_ml_dsa_65, SSL_SIGN_ML_DSA_65},
        {"mldsa87_certificate_verify", "[\"h2\"]", "h2", false, false, EVP_pkey_ml_dsa_87, SSL_SIGN_ML_DSA_87},
    };
    tlsclient_test_worker_env_t env;
    workerEnvSetup(&env);
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].name);
        cJSON    *settings = createTlsSettingsWithAlpns(cases[i].alpns);
        node_t    node     = {0};
        tunnel_t *tunnel   = createTlsClientFromSettings(&node, settings);
        require(tunnel != NULL, "failed to create the TLS 1.3 negotiation TlsClient");
        tlsclient_tstate_t *ts             = tunnelGetState(tunnel);
        SSL_CTX            *client_context = ts->threadlocal_ssl_contexts[0];
        SSL_CTX            *server_context = SSL_CTX_new(TLS_server_method());
        require(server_context != NULL && SSL_CTX_set_min_proto_version(client_context, TLS1_3_VERSION) == 1 &&
                    SSL_CTX_set_max_proto_version(client_context, TLS1_3_VERSION) == 1 &&
                    SSL_CTX_set_min_proto_version(server_context, TLS1_3_VERSION) == 1 &&
                    SSL_CTX_set_max_proto_version(server_context, TLS1_3_VERSION) == 1,
                "failed to configure the TLS 1.3 negotiation contexts");
        if (cases[i].key_algorithm != NULL)
        {
            /* This fixture disables chain trust checks; TLS still verifies CertificateVerify. */
            installMldsaCertificate(server_context, cases[i].key_algorithm());
        }
        else
        {
            require(SSL_CTX_use_certificate_chain_file(server_context, REALITY_TEST_CERT_FILE) == 1 &&
                        SSL_CTX_use_PrivateKey_file(server_context, REALITY_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1,
                    "failed to load the ALPS negotiation certificate");
        }
        require(SSL_CTX_check_private_key(server_context) == 1, "TLS 1.3 fixture certificate/key mismatch");
        SSL_CTX_set_alpn_select_cb(server_context, selectProtocol, (void *) cases[i].selected);

        /* Use the same line-state and SSL configuration helpers as ordinary TlsClient Init. */
        STACK_ALLOCATE_CACHE_ALIGNED(tlsclient_lstate_t, client_state);
        memoryZero(client_state, sizeof(*client_state));
        require(tlsclientLinestateInitialize(client_state, client_context, env.pool, ts->alpn_wire, ts->alpn_wire_len),
                "failed to initialize the ALPS client line state");
        require(tlsclientConfigureSslForConnect(
                    client_state->ssl, client_state->rbio, client_state->wbio, ts->sni, NULL, 0),
                "failed to configure the ALPS client handshake");
        SSL *server      = SSL_new(server_context);
        BIO *server_rbio = BIO_new(BIO_s_mem());
        BIO *server_wbio = BIO_new(BIO_s_mem());
        require(server != NULL && server_rbio != NULL && server_wbio != NULL,
                "failed to allocate the ALPS negotiation peer");
        BIO_set_mem_eof_return(server_rbio, -1);
        BIO_set_mem_eof_return(server_wbio, -1);
        SSL_set_bio(server, server_rbio, server_wbio);
        SSL_set_accept_state(server);
        SSL_set_alps_use_new_codepoint(server, 1);
        if (cases[i].server_alps)
        {
            require(SSL_add_application_settings(
                        server, (const uint8_t *) cases[i].selected, stringLength(cases[i].selected), NULL, 0) == 1,
                    "failed to configure the ALPS negotiation peer settings");
        }

        if (! driveHandshake(client_state->ssl, server))
        {
            ERR_print_errors_fp(stderr);
            require(false, "TLS 1.3 ALPS or signature handshake failed");
        }
        require(SSL_version(client_state->ssl) == TLS1_3_VERSION && SSL_version(server) == TLS1_3_VERSION,
                "ALPS/signature fixture did not negotiate TLS 1.3");
        if (cases[i].peer_signature != 0)
        {
            require(SSL_get_peer_signature_algorithm(client_state->ssl) == cases[i].peer_signature,
                    "TlsClient did not verify the selected ML-DSA CertificateVerify signature");
        }
        const uint8_t *selected     = NULL;
        unsigned int   selected_len = 0;
        SSL_get0_alpn_selected(client_state->ssl, &selected, &selected_len);
        require(selected_len == stringLength(cases[i].selected) &&
                    memoryCompare(selected, cases[i].selected, selected_len) == 0,
                "ALPS fixture selected the wrong application protocol");
        require(SSL_has_application_settings(client_state->ssl) == cases[i].expect_alps &&
                    SSL_has_application_settings(server) == cases[i].expect_alps,
                "ALPS negotiation did not match the selected protocol and peer support");
        if (cases[i].expect_alps)
        {
            const uint8_t *client_settings     = NULL;
            size_t         client_settings_len = SIZE_MAX;
            SSL_get0_peer_application_settings(server, &client_settings, &client_settings_len);
            require(client_settings_len == 0, "TlsClient sent nonempty h2 ALPS application settings");
        }

        SSL_free(server);
        tlsclientLinestateDestroy(client_state);
        SSL_CTX_free(server_context);
        tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
        cJSON_Delete(settings);
    }
    workerEnvTeardown(&env);
    testCaseSet("tlsclient_alpn_test");
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

    GSTATE.workers_count = 1; // one ordinary event worker
    testWorkerRegistryInstall(&g_test_worker_registry);

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

    SSL_CTX_set_alpn_select_cb(server_context, selectProtocol, (void *) "http/1.1");

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
    tlsclientTunnelDestroy(tunnel, wwLifecycleStartupRollback());
    GSTATE.workers_count = saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
    cJSON_Delete(settings);
}

int main(void)
{
    testCaseSet("tlsclient_alpn_test");
    testDefaultOrder();
    testConfiguredOrder();
    testEmptyListDisablesAlpn();
    testInvalidListsAreRejected();
    testClientHelloAlpsProtocols();
    testClientHelloGroups();
    testChromeReference();
    testTls13AlpsAndSignatureNegotiation();
    testTotalWireLengthBounds();
    testConfiguredSniLengthBounds();
    testConfiguredClientHelloFramingBounds();
    testGeneratedLargeClientHelloIsComplete();
    testOrdinaryLargeClientHelloIsCompletelyDrained();
    testApiSniLengthBounds();
    testTypedClientHelloGeneration();
    testHttp11Negotiation();
    return 0;
}
