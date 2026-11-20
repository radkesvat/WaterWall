/* Actual Encryption constructors and packet callbacks: credential and crypto
 * diagnostics, explicit L3 selection, L4 defaults, both directions, independent
 * packets, and bad-input drops that leave the chain-owned packet line alive.
 * CTest: waterwall.encryption_packet_nodes_unit. */
#include "EncryptionClient/interface.h"
#include "EncryptionCommon/packet.h"
#include "EncryptionServer/interface.h"
#include "fixtures/worker_lines.h"
#include "loggers/network_logger.h"
#include "test_assert.h"

#define require(c, m) TEST_REQUIRE(TEST_FAILURE_EXIT, c, m)

static sbuf_t        *received;
static buffer_pool_t *packet_pool;
static unsigned       deliveries;
static char           last_log[512];

static void captureLog(int level, const char *text, int length)
{
    discard level;
    snprintf(last_log, sizeof(last_log), "%.*s", length, text);
}

static tunnel_t *createNode(bool server, const char *settings)
{
    node_t *node             = memoryAllocateZero(sizeof(*node));
    *node                    = server ? nodeEncryptionServerGet() : nodeEncryptionClientGet();
    node->node_settings_json = cJSON_Parse(settings);
    require(node->node_settings_json != NULL, "invalid test settings");
    tunnel_t *t = node->createHandle(node);
    if (t == NULL)
    {
        cJSON_Delete(node->node_settings_json);
        memoryFree(node->type);
        memoryFree(node);
    }
    return t;
}

static void destroyNode(tunnel_t *t)
{
    node_t *node = tunnelGetNode(t);
    t->onDestroy(t, wwLifecycleStartupRollback());
    cJSON_Delete(node->node_settings_json);
    memoryFree(node->type);
    memoryFree(node);
}

static void recordPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    require(lineIsAlive(line), "delivered on a dead packet line");
    require(received == NULL, "delivery overwrote an owned buffer");
    received = buf;
    ++deliveries;
}

static sbuf_t *takeReceived(void)
{
    sbuf_t *buf = received;
    require(buf != NULL, "expected packet delivery");
    received = NULL;
    return buf;
}

static sbuf_t *packet(void)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(packet_pool);
    sbufSetLength(buf, 96);
    uint8_t *p = sbufGetMutablePtr(buf);
    memoryZero(p, 96);
    p[0] = 0x45;
    PUT_BE16(p + 2, 96);
    p[8] = 64;
    p[9] = 6;
    PUT_BE32(p + 12, 0xc0000201U);
    PUT_BE32(p + 16, 0xc6336401U);
    PUT_BE16(p + 20, 40001);
    PUT_BE16(p + 22, 40000);
    p[32] = 0x50;
    p[33] = 0x18;
    for (unsigned i = 40; i < 96; ++i)
        p[i] = (uint8_t) i;
    require(calcFullPacketChecksum(p, 96), "fixture checksum failed");
    return buf;
}

static void testSettings(void)
{
    const char *bad[] = {
        "{\"password\":\"secret\",\"packet-mode\":\"true\"}",
        "{\"password\":\"secret\",\"packet-mode\":null}",
        "{\"password\":\"secret\",\"packet-mode\":true,\"algorithm\":\"chacha20-poly1305\"}",
        "{\"password\":\"secret\",\"packet-mode\":true,\"algorithm\":\"aes-gcm\"}",
        "{\"password\":\"secret\",\"algorithm\":\"xchacha20-poly1305\"}",
        "{\"password\":\"secret\",\"packet-mode\":true,\"max-frame-size\":100}",
        "{\"password\":\"\",\"packet-mode\":true}",
    };
    for (unsigned role = 0; role < 2; ++role)
    {
        tunnel_t *stream = createNode(role != 0, "{\"password\":\"secret\",\"kdf-iterations\":2}");
        require(stream != NULL && stream->lstate_size != 0 && tunnelGetNode(stream)->layer_group == kNodeLayer4 &&
                    tunnelGetNode(stream)->required_padding_left == 17,
                "stream defaults changed");
        destroyNode(stream);
        tunnel_t *packets =
            createNode(role != 0, "{\"packet-mode\":true,\"password\":\"secret\",\"kdf-iterations\":2}");
        require(packets != NULL && packets->lstate_size == 0 && tunnelGetNode(packets)->layer_group == kNodeLayer3 &&
                    tunnelGetNode(packets)->layer_group_prev_node == kNodeLayer3 &&
                    tunnelGetNode(packets)->layer_group_next_node == kNodeLayer3 &&
                    tunnelGetNode(packets)->required_padding_left == 24,
                "packet metadata/state incorrect");
        destroyNode(packets);
        for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
            require(createNode(role != 0, bad[i]) == NULL, "invalid packet profile accepted");
    }
}

static void expectStartupError(bool server, const char *settings, const char *diagnostic)
{
    last_log[0] = '\0';
    require(createNode(server, settings) == NULL, "invalid Encryption configuration started");
    require(strstr(last_log, server ? "EncryptionServer: " : "EncryptionClient: ") != NULL &&
                strstr(last_log, diagnostic) != NULL,
            last_log);
}

static void testUninitializedCrypto(void)
{
    for (unsigned role = 0; role < 2; ++role)
        expectStartupError(role != 0,
                           "{\"password\":\"secret\",\"kdf-iterations\":2}",
                           "failed to derive base key: invalid crypto state");
}

static void testCredentialLimits(void)
{
    for (unsigned role = 0; role < 2; ++role)
    {
        const bool server = role != 0;
        expectStartupError(server,
                           "{\"password\":\"012345678901234567890123456789012\",\"kdf-iterations\":2}",
                           "'password' must be at most 32 bytes in stream mode");
        expectStartupError(
            server,
            "{\"password\":\"secret\",\"salt\":\"012345678901234567890123456789012\",\"kdf-iterations\":1}",
            "'salt' must be at most 32 bytes");
        expectStartupError(server,
                           "{\"packet-mode\":true,\"password\":\"secret\","
                           "\"salt\":\"012345678901234567890123456789012\",\"kdf-iterations\":2}",
                           "'salt' must be at most 32 bytes");

        tunnel_t *t = createNode(server,
                                 "{\"password\":\"01234567890123456789012345678901\","
                                 "\"salt\":\"01234567890123456789012345678901\",\"kdf-iterations\":2}");
        require(t != NULL, "32-byte stream credentials were rejected");
        destroyNode(t);

        t = createNode(server,
                       "{\"password\":\"012345678901234567890123456789012\",\"salt\":\"\",\"kdf-iterations\":1}");
        require(t != NULL, "one-round stream configuration with a long password and empty salt was rejected");
        destroyNode(t);
    }
}

static void testCallbacks(void)
{
    const char      *settings = "{\"packet-mode\":true,\"algorithm\":\"xchacha20-poly1305\","
                                "\"password\":\"a secret that deliberately exceeds thirty two bytes in length\","
                                "\"kdf-iterations\":2}";
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 24);
    packet_pool            = env.pool;
    line_t        *line    = twfLineCreate(0);
    line_t        *lines[] = {line};
    tunnel_chain_t chain = {.workers_count = 1, .contains_packet_node = true, .finalized = true, .packet_lines = lines};
    tunnel_t      *client = createNode(false, settings), *server = createNode(true, settings);
    require(client != NULL && server != NULL, "long-password packet constructors failed");
    node_t    sink_node = {0};
    tunnel_t *sink      = tunnelCreate(&sink_node, 0, 0);
    require(sink != NULL, "sink allocation failed");
    sink->fnPayloadU = recordPayload;
    sink->fnPayloadD = recordPayload;
    client->chain = server->chain = sink->chain = &chain;
    client->prev = client->next = server->prev = server->next = sink;
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        sbuf_t *buf = packet();
        uint8_t original[96];
        memoryCopy(original, sbufGetRawPtr(buf), sizeof(original));
        const unsigned before = deliveries;
        if (direction == 0)
            tunnelUpStreamPayload(client, line, buf);
        else
            tunnelDownStreamPayload(server, line, buf);
        buf = takeReceived();
        require(sbufGetLength(buf) == 136, "packet encode did not add exactly forty bytes");
        if (direction == 0)
            tunnelUpStreamPayload(server, line, buf);
        else
            tunnelDownStreamPayload(client, line, buf);
        buf = takeReceived();
        require(sbufGetLength(buf) == sizeof(original) && memoryEqual(sbufGetRawPtr(buf), original, sizeof(original)),
                "node packet roundtrip changed data");
        require(deliveries == before + 2 && lineIsAlive(line) && twfLineRefCount(line) == 1,
                "packet callbacks changed line lifetime or delivery count");
        lineReuseBuffer(line, buf);
    }

    tunnelUpStreamPayload(client, line, packet());
    sbuf_t *buf = takeReceived();
    sbufGetMutablePtr(buf)[sbufGetLength(buf) - 1] ^= 1;
    sbufSetRecalculateChecksum(buf, true);
    const unsigned before = deliveries;
    tunnelUpStreamPayload(server, line, buf);
    require(received == NULL && deliveries == before && lineIsAlive(line) && twfLineRefCount(line) == 1,
            "bad authentication forwarded or destroyed packet line");
    buf = packet();
    PUT_BE16(sbufGetMutablePtr(buf) + 6, 0x2000);
    tunnelDownStreamPayload(server, line, buf);
    require(received == NULL && deliveries == before && lineIsAlive(line), "fragment forwarded or closed packet line");
    tunnelUpStreamPayload(client, line, packet());
    tunnelDownStreamPayload(client, line, takeReceived());
    require(received == NULL && deliveries == before + 1 && lineIsAlive(line),
            "upload packet authenticated with download direction key");
    /* An authentication failure must not poison later independent packets. */
    tunnelUpStreamPayload(client, line, packet());
    tunnelUpStreamPayload(server, line, takeReceived());
    lineReuseBuffer(line, takeReceived());
    destroyNode(client);
    destroyNode(server);
    tunnelDestroy(sink);
    twfLineDestroy(line);
    twfWorkerEnvTeardown(&env);
}

int main(void)
{
    testCaseSet("encryption_packet_nodes_test");
    initWLibc();
    checkSumInit();
    require(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    frandInit();
    logger_t *logger = loggerCreate();
    require(logger != NULL, "logger allocation failed");
    loggerSetHandler(logger, captureLog);
    setNetworkLogger(logger);
    TEST_RUN_CASE(testUninitializedCrypto);
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    TEST_RUN_CASE(testSettings);
    TEST_RUN_CASE(testCredentialLimits);
    TEST_RUN_CASE(testCallbacks);
    networkloggerDestroy();
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
