/*
 * Covers: FakeTcpHeaderClient and FakeTcpHeaderServer node metadata and constructors.
 * Contract: both nodes are Layer-3 packet transforms with 60 bytes of left padding, explicit native TCP/UDP
 * protocol and no line state. Constructors retain the other defaults and report invalid settings by node/key.
 * All four actual payload callbacks forward the exact sbuf once or recycle it once, preserving the packet line.
 * Cases: testMetadata, testDefaults, testConfigured, testRejections, testPayloadCallbacks (both nodes);
 * testIpOverriderComposition (when IpOverrider is available).
 * Setup: capturing logger; existing worker/pool/packet-chain fixture and buffer ownership ledger on Linux.
 * Limits: socket delivery belongs to the namespace integrations; independent wire oracle is in the codec unit.
 * CTest: waterwall.fake_tcp_header_nodes_unit
 */
#include "FakeTcpHeaderClient/interface.h"
#include "FakeTcpHeaderClient/structure.h"
#include "FakeTcpHeaderServer/interface.h"
#include "FakeTcpHeaderServer/structure.h"

#include "test_assert.h"

#if FAKE_TCP_HEADER_CALLBACK_FIXTURE
#include "fixtures/worker_lines.h"
#endif
#if FAKE_TCP_HEADER_IPOVERRIDER_FIXTURE
#include "IpOverrider/structure.h"
#endif

#include "loggers/network_logger.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

enum
{
    kLogCaptureCapacity = 8192
};

typedef struct node_case_s
{
    const char *type_name;
    node_t (*get)(void);
    TunnelFlowRoutinePayload upstream_payload;
    TunnelFlowRoutinePayload downstream_payload;
    const faketcpheader_wire_config_t *(*wire)(tunnel_t *t);
} node_case_t;

static char   log_capture[kLogCaptureCapacity];
static size_t log_capture_len;

static void captureLog(int log_level, const char *buf, int len)
{
    discard log_level;
    if (buf == NULL || len <= 0 || log_capture_len >= sizeof(log_capture) - 1U)
    {
        return;
    }

    const size_t copy_len = min((size_t) len, sizeof(log_capture) - log_capture_len - 1U);
    memoryCopy(log_capture + log_capture_len, buf, copy_len);
    log_capture_len += copy_len;
    log_capture[log_capture_len] = '\0';
}

static void resetLogCapture(void)
{
    log_capture_len = 0;
    log_capture[0]  = '\0';
}

static const faketcpheader_wire_config_t *clientWire(tunnel_t *t)
{
    return &((faketcpheaderclient_tstate_t *) tunnelGetState(t))->wire;
}

static const faketcpheader_wire_config_t *serverWire(tunnel_t *t)
{
    return &((faketcpheaderserver_tstate_t *) tunnelGetState(t))->wire;
}

static tunnel_t *createWithSettings(const node_case_t *c, const char *json)
{
    node_t node             = c->get();
    cJSON *settings         = json != NULL ? cJSON_Parse(json) : NULL;
    node.node_settings_json = settings;
    require(json == NULL || settings != NULL, "settings fixture JSON failed to parse");

    resetLogCapture();
    tunnel_t *t = node.createHandle(&node);
    cJSON_Delete(settings);
    memoryFree(node.type);
    return t;
}

static void destroyTunnel(tunnel_t *t)
{
    t->onDestroy(t, wwLifecycleStartupRollback());
}

static void testMetadata(const node_case_t *c)
{
    node_t node = c->get();
    require(node.type != NULL && stringCompare(node.type, c->type_name) == 0, "node type name changed");
    require(node.hash_type == calcHashBytes(c->type_name, stringLength(c->type_name)), "node type hash mismatch");
    require(node.version == 0001, "node version changed");
    require(node.flags == kNodeFlagNone, "node flags changed");
    require(node.required_padding_left == kFakeTcpHeaderWireRequiredPaddingLeft && node.required_padding_left == 60,
            "node does not advertise the 60-byte fake TCP padding");
    require(node.layer_group == kNodeLayer3 && node.layer_group_prev_node == kNodeLayer3 &&
                node.layer_group_next_node == kNodeLayer3,
            "node is not a Layer-3 packet transform between Layer-3 neighbours");
    require(node.can_have_prev && node.can_have_next, "node must accept both neighbours");
    require(node.createHandle != NULL, "node has no constructor");
    memoryFree(node.type);
}

static void requireDefaults(const faketcpheader_wire_config_t *wire)
{
    require(wire->server_port == 40000 && wire->client_port == 40001 && wire->client_port_count == 16,
            "default carrier ports changed");
    require(wire->sequence == 0 && wire->acknowledgment == 0 && wire->window == 65535 && wire->urgent_pointer == 0,
            "default TCP header template changed");
    require(wire->options_length == 0, "default TCP options are not empty");
}

static void testDefaults(const node_case_t *c)
{
    const char *const fixtures[] = {"{\"payload-protocol\":6}", "{\"payload-protocol\":17}"};
    for (size_t i = 0; i < ARRAY_SIZE(fixtures); ++i)
    {
        tunnel_t *t = createWithSettings(c, fixtures[i]);
        require(t != NULL, "constructor refused default settings");
        require(log_capture_len == 0, "constructor logged while accepting default settings");
        require(t->fnPayloadU == c->upstream_payload, "constructor did not install the node's upstream payload");
        require(t->fnPayloadD == c->downstream_payload, "constructor did not install the node's downstream payload");
        require(t->onDestroy == tunnelDefaultOnDestroy, "constructor replaced the default destroy");
        require(t->lstate_size == 0, "packet transform must not reserve line state");
        requireDefaults(c->wire(t));
        require(c->wire(t)->payload_protocol == (i == 0 ? 6 : 17), "required native protocol was not loaded");
        destroyTunnel(t);
    }
}

static void testConfigured(const node_case_t *c)
{
    tunnel_t *t = createWithSettings(
        c,
        "{\"payload-protocol\":6,\"server-port\":443,\"client-port\":50000,\"client-port-count\":1024,"
        "\"sequence\":4294967295,\"acknowledgment\":7,\"window\":0,"
        "\"urgent-pointer\":65535,\"options\":\"0101080a\"}");
    require(t != NULL, "constructor refused a valid configuration");
    const faketcpheader_wire_config_t *wire = c->wire(t);
    require(wire->server_port == 443 && wire->client_port == 50000 && wire->client_port_count == 1024,
            "configured carrier ports were not loaded");
    require(wire->sequence == UINT32_MAX && wire->acknowledgment == 7 && wire->window == 0 &&
                wire->urgent_pointer == UINT16_MAX,
            "configured TCP header template was not loaded");
    require(wire->options_length == 4 && wire->options[0] == 0x01 && wire->options[2] == 0x08 &&
                wire->options[3] == 0x0a,
            "configured TCP options were not loaded");
    destroyTunnel(t);
}

static void requireRejected(const node_case_t *c, const char *json, const char *key)
{
    char expected[128];
    snprintf(expected, sizeof(expected), "JSON Error: %s->settings->%s : ", c->type_name, key);

    tunnel_t *t = createWithSettings(c, json);
    if (t != NULL)
    {
        destroyTunnel(t);
    }
    require(t == NULL, "constructor accepted invalid settings");
    require(strstr(log_capture, expected) != NULL, "rejection did not name the node and the offending key");
}

static void testRejections(const node_case_t *c)
{
    const char *const bad_protocol[] = {NULL,
                                        "{}",
                                        "{\"payload-protocol\":null}",
                                        "{\"payload-protocol\":6.5}",
                                        "{\"payload-protocol\":6.0}",
                                        "{\"payload-protocol\":6e0}",
                                        "{\"payload-protocol\":7}",
                                        "{\"payload-protocol\":16}",
                                        "{\"window\":1}",
                                        "{\"payload-protocol\":\"17\"}",
                                        "{\"payload-protocol\":true}",
                                        "{\"payload-protocol\":false}",
                                        "{\"payload-protocol\":-1}",
                                        "{\"payload-protocol\":0}",
                                        "{\"payload-protocol\":1}",
                                        "{\"payload-protocol\":256}",
                                        "{\"payload-protocol\":4294967296}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad_protocol); ++i)
        requireRejected(c, bad_protocol[i], "payload-protocol");

    static const char *const removed[] = {
        "role", "protocol-number", "flags", "mtu", "local-ipv4", "peer-ipv4", "local-port", "peer-port"};
    for (size_t i = 0; i < ARRAY_SIZE(removed); ++i)
    {
        char json[96];
        snprintf(json, sizeof(json), "{\"payload-protocol\":17,\"%s\":1}", removed[i]);
        requireRejected(c, json, removed[i]);
    }

    requireRejected(c, "{\"payload-protocol\":17,\"client-port-count\":1025}", "client-port-count");
    requireRejected(c, "{\"payload-protocol\":17,\"server-port\":0}", "server-port");
    requireRejected(c, "{\"payload-protocol\":17,\"window\":65536}", "window");
    requireRejected(c, "{\"payload-protocol\":17,\"server-port\":40001}", "server-port");
    requireRejected(c, "{\"payload-protocol\":17,\"options\":\"010101\"}", "options");

    char expected[128];
    snprintf(expected, sizeof(expected), "JSON Error: %s->settings : expected an object", c->type_name);
    tunnel_t *t = createWithSettings(c, "[]");
    require(t == NULL, "constructor accepted a non-object settings value");
    require(strstr(log_capture, expected) != NULL, "non-object rejection did not name the node");
}

#if FAKE_TCP_HEADER_CALLBACK_FIXTURE
static unsigned forwarded_up, forwarded_down, unexpected_callbacks;
static line_t  *forwarded_line;
static sbuf_t  *forwarded_buffer;

static void recordUp(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    ++forwarded_up;
    forwarded_line   = line;
    forwarded_buffer = buf;
}
static void recordDown(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    ++forwarded_down;
    forwarded_line   = line;
    forwarded_buffer = buf;
}
static void recordUnexpected(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    ++unexpected_callbacks;
}
static void resetForwarding(void)
{
    forwarded_up = forwarded_down = unexpected_callbacks = 0;
    forwarded_line                                       = NULL;
    forwarded_buffer                                     = NULL;
}
static tunnel_t *recordingTunnel(void)
{
    tunnel_t *t = tunnelCreate(NULL, 0, 0);
    require(t != NULL, "recording tunnel constructor");
    t->fnPayloadU = recordUp;
    t->fnPayloadD = recordDown;
    t->fnInitU = t->fnInitD = t->fnEstU = t->fnEstD = t->fnFinU = t->fnFinD = recordUnexpected;
    t->fnPauseU = t->fnPauseD = t->fnResumeU = t->fnResumeD = recordUnexpected;
    return t;
}
static void makeNative(uint8_t *packet, uint8_t protocol)
{
    memoryZero(packet, 80);
    packet[0] = 0x45;
    packet[1] = 0xab;
    PUT_BE16(packet + 2, 80);
    PUT_BE16(packet + 4, 0x1234);
    PUT_BE16(packet + 6, 0x4000);
    packet[8] = 47;
    packet[9] = protocol;
    PUT_BE32(packet + 12, 0x0a000001U);
    PUT_BE32(packet + 16, 0x0a000002U);
    PUT_BE16(packet + 20, 5000);
    PUT_BE16(packet + 22, 53);
    if (protocol == 6)
    {
        packet[32] = 0x50;
        packet[33] = 0x19;
        PUT_BE32(packet + 24, 0x87654321U);
        PUT_BE32(packet + 28, 0xfedcba98U);
    }
    else
        PUT_BE16(packet + 24, 60);
    for (unsigned i = 40; i < 80; ++i)
        packet[i] = (uint8_t) i;
    require(calcFullPacketChecksum(packet, 80), "native fixture checksum");
}
static sbuf_t *pooledPacket(line_t *line, const uint8_t *packet, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    require(sbufGetLeftCapacity(buf) >= 60, "fixture did not advertise fake TCP headroom");
    sbufSetLength(buf, length);
    memoryCopy(sbufGetMutablePtr(buf), packet, length);
    return buf;
}
static void requireForwarded(bool upstream, line_t *line, sbuf_t *buf)
{
    require(forwarded_up == (upstream ? 1U : 0U) && forwarded_down == (upstream ? 0U : 1U),
            "payload forwarded in wrong direction or more than once");
    require(forwarded_line == line && forwarded_buffer == buf, "forwarding did not transfer the exact line/buffer");
    require(unexpected_callbacks == 0, "payload emitted an unexpected lifecycle callback");
    require(lineIsAlive(line), "payload destroyed the chain-owned packet line");
}
static void testPayloadCallbacks(const node_case_t *c)
{
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 60);
    line_t        *line    = twfLineCreate(0);
    line_t        *lines[] = {line};
    tunnel_chain_t chain = {.workers_count = 1, .contains_packet_node = true, .finalized = true, .packet_lines = lines};
    tunnel_t      *prev = recordingTunnel(), *next = recordingTunnel();
    uint8_t        packet[80];
    for (unsigned p = 0; p < 2; ++p)
    {
        const uint8_t protocol = p == 0 ? 6 : 17;
        char          settings[64];
        snprintf(settings, sizeof(settings), "{\"payload-protocol\":%u}", protocol);
        tunnel_t *t = createWithSettings(c, settings);
        require(t != NULL, "callback fixture constructor");
        t->chain = &chain;
        tunnelBind(prev, t);
        tunnelBind(t, next);
        makeNative(packet, protocol);
        for (unsigned direction = 0; direction < 2; ++direction)
        {
            const bool                      upstream  = direction == 0;
            const bool                      is_client = strcmp(c->type_name, "FakeTcpHeaderClient") == 0;
            const bool                      encoding  = upstream == is_client;
            const faketcpheader_wire_side_t side      = is_client ? kFakeTcpHeaderWireClient : kFakeTcpHeaderWireServer;
            sbuf_t                         *buf       = pooledPacket(line, packet, sizeof(packet));
            if (! encoding)
                require(faketcpheaderWireEncode(c->wire(t),
                                                side == kFakeTcpHeaderWireClient ? kFakeTcpHeaderWireServer
                                                                                 : kFakeTcpHeaderWireClient,
                                                buf) == kFakeTcpHeaderWireOk,
                        "incoming carrier fixture");
            const uint32_t recycled = twfRecycleCount();
            resetForwarding();
            if (upstream)
                t->fnPayloadU(t, line, buf);
            else
                t->fnPayloadD(t, line, buf);
            requireForwarded(upstream, line, buf);
            require(twfRecycleCount() == recycled, "successful forwarding recycled a transferred buffer");
            if (encoding)
            {
                require(sbufGetLength(buf) == 100, "callback did not insert exactly fake TCP");
                require(faketcpheaderWireDecode(c->wire(t),
                                                side == kFakeTcpHeaderWireClient ? kFakeTcpHeaderWireServer
                                                                                 : kFakeTcpHeaderWireClient,
                                                buf) == kFakeTcpHeaderWireOk,
                        "encoded callback output invalid");
            }
            require(sbufGetLength(buf) == sizeof(packet) && memoryEqual(sbufGetRawPtr(buf), packet, sizeof(packet)),
                    "payload callback did not preserve native packet");
            lineReuseBuffer(line, buf);

            buf                             = pooledPacket(line, packet, 1);
            const uint32_t refused_recycles = twfRecycleCount();
            resetForwarding();
            if (upstream)
                t->fnPayloadU(t, line, buf);
            else
                t->fnPayloadD(t, line, buf);
            require(forwarded_up == 0 && forwarded_down == 0 && unexpected_callbacks == 0,
                    "refused payload emitted callbacks");
            require(twfRecycleCount() == refused_recycles + 1, "refused payload was not recycled exactly once");
            twfRequireLastRecycle(buf, lineGetBufferPool(line), "refusal used another line's pool");
            require(lineIsAlive(line), "refusal destroyed packet line");
        }
        destroyTunnel(t);
    }
    twfLineDestroy(line); /* Bare fixture allocation; production chain owns packet-line teardown. */
    tunnelDestroy(prev);
    tunnelDestroy(next);
    twfWorkerEnvTeardown(&env);
}

#if FAKE_TCP_HEADER_IPOVERRIDER_FIXTURE
static tunnel_t *createOverride(const char *up_source, const char *up_dest, const char *down_source,
                                const char *down_dest)
{
    char json[512];
    snprintf(json,
             sizeof(json),
             "{\"up\":{\"source-ip\":{\"ipv4\":\"%s\"},\"dest-ip\":{\"ipv4\":\"%s\"}},"
             "\"down\":{\"source-ip\":{\"ipv4\":\"%s\"},\"dest-ip\":{\"ipv4\":\"%s\"}}}",
             up_source,
             up_dest,
             down_source,
             down_dest);
    cJSON *settings = cJSON_Parse(json);
    require(settings != NULL, "IpOverrider settings fixture");
    node_t    node = {.node_settings_json = settings};
    tunnel_t *t    = ipoverriderCreate(&node);
    cJSON_Delete(settings);
    require(t != NULL, "IpOverrider constructor");
    return t;
}
static void testIpOverriderComposition(const node_case_t *client, const node_case_t *server)
{
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 120);
    line_t        *line    = twfLineCreate(0);
    line_t        *lines[] = {line};
    tunnel_chain_t chain = {.workers_count = 1, .contains_packet_node = true, .finalized = true, .packet_lines = lines};
    tunnel_t      *prev = recordingTunnel(), *next = recordingTunnel();
    tunnel_t      *before  = createOverride("192.0.2.1", "192.0.2.2", "192.0.2.2", "192.0.2.1");
    tunnel_t      *between = createOverride("198.51.100.1", "198.51.100.2", "198.51.100.2", "198.51.100.1");
    tunnel_t      *after   = createOverride("203.0.113.1", "203.0.113.2", "203.0.113.2", "203.0.113.1");
    for (unsigned p = 0; p < 2; ++p)
    {
        const uint8_t protocol = p == 0 ? 6 : 17;
        char          settings[64];
        snprintf(settings, sizeof(settings), "{\"payload-protocol\":%u}", protocol);
        tunnel_t *c = createWithSettings(client, settings), *s = createWithSettings(server, settings);
        require(c != NULL && s != NULL, "composition constructors");
        c->chain = s->chain = &chain;
        tunnelBind(prev, before);
        tunnelBind(before, c);
        tunnelBind(c, between);
        tunnelBind(between, s);
        tunnelBind(s, after);
        tunnelBind(after, next);
        for (unsigned direction = 0; direction < 2; ++direction)
        {
            uint8_t packet[80], expected[80];
            makeNative(packet, protocol);
            memoryCopy(expected, packet, sizeof(expected));
            PUT_BE32(expected + 12, direction == 0 ? 0xcb007101U : 0xc0000202U);
            PUT_BE32(expected + 16, direction == 0 ? 0xcb007102U : 0xc0000201U);
            require(calcFullPacketChecksum(expected, sizeof(expected)), "composition expected native checksum");
            sbuf_t        *buf      = pooledPacket(line, packet, sizeof(packet));
            const uint32_t recycled = twfRecycleCount();
            resetForwarding();
            if (direction == 0)
                before->fnPayloadU(before, line, buf);
            else
                after->fnPayloadD(after, line, buf);
            requireForwarded(direction == 0, line, buf);
            require(twfRecycleCount() == recycled, "composition recycled a successful buffer");
            require(sbufGetLength(buf) == sizeof(expected) &&
                        memoryEqual(sbufGetRawPtr(buf), expected, sizeof(expected)),
                    "IpOverrider before encode, during carrier or after decode damaged native checksums/bytes");
            require(! sbufGetRecalculateChecksum(buf), "composition left checksum repair pending");
            lineReuseBuffer(line, buf);
        }
        destroyTunnel(c);
        destroyTunnel(s);
    }
    before->onDestroy(before, wwLifecycleStartupRollback());
    between->onDestroy(between, wwLifecycleStartupRollback());
    after->onDestroy(after, wwLifecycleStartupRollback());
    twfLineDestroy(line);
    tunnelDestroy(prev);
    tunnelDestroy(next);
    twfWorkerEnvTeardown(&env);
}
#endif
#endif

int main(void)
{
    testCaseSet("fake_tcp_header_nodes_test");
    initWLibc();
    checkSumInit();

    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create network logger");
    loggerSetHandler(logger, captureLog);
    setNetworkLogger(logger);

    const node_case_t cases[] = {
        {"FakeTcpHeaderClient",
         nodeFakeTcpHeaderClientGet,
         faketcpheaderclientUpStreamPayload,
         faketcpheaderclientDownStreamPayload,
         clientWire},
        {"FakeTcpHeaderServer",
         nodeFakeTcpHeaderServerGet,
         faketcpheaderserverUpStreamPayload,
         faketcpheaderserverDownStreamPayload,
         serverWire},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testMetadata(&cases[i]);
        testDefaults(&cases[i]);
        testConfigured(&cases[i]);
        testRejections(&cases[i]);
#if FAKE_TCP_HEADER_CALLBACK_FIXTURE
        testPayloadCallbacks(&cases[i]);
#endif
    }

#if FAKE_TCP_HEADER_IPOVERRIDER_FIXTURE
    require(globalstateInitializeSecureRandom(), "OS random source unavailable");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();
    testIpOverriderComposition(&cases[0], &cases[1]);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
#endif
    networkloggerDestroy();
    puts("FakeTcpHeaderClient/FakeTcpHeaderServer node tests passed");
    return 0;
}
