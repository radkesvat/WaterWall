/*
 * Covers: FakeTcpHeaderClient and FakeTcpHeaderServer node metadata and constructors.
 * Contract: both nodes are Layer-3 packet transforms with 80 bytes of left padding; each constructor installs its
 * own two payload callbacks and the default destroy, accepts omitted or empty settings as the codec defaults, and
 * refuses removed keys and out-of-range values with a NULL result and a "JSON Error: <Node>->settings-><key>" log.
 * Cases: testMetadata, testDefaults, testConfigured, testRejections (each for both nodes)
 * Setup: a capturing network logger; tunnels are created without a chain and destroyed through onDestroy.
 * Limits: payload transforms are covered by waterwall.fake_tcp_header_wire_unit; no line or chain is involved.
 * CTest: waterwall.fake_tcp_header_nodes_unit
 */
#include "FakeTcpHeaderClient/interface.h"
#include "FakeTcpHeaderClient/structure.h"
#include "FakeTcpHeaderServer/interface.h"
#include "FakeTcpHeaderServer/structure.h"

#include "test_assert.h"

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
    require(node.required_padding_left == kFakeTcpHeaderWireRequiredPaddingLeft && node.required_padding_left == 80,
            "node does not advertise the 80-byte carrier padding");
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
    const char *const fixtures[] = {NULL, "{}"};
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
        destroyTunnel(t);
    }
}

static void testConfigured(const node_case_t *c)
{
    tunnel_t *t = createWithSettings(c,
                                     "{\"server-port\":443,\"client-port\":50000,\"client-port-count\":1024,"
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
    static const char *const removed[] = {
        "role", "protocol-number", "flags", "mtu", "local-ipv4", "peer-ipv4", "local-port", "peer-port"};
    for (size_t i = 0; i < ARRAY_SIZE(removed); ++i)
    {
        char json[96];
        snprintf(json, sizeof(json), "{\"%s\":1}", removed[i]);
        requireRejected(c, json, removed[i]);
    }

    requireRejected(c, "{\"client-port-count\":1025}", "client-port-count");
    requireRejected(c, "{\"server-port\":0}", "server-port");
    requireRejected(c, "{\"window\":65536}", "window");
    requireRejected(c, "{\"server-port\":40001}", "server-port");
    requireRejected(c, "{\"options\":\"010101\"}", "options");

    char expected[128];
    snprintf(expected, sizeof(expected), "JSON Error: %s->settings : expected an object", c->type_name);
    tunnel_t *t = createWithSettings(c, "[]");
    require(t == NULL, "constructor accepted a non-object settings value");
    require(strstr(log_capture, expected) != NULL, "non-object rejection did not name the node");
}

int main(void)
{
    testCaseSet("fake_tcp_header_nodes_test");
    initWLibc();

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
    }

    networkloggerDestroy();
    puts("FakeTcpHeaderClient/FakeTcpHeaderServer node tests passed");
    return 0;
}
