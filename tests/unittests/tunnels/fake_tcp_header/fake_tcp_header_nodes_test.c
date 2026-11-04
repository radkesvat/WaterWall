/*
 * Covers: FakeTcpHeaderClient and FakeTcpHeaderServer node metadata and constructors.
 * Contract: both nodes are Layer-3 packet transforms with 61 bytes of left padding, per-packet native
 * protocol tags and no line state. Client ports accept one integer or an inclusive range; omitted ports retain the
 * default range. Sequence counters default to independent random_port seeds and byte progression; numeric/random_node
 * seeds and fixed output are also supported. ACK accepts numeric/random_node/random_port/random_packet independently
 * of sequence settings; optional ACK progression adds one per successful encoded packet, wraps, and stays per port.
 * Packet processing preserves disabled ACK seeds and uses the configured storage layout.
 * Constructors report invalid settings by node/key.
 * All four actual payload callbacks forward the exact sbuf once or recycle it once, preserving the packet line.
 * Cases: testMetadata, testDefaults, testConfigured, testRejections, testPayloadCallbacks (both nodes,
 * default/true/false); testIpOverriderComposition (when IpOverrider is available). Setup: capturing logger; existing
 * worker/pool/packet-chain fixture and buffer ownership ledger on Linux. Limits: socket delivery belongs to the
 * namespace integrations; independent wire oracle is in the codec unit. CTest: waterwall.fake_tcp_header_nodes_unit
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
    atomic_u32_t *(*values)(tunnel_t *t);
    size_t state_size;
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

static atomic_u32_t *clientValues(tunnel_t *t)
{
    return ((faketcpheaderclient_tstate_t *) tunnelGetState(t))->values;
}

static atomic_u32_t *serverValues(tunnel_t *t)
{
    return ((faketcpheaderserver_tstate_t *) tunnelGetState(t))->values;
}

static void requireFieldStorage(const node_case_t *c, tunnel_t *t)
{
    const faketcpheader_wire_config_t *wire = c->wire(t);
    uint32_t                           expected_size;
    require(tunnelTryAlignStateSize(c->state_size + faketcpheaderWireStateCount(wire) * sizeof(atomic_u32_t),
                                    &expected_size),
            "field storage size does not align");
    require(t->tstate_size == expected_size, "node did not size field storage for the selected range/modes");
    if (faketcpheaderWireNeedsSequences(wire) && wire->sequence_mode != kFakeTcpHeaderFieldRandomPort)
        for (uint16_t i = 0; i < wire->client_port_count; ++i)
            require(atomicLoadU32Relaxed(&c->values(t)[i]) == wire->sequence, "node did not seed every port counter");
    if (faketcpheaderWireNeedsAcknowledgments(wire) && wire->acknowledgment_mode != kFakeTcpHeaderFieldRandomPort)
    {
        const unsigned offset = faketcpheaderWireNeedsSequences(wire) ? wire->client_port_count : 0;
        for (uint16_t i = 0; i < wire->client_port_count; ++i)
            require(atomicLoadU32Relaxed(&c->values(t)[offset + i]) == wire->acknowledgment,
                    "node did not seed every ACK counter");
    }
    if (faketcpheaderWireNeedsFlagPositions(wire))
    {
        const unsigned offset = wire->client_port_count *
                                (faketcpheaderWireNeedsSequences(wire) + faketcpheaderWireNeedsAcknowledgments(wire));
        for (uint16_t i = 0; i < wire->client_port_count; ++i)
            require(atomicLoadU32Relaxed(&c->values(t)[offset + i]) == 0,
                    "node did not start every flags array at zero");
    }
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
    require(node.required_padding_left == kFakeTcpHeaderWireRequiredPaddingLeft && node.required_padding_left == 61,
            "node does not advertise the 61-byte framing padding");
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
    require(wire->sequence_mode == kFakeTcpHeaderFieldRandomPort &&
                wire->acknowledgment_mode == kFakeTcpHeaderFieldNumeric && wire->acknowledgment == 0 &&
                wire->window == 65535 && wire->urgent_pointer == 0,
            "default TCP header template changed");
    require(wire->options_length == 0, "default TCP options are not empty");
    require(wire->increment_sequence, "sequence progression is not enabled by default");
    require(! wire->increment_acknowledgment, "ACK progression is not disabled by default");
    require(! wire->encryption_enabled, "omitting password enabled encryption");
    require(wire->flags_count == 1 && wire->flags[0] == 0x18, "default flags are not one ACK|PSH template");
}

static void testDefaults(const node_case_t *c)
{
    const char *const fixtures[] = {NULL, "{}", "{\"window\":65535}"};
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
        requireFieldStorage(c, t);
        destroyTunnel(t);
    }
}

static void testConfigured(const node_case_t *c)
{
    tunnel_t *t = createWithSettings(c,
                                     "{\"server-port\":443,\"client-port-range\":[64512,65535],"
                                     "\"sequence\":4294967295,\"acknowledgment\":7,\"window\":0,"
                                     "\"urgent-pointer\":65535,\"options\":\"0101080a\"}");
    require(t != NULL, "constructor refused a valid configuration");
    const faketcpheader_wire_config_t *wire = c->wire(t);
    require(wire->server_port == 443 && wire->client_port == 64512 && wire->client_port_count == 1024,
            "configured carrier ports were not loaded");
    require(wire->sequence_mode == kFakeTcpHeaderFieldNumeric && wire->sequence == UINT32_MAX &&
                wire->acknowledgment_mode == kFakeTcpHeaderFieldNumeric && wire->acknowledgment == 7 &&
                wire->window == 0 && wire->urgent_pointer == UINT16_MAX,
            "configured TCP header template was not loaded");
    require(wire->options_length == 4 && wire->options[0] == 0x01 && wire->options[2] == 0x08 &&
                wire->options[3] == 0x0a,
            "configured TCP options were not loaded");
    requireFieldStorage(c, t);
    destroyTunnel(t);

    const struct
    {
        const char *json;
        uint16_t    first;
        uint16_t    count;
    } ports[] = {{"{\"client-port\":40001}", 40001, 1},
                 {"{\"client-port\":1}", 1, 1},
                 {"{\"client-port\":65535}", 65535, 1},
                 {"{\"client-port-range\":[40001,40016]}", 40001, 16},
                 {"{\"client-port-range\":[1,1]}", 1, 1},
                 {"{\"client-port-range\":[65535,65535]}", 65535, 1},
                 {"{\"server-port\":40002,\"client-port\":40001}", 40001, 1}};
    for (size_t i = 0; i < ARRAY_SIZE(ports); ++i)
    {
        t = createWithSettings(c, ports[i].json);
        require(t != NULL, "constructor refused a valid client port selection");
        require(log_capture_len == 0, "constructor logged while accepting client ports");
        wire = c->wire(t);
        require(wire->client_port == ports[i].first && wire->client_port_count == ports[i].count,
                "constructor loaded the wrong client port selection");
        requireFieldStorage(c, t);
        destroyTunnel(t);
    }

    for (unsigned enabled = 0; enabled < 2; ++enabled)
    {
        char json[160];
        snprintf(json,
                 sizeof(json),
                 "{\"increment-sequence\":%s,\"sequence\":123456,\"client-port-range\":[64512,65535]}",
                 enabled ? "true" : "false");
        t = createWithSettings(c, json);
        require(t != NULL, "constructor refused an explicit sequence mode");
        require(c->wire(t)->increment_sequence == (enabled != 0), "constructor ignored sequence mode");
        requireFieldStorage(c, t);
        destroyTunnel(t);
    }
    const struct
    {
        const char                *name;
        faketcpheader_field_mode_t mode;
    } modes[] = {{"random_node", kFakeTcpHeaderFieldRandomNode}, {"random_port", kFakeTcpHeaderFieldRandomPort}};
    for (size_t i = 0; i < ARRAY_SIZE(modes); ++i)
        for (unsigned enabled = 0; enabled < 2; ++enabled)
        {
            char json[160];
            snprintf(json,
                     sizeof(json),
                     "{\"sequence\":\"%s\",\"increment-sequence\":%s,\"client-port-range\":[64512,65535]}",
                     modes[i].name,
                     enabled ? "true" : "false");
            t = createWithSettings(c, json);
            require(t != NULL, "constructor refused a random sequence mode");
            require(c->wire(t)->sequence_mode == modes[i].mode && c->wire(t)->increment_sequence == (enabled != 0),
                    "constructor ignored the selected random sequence mode");
            requireFieldStorage(c, t);
            destroyTunnel(t);
        }

    const struct
    {
        const char                *json_value;
        faketcpheader_field_mode_t mode;
        uint32_t                   fixed_value;
    } ack_modes[]                       = {{"0", kFakeTcpHeaderFieldNumeric, 0},
                                           {"4294967295", kFakeTcpHeaderFieldNumeric, UINT32_MAX},
                                           {"\"random_node\"", kFakeTcpHeaderFieldRandomNode, 0},
                                           {"\"random_port\"", kFakeTcpHeaderFieldRandomPort, 0},
                                           {"\"random_packet\"", kFakeTcpHeaderFieldRandomPacket, 0}};
    const char *const sequence_values[] = {"17", "\"random_node\"", "\"random_port\""};
    for (size_t a = 0; a < ARRAY_SIZE(ack_modes); ++a)
        for (size_t q = 0; q < ARRAY_SIZE(sequence_values); ++q)
            for (unsigned enabled = 0; enabled < 2; ++enabled)
                for (unsigned ack_enabled = 0;
                     ack_enabled < (ack_modes[a].mode == kFakeTcpHeaderFieldRandomPacket ? 1U : 2U);
                     ++ack_enabled)
                {
                    char json[192];
                    snprintf(json,
                             sizeof(json),
                             "{\"acknowledgment\":%s,\"sequence\":%s,\"increment-sequence\":%s,\"increment-"
                             "acknowledgment\":%s,"
                             "\"client-port-range\":[64512,65535]}",
                             ack_modes[a].json_value,
                             sequence_values[q],
                             enabled ? "true" : "false",
                             ack_enabled ? "true" : "false");
                    t = createWithSettings(c, json);
                    require(t != NULL, "constructor refused an acknowledgment mode");
                    wire = c->wire(t);
                    require(wire->acknowledgment_mode == ack_modes[a].mode &&
                                wire->increment_sequence == (enabled != 0) &&
                                wire->increment_acknowledgment == (ack_enabled != 0),
                            "constructor changed ACK mode or sequence increments");
                    if (ack_modes[a].mode == kFakeTcpHeaderFieldNumeric)
                        require(wire->acknowledgment == ack_modes[a].fixed_value, "constructor lost numeric ACK");
                    require(log_capture_len == 0, "constructor logged while accepting an ACK mode");
                    requireFieldStorage(c, t);
                    destroyTunnel(t);
                }
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

static void testFlagSettings(const node_case_t *c)
{
    const struct
    {
        const char *json;
        uint8_t     count;
        uint8_t     flags[3];
    } cases[] = {
        {"[{}]", 1, {0}},
        {"[{\"syn\":true},{\"ack\":true,\"psh\":true}]", 2, {2, 0x18}},
        {"[{\"fin\":true,\"syn\":true,\"rst\":true,\"psh\":true,\"ack\":true,\"urg\":true,\"ece\":true,\"cwr\":true}]",
         1,
         {255}}};
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
        for (unsigned counters = 0; counters < 4; ++counters)
        {
            char json[320];
            snprintf(json,
                     sizeof(json),
                     "{\"sequence\":0,\"increment-sequence\":%s,\"increment-acknowledgment\":%s,"
                     "\"client-port-range\":[64512,65535],\"flags\":%s}",
                     counters & 1U ? "true" : "false",
                     counters & 2U ? "true" : "false",
                     cases[i].json);
            tunnel_t *t = createWithSettings(c, json);
            require(t != NULL, "constructor refused flags settings");
            const faketcpheader_wire_config_t *wire = c->wire(t);
            require(wire->flags_count == cases[i].count && memoryEqual(wire->flags, cases[i].flags, cases[i].count),
                    "constructor changed flag masks or order");
            requireFieldStorage(c, t);
            destroyTunnel(t);
        }
    const char *const rejected[] = {"{\"flags\":24}",
                                    "{\"flags\":null}",
                                    "{\"flags\":[]}",
                                    "{\"flags\":{}}",
                                    "{\"flags\":[null]}",
                                    "{\"flags\":[24]}",
                                    "{\"flags\":[[]]}",
                                    "{\"flags\":[{\"syn\":1}]}",
                                    "{\"flags\":[{\"ack\":null}]}",
                                    "{\"flags\":[{\"syn\":\"true\"}]}",
                                    "{\"flags\":[{\"SYN\":true}]}",
                                    "{\"flags\":[{\"ns\":true}]}",
                                    "{\"flags\":[{\"syn\":true,\"syn\":false}]}",
                                    "{\"flags\":[{}],\"flags\":[{}]}",
                                    "{\"flags\":[{\"syn\\u0000extra\":true}]}"};
    for (size_t i = 0; i < ARRAY_SIZE(rejected); ++i)
        requireRejected(c, rejected[i], "flags");
}

static void testRejections(const node_case_t *c)
{
    const char *const bad_modes[] = {"null", "0", "1", "\"true\"", "[]", "{}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad_modes); ++i)
    {
        char json[80];
        snprintf(json, sizeof(json), "{\"increment-sequence\":%s}", bad_modes[i]);
        requireRejected(c, json, "increment-sequence");
        snprintf(json, sizeof(json), "{\"increment-acknowledgment\":%s}", bad_modes[i]);
        requireRejected(c, json, "increment-acknowledgment");
    }
    requireRejected(
        c, "{\"increment-acknowledgment\":true,\"acknowledgment\":\"random_packet\"}", "increment-acknowledgment");
    const char *const bad_sequences[] = {"null",
                                         "true",
                                         "false",
                                         "[]",
                                         "{}",
                                         "-1",
                                         "4294967296",
                                         "1.0",
                                         "1e0",
                                         "1.5",
                                         "\"123\"",
                                         "\"random_fixed\"",
                                         "\"random_con\"",
                                         "\"random_always\"",
                                         "\"random_packet\"",
                                         "\"RANDOM_PORT\"",
                                         "\" random_node\"",
                                         "\"random_port \"",
                                         "\"\"",
                                         "\"random_node\\u0000extra\"",
                                         "\"random_port\\u0000extra\""};
    for (size_t i = 0; i < ARRAY_SIZE(bad_sequences); ++i)
    {
        char json[128];
        snprintf(json, sizeof(json), "{\"sequence\":%s}", bad_sequences[i]);
        requireRejected(c, json, "sequence");
    }
    const char *const bad_acknowledgments[] = {"null",
                                               "true",
                                               "false",
                                               "[]",
                                               "{}",
                                               "-1",
                                               "4294967296",
                                               "1.0",
                                               "1e0",
                                               "1.5",
                                               "\"123\"",
                                               "\"random_fixed\"",
                                               "\"random_con\"",
                                               "\"random_always\"",
                                               "\"RANDOM_PACKET\"",
                                               "\" random_node\"",
                                               "\"random_port \"",
                                               "\"\"",
                                               "\"random_node\\u0000extra\"",
                                               "\"random_port\\u0000extra\"",
                                               "\"random_packet\\u0000extra\""};
    for (size_t i = 0; i < ARRAY_SIZE(bad_acknowledgments); ++i)
    {
        char json[128];
        snprintf(json, sizeof(json), "{\"acknowledgment\":%s}", bad_acknowledgments[i]);
        requireRejected(c, json, "acknowledgment");
    }
    const char *const bad_protocol[] = {"{\"payload-protocol\":6}",
                                        "{\"payload-protocol\":17}",
                                        "{\"payload-protocol\":null}",
                                        "{\"payload-protocol\":6.5}",
                                        "{\"payload-protocol\":6.0}",
                                        "{\"payload-protocol\":6e0}",
                                        "{\"payload-protocol\":7}",
                                        "{\"payload-protocol\":16}",
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
        "role", "protocol-number", "mtu", "local-ipv4", "peer-ipv4", "local-port", "peer-port", "client-port-count"};
    for (size_t i = 0; i < ARRAY_SIZE(removed); ++i)
    {
        char json[96];
        snprintf(json, sizeof(json), "{\"%s\":1}", removed[i]);
        requireRejected(c, json, removed[i]);
    }

    const char *const bad_client_ports[] = {"{\"client-port\":0}",
                                            "{\"client-port\":65536}",
                                            "{\"client-port\":40001.5}",
                                            "{\"client-port\":40001.0}",
                                            "{\"client-port\":40001e0}",
                                            "{\"client-port\":null}",
                                            "{\"client-port\":\"40001\"}",
                                            "{\"client-port\":true}",
                                            "{\"client-port\":[40001,40016]}"};
    for (size_t i = 0; i < ARRAY_SIZE(bad_client_ports); ++i)
        requireRejected(c, bad_client_ports[i], "client-port");

    const char *const bad_client_ranges[] = {
        "{\"client-port-range\":null}",
        "{\"client-port-range\":40001}",
        "{\"client-port-range\":\"40001-40016\"}",
        "{\"client-port-range\":[]}",
        "{\"client-port-range\":[40001]}",
        "{\"client-port-range\":[40001,40002,40003]}",
        "{\"client-port-range\":[null,40016]}",
        "{\"client-port-range\":[40001,true]}",
        "{\"client-port-range\":[40001.5,40016]}",
        "{\"client-port-range\":[40001,40016.0]}",
        "{\"client-port-range\":[40001e0,40016]}",
        "{\"client-port-range\":[0,16]}",
        "{\"client-port-range\":[65530,65536]}",
        "{\"client-port-range\":[40016,40001]}",
        "{\"client-port-range\":[64511,65535]}",
        "{\"client-port\":40001,\"client-port-range\":[40001,40016]}",
        "{\"client-port\":null,\"client-port-range\":[40001,40016]}",
        "{\"client-port\":40001,\"client-port-range\":null}",
        "{\"client-port\":null,\"client-port-range\":null}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(bad_client_ranges); ++i)
        requireRejected(c, bad_client_ranges[i], "client-port-range");

    requireRejected(c, "{\"client-port-count\":16}", "client-port-count");
    requireRejected(c, "{\"client-port-count\":null}", "client-port-count");
    requireRejected(c, "{\"server-port\":0}", "server-port");
    requireRejected(c, "{\"window\":65536}", "window");
    requireRejected(c, "{\"server-port\":40001}", "server-port");
    requireRejected(c, "{\"server-port\":40001,\"client-port\":40001}", "server-port");
    requireRejected(c, "{\"server-port\":40001,\"client-port-range\":[40001,40016]}", "server-port");
    requireRejected(c, "{\"server-port\":40008,\"client-port-range\":[40001,40016]}", "server-port");
    requireRejected(c, "{\"server-port\":40016,\"client-port-range\":[40001,40016]}", "server-port");
    requireRejected(c, "{\"options\":\"010101\"}", "options");

    char expected[128];
    snprintf(expected, sizeof(expected), "JSON Error: %s->settings : expected an object", c->type_name);
    tunnel_t *t = createWithSettings(c, "[]");
    require(t == NULL, "constructor accepted a non-object settings value");
    require(strstr(log_capture, expected) != NULL, "non-object rejection did not name the node");
}

#if FAKE_TCP_HEADER_CALLBACK_FIXTURE
/* Exercise real private-child construction and topology without linking either Encryption module. */
static bool        encryption_module_available, encryption_child_refused;
static const char *encryption_expected_type;
static unsigned    encryption_lookups, encryption_creates, encryption_live, encryption_destroys;
static cJSON      *encryption_owned_settings;
static size_t      encryption_password_length;
static node_t     *encryption_configured_next;

node_t  __wrap_nodelibraryLoadByTypeName(const char *name);
node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash);
void    __real_cJSON_Delete(cJSON *item);
void    __wrap_cJSON_Delete(cJSON *item);

void __wrap_cJSON_Delete(cJSON *item)
{
    if (item != NULL && item == encryption_owned_settings)
    {
        const cJSON *password = cJSON_GetObjectItemCaseSensitive(item, "password");
        require(cJSON_IsString(password), "private child lost its password before cleanup");
        for (size_t i = 0; i < encryption_password_length; ++i)
            require(password->valuestring[i] == '\0', "private password was not wiped before deleting settings");
        encryption_owned_settings = NULL;
    }
    __real_cJSON_Delete(item);
}

static void encryptionChildDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    require(context->scope == kWwLifecycleOwnedChildStop, "private helper destruction lost child ownership");
    require(encryption_live == 1, "private helper destroyed more than once");
    --encryption_live;
    ++encryption_destroys;
    require(tunnelGetNode(t)->node_settings_json == encryption_owned_settings,
            "private settings were freed before helper destruction");
    tunnelDefaultOnDestroy(t, context);
}

static tunnel_t *encryptionChildCreate(node_t *node)
{
    ++encryption_creates;
    require(stringCompare(node->type, encryption_expected_type) == 0, "wrong Encryption orientation");
    const cJSON *settings  = node->node_settings_json;
    const cJSON *algorithm = cJSON_GetObjectItemCaseSensitive(settings, "algorithm");
    const cJSON *password  = cJSON_GetObjectItemCaseSensitive(settings, "password");
    require(cJSON_GetArraySize(settings) == 3 &&
                cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(settings, "packet-mode")) && cJSON_IsString(algorithm) &&
                stringCompare(algorithm->valuestring, "xchacha20-poly1305") == 0 && cJSON_IsString(password) &&
                stringCompare(password->valuestring, "private test secret") == 0,
            "private helper did not receive exact packet encryption settings");
    encryption_owned_settings  = node->node_settings_json;
    encryption_password_length = stringLength(password->valuestring);
    if (encryption_child_refused)
        return NULL;
    tunnel_t *t = tunnelCreate(node, 0, 0);
    require(t != NULL, "mock Encryption constructor failed");
    t->onDestroy = encryptionChildDestroy;
    ++encryption_live;
    return t;
}

node_t __wrap_nodelibraryLoadByTypeName(const char *name)
{
    ++encryption_lookups;
    require(encryption_expected_type != NULL && stringCompare(name, encryption_expected_type) == 0,
            "unexpected registry lookup from a FakeTcpHeader node");
    if (! encryption_module_available)
        return (node_t) {0};
    return (node_t) {.type                  = (char *) encryption_expected_type,
                     .hash_type             = calcHashBytes(name, stringLength(name)),
                     .createHandle          = encryptionChildCreate,
                     .required_padding_left = 24,
                     .layer_group           = kNodeLayer3,
                     .layer_group_prev_node = kNodeLayer3,
                     .layer_group_next_node = kNodeLayer3,
                     .can_have_prev         = true,
                     .can_have_next         = true};
}

node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash)
{
    discard config;
    require(encryption_configured_next != NULL && hash == encryption_configured_next->hash_name,
            "private helper lost the configured next link");
    return encryption_configured_next;
}

static faketcpheader_encryption_t *nodeEncryption(const node_case_t *c, tunnel_t *t)
{
    return c->get == nodeFakeTcpHeaderClientGet ? &((faketcpheaderclient_tstate_t *) tunnelGetState(t))->encryption
                                                : &((faketcpheaderserver_tstate_t *) tunnelGetState(t))->encryption;
}

static void testEncryptionHelper(const node_case_t *c)
{
    const bool client           = c->get == nodeFakeTcpHeaderClientGet;
    encryption_expected_type    = client ? "EncryptionClient" : "EncryptionServer";
    encryption_lookups          = 0;
    encryption_creates          = 0;
    encryption_destroys         = 0;
    encryption_module_available = false;
    tunnel_t *t                 = createWithSettings(c, "{}");
    require(t != NULL && encryption_lookups == 0, "unencrypted node requires the Encryption module");
    destroyTunnel(t);

    t = createWithSettings(c, "{\"password\":\"private test secret\"}");
    require(t == NULL && encryption_lookups == 1 && encryption_creates == 0 && encryption_live == 0,
            "missing Encryption module allowed plaintext or attempted a child constructor");
    require(strstr(log_capture, c->type_name) != NULL && strstr(log_capture, encryption_expected_type) != NULL &&
                strstr(log_capture, "unavailable") != NULL && strstr(log_capture, "private test secret") == NULL,
            "missing module diagnostic is unclear or exposes the password");

    encryption_module_available = true;
    encryption_child_refused    = true;
    t                           = createWithSettings(c, "{\"password\":\"private test secret\"}");
    require(t == NULL && encryption_creates == 1 && encryption_live == 0 && encryption_owned_settings == NULL,
            "child construction refusal leaked settings or fell back to plaintext");
    encryption_child_refused = false;

    for (unsigned int manual = 0; manual < 2; ++manual)
    {
        node_t owner             = c->get();
        owner.name               = (char *) "fake";
        owner.next               = (char *) "next";
        owner.hash_next          = 17;
        owner.node_settings_json = cJSON_Parse("{\"password\":\"private test secret\"}");
        require(owner.node_settings_json != NULL, "encrypted owner settings fixture");
        t = owner.createHandle(&owner);
        require(t != NULL && c->wire(t)->encryption_enabled, "password did not create an encrypted parent");
        faketcpheader_encryption_t *child = nodeEncryption(c, t);
        require(child->tunnel != NULL && child->node.instance == child->tunnel &&
                    child->settings != owner.node_settings_json && child->node.node_settings_json == child->settings &&
                    stringCompare(child->node.name, "fake.encryption") == 0,
                "private child metadata or settings ownership is wrong");
        require(client ? child->node.hash_next == owner.hash_next && stringCompare(child->node.next, owner.next) == 0
                       : child->node.hash_next == 0 && child->node.next == NULL,
                "private child copied the wrong traversal link");
        cJSON_Delete(owner.node_settings_json);
        owner.node_settings_json = NULL;
        require(stringCompare(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(child->settings, "password")),
                              "private test secret") == 0,
                "private settings borrowed the parent's password");

        node_t    previous_node = {.type = (char *) (manual && ! client ? "EncryptionServer" : "Previous")};
        node_t    next_node     = {.type = (char *) (manual && client ? "EncryptionClient" : "Next"), .hash_name = 17};
        tunnel_t *previous      = tunnelCreate(&previous_node, 0, 0);
        tunnel_t *next          = tunnelCreate(&next_node, 0, 0);
        require(previous != NULL && next != NULL, "encryption chain neighbor construction");
        next_node.instance           = next;
        encryption_configured_next   = &next_node;
        ww_startup_context_t startup = {0};
        wwStartupContextBegin(&startup);
        if (! client && manual == 0)
        {
            tunnel_chain_t *deferred = tunnelchainCreate(1);
            t->onChain(t, deferred); /* The server releases an empty chain until its predecessor is bound. */
            require(! startupFailurePending() && t->chain == NULL && child->tunnel->chain == NULL && t->prev == NULL &&
                        child->tunnel->prev == NULL,
                    "server helper failed to defer until its predecessor exists");
        }
        tunnelBind(previous, t);
        tunnel_chain_t *chain = tunnelchainCreate(1);
        t->onChain(t, chain);
        const bool succeeded = wwStartupSucceeded(wwStartupContextEnd(&startup));
        if (manual)
        {
            require(! succeeded && chain->tunnels.len == 0 && t->chain == NULL && child->tunnel->chain == NULL,
                    "password accepted an adjacent manual Encryption node");
            require(strstr(log_capture, "adjacent Encryption") != NULL, "duplicate encryption diagnostic missing");
        }
        else
        {
            require(succeeded && chain->tunnels.len == 3 && chain->sum_padding_left == 85,
                    "private helper is absent from chain indexing/padding");
            require(client ? previous->next == t && t->next == child->tunnel && child->tunnel->prev == t &&
                                 child->tunnel->next == next && next->prev == child->tunnel
                           : previous->next == child->tunnel && child->tunnel->prev == previous &&
                                 child->tunnel->next == t && t->prev == child->tunnel && t->next == next,
                    "encryption helper is on the wrong side or broke neighbor links");
            require(tunnelGetBranchEntry(previous, t) == (client ? t : child->tunnel),
                    "encryption helper changed the callable branch entry");
        }
        destroyTunnel(t);
        require(encryption_live == 0 && encryption_owned_settings == NULL,
                "parent destruction leaked its child or settings");
        tunnelDestroy(previous);
        tunnelDestroy(next);
        tunnelchainDestroy(chain);
        memoryFree(owner.type);
        encryption_configured_next = NULL;
    }
    require(encryption_destroys == 2, "private helper destruction was missing or repeated");
    encryption_module_available = false;
    encryption_expected_type    = NULL;
}

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
    else if (protocol == 17)
        PUT_BE16(packet + 24, 60);
    else if (protocol == 1)
    {
        packet[20] = 8; /* ICMP echo request; addresses are outside its checksum. */
        packet[21] = 0;
    }
    for (unsigned i = 40; i < 80; ++i)
        packet[i] = (uint8_t) i;
    require(calcFullPacketChecksum(packet, 80), "native fixture checksum");
}
static sbuf_t *pooledPacket(line_t *line, const uint8_t *packet, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    require(sbufGetLeftCapacity(buf) >= 61, "fixture did not advertise framing headroom");
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
static void requireValuesUnchanged(const node_case_t *c, tunnel_t *t, const uint32_t *expected_sequences,
                                   const uint32_t *expected_acknowledgments, const uint32_t *expected_positions)
{
    const faketcpheader_wire_config_t *wire          = c->wire(t);
    const bool                         has_sequences = faketcpheaderWireNeedsSequences(wire);
    if (has_sequences)
        for (uint16_t i = 0; i < wire->client_port_count; ++i)
            require(atomicLoadU32Relaxed(&c->values(t)[i]) == expected_sequences[i],
                    "callback changed an outgoing counter unexpectedly");
    if (faketcpheaderWireNeedsAcknowledgments(wire))
        for (uint16_t i = 0; i < wire->client_port_count; ++i)
            require(atomicLoadU32Relaxed(&c->values(t)[(has_sequences ? wire->client_port_count : 0) + i]) ==
                        expected_acknowledgments[i],
                    "callback changed a per-port ACK");
    if (faketcpheaderWireNeedsFlagPositions(wire))
    {
        const unsigned offset = wire->client_port_count * (has_sequences + faketcpheaderWireNeedsAcknowledgments(wire));
        for (uint16_t i = 0; i < wire->client_port_count; ++i)
            require(atomicLoadU32Relaxed(&c->values(t)[offset + i]) == expected_positions[i],
                    "callback advanced flag position on refusal/decode or changed another port");
    }
}

static void testPayloadCallbacks(const node_case_t *c, const char *settings)
{
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 8192, 61);
    line_t        *line    = twfLineCreate(0);
    line_t        *lines[] = {line};
    tunnel_chain_t chain = {.workers_count = 1, .contains_packet_node = true, .finalized = true, .packet_lines = lines};
    tunnel_t      *prev = recordingTunnel(), *next = recordingTunnel();
    uint8_t        packet[80];
    tunnel_t      *t = createWithSettings(c, settings);
    require(t != NULL, "callback fixture constructor");
    requireFieldStorage(c, t);
    const faketcpheader_wire_config_t *wire      = c->wire(t);
    faketcpheader_wire_config_t        peer_wire = *wire;
    atomic_u32_t                       peer_values[3 * kFakeTcpHeaderWireMaxClientPortCount];
    atomic_u32_t                      *peer_state = faketcpheaderWireStateCount(&peer_wire) != 0 ? peer_values : NULL;
    faketcpheaderWireInitState(&peer_wire, peer_state);
    tunnel_t *idle = createWithSettings(c, settings);
    require(idle != NULL, "independent node constructor");
    const faketcpheader_wire_config_t *idle_wire = c->wire(idle);
    const uint32_t                     idle_seed = idle_wire->sequence;
    const uint32_t                     idle_ack  = idle_wire->acknowledgment;
    uint32_t next_sequences[kFakeTcpHeaderWireMaxClientPortCount], idle_sequences[kFakeTcpHeaderWireMaxClientPortCount];
    uint32_t acknowledgments[kFakeTcpHeaderWireMaxClientPortCount],
        idle_acknowledgments[kFakeTcpHeaderWireMaxClientPortCount];
    uint32_t       positions[kFakeTcpHeaderWireMaxClientPortCount]      = {0};
    const uint32_t idle_positions[kFakeTcpHeaderWireMaxClientPortCount] = {0};
    const unsigned ack_offset      = faketcpheaderWireNeedsSequences(wire) ? wire->client_port_count : 0;
    const unsigned idle_ack_offset = faketcpheaderWireNeedsSequences(idle_wire) ? idle_wire->client_port_count : 0;
    for (uint16_t i = 0; i < wire->client_port_count; ++i)
    {
        next_sequences[i] =
            faketcpheaderWireNeedsSequences(wire) ? atomicLoadU32Relaxed(&c->values(t)[i]) : wire->sequence;
        idle_sequences[i]       = faketcpheaderWireNeedsSequences(idle_wire) ? atomicLoadU32Relaxed(&c->values(idle)[i])
                                                                             : idle_wire->sequence;
        acknowledgments[i]      = faketcpheaderWireNeedsAcknowledgments(wire)
                                      ? atomicLoadU32Relaxed(&c->values(t)[ack_offset + i])
                                      : wire->acknowledgment;
        idle_acknowledgments[i] = faketcpheaderWireNeedsAcknowledgments(idle_wire)
                                      ? atomicLoadU32Relaxed(&c->values(idle)[idle_ack_offset + i])
                                      : idle_wire->acknowledgment;
    }
    const uint8_t  protocols[] = {6, 17, 1, 253, 17, 6, 253, 1};
    for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
    {
        const uint8_t protocol = protocols[p];
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
            const uint16_t                  index     = faketcpheaderWirePortIndex(wire, packet, sizeof(packet));
            sbuf_t                         *buf       = pooledPacket(line, packet, sizeof(packet));
            if (! encoding)
                require(faketcpheaderWireEncode(&peer_wire,
                                                peer_state,
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
                const uint8_t *carrier = sbufGetRawPtr(buf);
                const uint8_t  flags   = wire->flags[positions[index]];
                require(carrier[33] == flags, "callback selected the wrong per-port flag template");
                require(GET_BE32(carrier + 24) == next_sequences[index], "callback used the wrong outgoing sequence");
                if (wire->acknowledgment_mode != kFakeTcpHeaderFieldRandomPacket)
                    require(GET_BE32(carrier + 28) == acknowledgments[index], "callback used the wrong ACK");
                if (wire->increment_sequence)
                    next_sequences[index] += 61U + ((flags & 2U) != 0) + ((flags & 1U) != 0);
                if (wire->increment_acknowledgment)
                    ++acknowledgments[index];
                if (positions[index] + 1U < wire->flags_count)
                    ++positions[index];
                require(sbufGetLength(buf) == 101, "callback did not insert fake TCP and one protocol byte");
                require(((const uint8_t *) sbufGetRawPtr(buf))[40] == protocol,
                        "callback did not tag the actual native protocol");
                require(faketcpheaderWireDecode(c->wire(t),
                                                side == kFakeTcpHeaderWireClient ? kFakeTcpHeaderWireServer
                                                                                 : kFakeTcpHeaderWireClient,
                                                buf) == kFakeTcpHeaderWireOk,
                        "encoded callback output invalid");
            }
            requireValuesUnchanged(c, t, next_sequences, acknowledgments, positions);
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
            requireValuesUnchanged(c, t, next_sequences, acknowledgments, positions);

            const uint16_t fragments[] = {0x2000, 0x2001, 0x0001};
            for (size_t f = 0; f < ARRAY_SIZE(fragments); ++f)
            {
                for (unsigned repair = 0; repair < 2; ++repair)
                {
                    buf = pooledPacket(line, packet, sizeof(packet));
                    if (! encoding)
                        require(faketcpheaderWireEncode(&peer_wire,
                                                        peer_state,
                                                        side == kFakeTcpHeaderWireClient ? kFakeTcpHeaderWireServer
                                                                                         : kFakeTcpHeaderWireClient,
                                                        buf) == kFakeTcpHeaderWireOk,
                                "fragmented carrier fixture");
                    PUT_BE16((uint8_t *) sbufGetMutablePtr(buf) + 6, fragments[f]);
                    sbufSetRecalculateChecksum(buf, repair != 0);
                    const uint32_t fragment_recycles = twfRecycleCount();
                    resetForwarding();
                    if (upstream)
                        t->fnPayloadU(t, line, buf);
                    else
                        t->fnPayloadD(t, line, buf);
                    require(forwarded_up == 0 && forwarded_down == 0 && unexpected_callbacks == 0,
                            "fragment emitted a neighbor callback");
                    require(twfRecycleCount() == fragment_recycles + 1, "fragment was not recycled exactly once");
                    twfRequireLastRecycle(buf, lineGetBufferPool(line), "fragment refusal used another pool");
                    require(lineIsAlive(line), "fragment refusal destroyed packet line");
                    requireValuesUnchanged(c, t, next_sequences, acknowledgments, positions);
                }
            }
        }
    }
    requireValuesUnchanged(c, idle, idle_sequences, idle_acknowledgments, idle_positions);
    require(idle_wire->sequence == idle_seed && idle_wire->acknowledgment == idle_ack,
            "another node changed a fixed field seed");
    destroyTunnel(idle);
    destroyTunnel(t);
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
    twfWorkerEnvSetup(&env, 8192, 122);
    line_t        *line    = twfLineCreate(0);
    line_t        *lines[] = {line};
    tunnel_chain_t chain = {.workers_count = 1, .contains_packet_node = true, .finalized = true, .packet_lines = lines};
    tunnel_t      *prev = recordingTunnel(), *next = recordingTunnel();
    tunnel_t      *before  = createOverride("192.0.2.1", "192.0.2.2", "192.0.2.2", "192.0.2.1");
    tunnel_t      *between = createOverride("198.51.100.1", "198.51.100.2", "198.51.100.2", "198.51.100.1");
    tunnel_t      *after   = createOverride("203.0.113.1", "203.0.113.2", "203.0.113.2", "203.0.113.1");
    tunnel_t      *c = createWithSettings(client, NULL), *s = createWithSettings(server, "{}");
    const uint8_t  protocols[] = {6, 17, 1, 253};
    for (size_t p = 0; p < ARRAY_SIZE(protocols); ++p)
    {
        const uint8_t protocol = protocols[p];
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
    }
    destroyTunnel(c);
    destroyTunnel(s);
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
    require(globalstateInitializeSecureRandom(), "OS random source unavailable");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();

    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create network logger");
    loggerSetHandler(logger, captureLog);
    setNetworkLogger(logger);

    const node_case_t cases[] = {
        {"FakeTcpHeaderClient",
         nodeFakeTcpHeaderClientGet,
         faketcpheaderclientUpStreamPayload,
         faketcpheaderclientDownStreamPayload,
         clientWire,
         clientValues,
         sizeof(faketcpheaderclient_tstate_t)},
        {"FakeTcpHeaderServer",
         nodeFakeTcpHeaderServerGet,
         faketcpheaderserverUpStreamPayload,
         faketcpheaderserverDownStreamPayload,
         serverWire,
         serverValues,
         sizeof(faketcpheaderserver_tstate_t)},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testMetadata(&cases[i]);
        testDefaults(&cases[i]);
        testConfigured(&cases[i]);
        testFlagSettings(&cases[i]);
        testRejections(&cases[i]);
#if FAKE_TCP_HEADER_CALLBACK_FIXTURE
        testEncryptionHelper(&cases[i]);
        testPayloadCallbacks(&cases[i], NULL);
        testPayloadCallbacks(&cases[i], "{\"increment-sequence\":true,\"sequence\":4294967270,\"acknowledgment\":321}");
        testPayloadCallbacks(&cases[i], "{\"increment-sequence\":false,\"sequence\":123,\"acknowledgment\":321}");
        testPayloadCallbacks(&cases[i], "{\"sequence\":\"random_node\"}");
        testPayloadCallbacks(&cases[i], "{\"sequence\":\"random_node\",\"increment-sequence\":false}");
        testPayloadCallbacks(&cases[i], "{\"sequence\":\"random_port\"}");
        testPayloadCallbacks(&cases[i], "{\"increment-sequence\":false}");
        testPayloadCallbacks(&cases[i],
                             "{\"sequence\":123,\"increment-sequence\":false,"
                             "\"acknowledgment\":4294967295,\"increment-acknowledgment\":true}");
        testPayloadCallbacks(&cases[i], "{\"acknowledgment\":4294967295,\"increment-acknowledgment\":true}");
        testPayloadCallbacks(&cases[i],
                             "{\"client-port\":40001,\"sequence\":0,\"increment-sequence\":false,"
                             "\"flags\":[{\"syn\":true},{},{\"ack\":true,\"psh\":true}]}");
        testPayloadCallbacks(&cases[i],
                             "{\"client-port\":40001,\"sequence\":4294967294,\"acknowledgment\":4294967295,"
                             "\"increment-acknowledgment\":true,\"flags\":[{\"syn\":true},{},{\"fin\":true}]}");
        testPayloadCallbacks(&cases[i],
                             "{\"client-port\":40001,\"acknowledgment\":\"random_packet\","
                             "\"flags\":[{\"syn\":true},{},{\"fin\":true}]}");
        testPayloadCallbacks(&cases[i],
                             "{\"flags\":[{\"fin\":true,\"syn\":true,\"rst\":true,\"psh\":true,"
                             "\"ack\":true,\"urg\":true,\"ece\":true,\"cwr\":true}]}");
        testPayloadCallbacks(&cases[i], "{\"sequence\":0,\"increment-sequence\":false,\"flags\":[{}]}");
        const char *const ack_modes[]    = {"random_node", "random_port", "random_packet"};
        const char *const seq_settings[] = {"\"sequence\":0,\"increment-sequence\":false",
                                            "\"sequence\":4294967270,\"increment-sequence\":true",
                                            "\"sequence\":\"random_node\",\"increment-sequence\":false",
                                            "\"sequence\":\"random_port\",\"increment-sequence\":true"};
        for (size_t a = 0; a < ARRAY_SIZE(ack_modes); ++a)
            for (size_t q = 0; q < ARRAY_SIZE(seq_settings); ++q)
            {
                char settings[192];
                snprintf(settings, sizeof(settings), "{\"acknowledgment\":\"%s\",%s}", ack_modes[a], seq_settings[q]);
                testPayloadCallbacks(&cases[i], settings);
                if (strcmp(ack_modes[a], "random_packet") != 0)
                {
                    snprintf(settings,
                             sizeof(settings),
                             "{\"acknowledgment\":\"%s\",\"increment-acknowledgment\":true,%s}",
                             ack_modes[a],
                             seq_settings[q]);
                    testPayloadCallbacks(&cases[i], settings);
                }
            }
#endif
    }

#if FAKE_TCP_HEADER_IPOVERRIDER_FIXTURE
    testIpOverriderComposition(&cases[0], &cases[1]);
#endif
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    networkloggerDestroy();
    puts("FakeTcpHeaderClient/FakeTcpHeaderServer node tests passed");
    return 0;
}
