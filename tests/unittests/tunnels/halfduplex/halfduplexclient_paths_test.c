/*
 * Covers: HalfDuplexClient path configuration and topology construction.
 * Setup: real constructors, chaining and layer solver; only config-node lookup
 * is wrapped. Synthetic branch helpers exercise the same insertion API as DNS.
 * Cases: default, distinct and identical targets; helper entries; chain merging;
 * invalid fields, missing nodes, cycles, occupied branches and incompatible layers.
 * Limits: runtime callback routing is covered by the framing/reentrant suites;
 * real connectors are covered by the loopback integration test.
 * CTest: waterwall.halfduplexclient_paths_unit
 */
#include "HalfDuplexClient/interface.h"
#include "HalfDuplexClient/structure.h"
#include "node_layer_solver.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static node_t   *configured_nodes[4];
static tunnel_t *helpers[2];
static bool      replace_chain;

node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash);
node_t *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name);

node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash)
{
    discard config;
    for (size_t i = 0; i < ARRAY_SIZE(configured_nodes); ++i)
        if (configured_nodes[i] != NULL && configured_nodes[i]->hash_name == hash)
            return configured_nodes[i];
    return NULL;
}

node_t *__wrap_nodemanagerGetConfigNodeByName(node_manager_config_t *config, const char *name)
{
    return __wrap_nodemanagerGetConfigNodeByHash(config, calcHashBytes(name, stringLength(name)));
}

static node_t makeNode(const char *name, unsigned flags)
{
    return (node_t) {.name                  = (char *) name,
                     .type                  = (char *) "test",
                     .hash_name             = calcHashBytes(name, stringLength(name)),
                     .flags                 = flags | kNodeFlagSupportsSplice,
                     .can_have_prev         = true,
                     .can_have_next         = true,
                     .layer_group           = kNodeLayer4,
                     .layer_group_prev_node = kNodeLayer4,
                     .layer_group_next_node = kNodeLayer4};
}

static void setConfig(node_t *node, const char *json)
{
    node->node_json = cJSON_Parse(json);
    require(node->node_json != NULL, "fixture JSON failed to parse");
    node->node_settings_json = cJSON_GetObjectItemCaseSensitive(node->node_json, "settings");
    node->next               = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(node->node_json, "next"));
    node->hash_next          = node->next != NULL ? calcHashBytes(node->next, stringLength(node->next)) : 0;
}

static void caseSettings(void)
{
    node_t client       = makeNode("client", 0);
    node_t upload       = makeNode("upload", kNodeFlagChainEnd);
    node_t download     = makeNode("download", kNodeFlagChainEnd);
    configured_nodes[0] = &client;
    configured_nodes[1] = &upload;
    configured_nodes[2] = &download;
    const struct
    {
        const char *json;
        bool        valid;
    } cases[] = {
        {"{\"next\":\"upload\"}", true},
        {"{\"next\":\"upload\",\"settings\":{}}", true},
        {"{\"settings\":{\"upload\":\"upload\",\"download\":\"download\"}}", true},
        {"{\"settings\":{\"upload\":\"upload\",\"download\":\"upload\"}}", true},
        {"{}", false},
        {"{\"next\":null}", false},
        {"{\"next\":42}", false},
        {"{\"next\":\"\"}", false},
        {"{\"next\":\"upload\\u0000suffix\"}", false},
        {"{\"next\":\"upload\",\"settings\":[]}", false},
        {"{\"settings\":{\"upload\":\"upload\"}}", false},
        {"{\"next\":\"upload\",\"settings\":{\"download\":\"download\"}}", false},
        {"{\"settings\":{\"upload\":null,\"download\":null}}", false},
        {"{\"settings\":{\"upload\":\"upload\",\"download\":false}}", false},
        {"{\"settings\":{\"upload\":\"\",\"download\":\"download\"}}", false},
        {"{\"settings\":{\"upload\":\"upload\",\"download\":\"\"}}", false},
        {"{\"settings\":{\"upload\":\"upload\\u0000suffix\",\"download\":\"download\"}}", false},
        {"{\"settings\":{\"upload\":\"missing\",\"download\":\"download\"}}", false},
        {"{\"settings\":{\"upload\":\"upload\",\"download\":\"missing\"}}", false},
        {"{\"settings\":{\"upload\":\"client\",\"download\":\"download\"}}", false},
        {"{\"settings\":{\"upload\":\"upload\",\"download\":\"client\"}}", false},
        {"{\"next\":\"upload\",\"settings\":{\"upload\":\"upload\",\"download\":\"download\"}}", false},
        {"{\"next\":null,\"settings\":{\"upload\":\"upload\",\"download\":\"download\"}}", false},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].json);
        setConfig(&client, cases[i].json);
        tunnel_t *t = halfduplexclientTunnelCreate(&client);
        require((t != NULL) == cases[i].valid, "configuration acceptance disagreed with the path contract");
        if (t != NULL)
            tunnelDestroy(t);
        cJSON_Delete(client.node_json);
    }
    memoryZero(configured_nodes, sizeof(configured_nodes));
}

static void insertHelper(tunnel_t *target, tunnel_chain_t *chain)
{
    unsigned index = target == configured_nodes[1]->instance ? 0 : 1;
    require(tunnelInsertBefore(target, helpers[index], chain), "helper insertion failed");
    tunnelDefaultOnChain(target, chain);
    if (replace_chain && index == 1)
        tunnelchainCombine(tunnelchainCreate(0), tunnelGetChain(target));
}

static void caseTopology(unsigned mode, bool with_helpers, bool prebuilt, unsigned invalid)
{
    char label[128];
    snprintf(label,
             sizeof(label),
             "HalfDuplexClient paths mode=%u helpers=%u prebuilt=%u invalid=%u",
             mode,
             with_helpers,
             prebuilt,
             invalid);
    testCaseSet(label);
    node_t client         = nodeHalfDuplexClientGet();
    client.name           = (char *) "client";
    client.hash_name      = calcHashBytes(client.name, stringLength(client.name));
    node_t nodes[]        = {makeNode("head", kNodeFlagChainHead),
                             makeNode("upload", kNodeFlagChainEnd),
                             makeNode("download", kNodeFlagChainEnd),
                             makeNode("upload.helper", 0),
                             makeNode("download.helper", 0)};
    configured_nodes[0]   = &client;
    configured_nodes[1]   = &nodes[1];
    configured_nodes[2]   = &nodes[2];
    configured_nodes[3]   = &nodes[0];
    const char *configs[] = {"{\"next\":\"upload\"}",
                             "{\"settings\":{\"upload\":\"upload\",\"download\":\"download\"}}",
                             "{\"settings\":{\"upload\":\"upload\",\"download\":\"upload\"}}"};
    setConfig(&client, configs[mode]);
    client.instance = halfduplexclientTunnelCreate(&client);
    require(client.instance != NULL, "valid path constructor failed");
    for (size_t i = 0; i < ARRAY_SIZE(nodes); ++i)
    {
        nodes[i].instance = tunnelCreate(&nodes[i], 0, 32);
        require(nodes[i].instance != NULL, "fixture tunnel allocation failed");
    }
    helpers[0]                     = nodes[3].instance;
    helpers[1]                     = nodes[4].instance;
    nodes[3].required_padding_left = 11;
    nodes[4].required_padding_left = 23;
    if (with_helpers)
    {
        nodes[1].instance->onChain = insertHelper;
        nodes[2].instance->onChain = insertHelper;
    }
    // Visit the middle node before its inlet, as NodeManager may do.
    client.instance->onChain(client.instance, tunnelchainCreate(0));
    require(client.instance->chain == NULL, "middle node did not defer until its inlet was bound");
    tunnel_t *head = nodes[0].instance;
    tunnelBind(head, client.instance);
    tunnel_chain_t *chain = tunnelchainCreate(0);
    tunnelchainInsert(chain, head);
    if (prebuilt)
    {
        require(! with_helpers, "prebuilt fixture cannot insert helpers without an inlet");
        tunnelchainInsert(tunnelchainCreate(0), nodes[1].instance);
        if (mode == 1)
            tunnelchainInsert(tunnelchainCreate(0), nodes[2].instance);
    }
    if (invalid == 1)
        nodes[1].instance->prev = head;
    if (invalid == 2)
        nodes[1].hash_next = client.hash_name;
    if (invalid == 3)
        nodes[1].hash_next = nodes[2].hash_name; // Branches cannot converge onto a bound node.
    if (invalid == 4)
        nodes[1].layer_group = nodes[1].layer_group_prev_node = kNodeLayer3;
    if (invalid == 5)
        nodes[2].layer_group = nodes[2].layer_group_prev_node = kNodeLayer3;
    if (invalid == 6)
        nodes[1].hash_next = nodes[0].hash_name; // Return to the configured inlet.

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    client.instance->onChain(client.instance, chain);
    ww_startup_result_t result = wwStartupContextEnd(&startup);
    chain                      = tunnelGetChain(client.instance);
    require(wwStartupSucceeded(result) == (invalid == 0 || invalid == 4 || invalid == 5),
            "invalid branch ownership/cycle was not rejected");
    if (wwStartupSucceeded(result))
    {
        node_layer_solver_status_t status = {0};
        bool                       solved = nodeLayerSolveChain(chain, &status);
        if (! solved && invalid == 0)
            fprintf(stderr, "Layer solver: %s\n", status.message);
        require(solved == (invalid == 0), "branch layer validation disagreed");
        if (invalid == 0)
        {
            halfduplexclient_tstate_t *ts       = tunnelGetState(client.instance);
            tunnel_t                  *upload   = with_helpers ? helpers[0] : nodes[1].instance;
            tunnel_t                  *download = mode == 1 ? (with_helpers ? helpers[1] : nodes[2].instance) : upload;
            require(ts->upload_tunnel == upload && ts->download_tunnel == download,
                    "resolved path skipped a helper or selected the wrong target");
            require(upload->prev == client.instance && download->prev == client.instance,
                    "branch callbacks cannot return to their owner");
            unsigned expected = 2 + (mode == 1 ? 2 : 1) * (with_helpers ? 2 : 1);
            require(chain->tunnels.len == expected, "branch was missing or registered more than once");
            require(chain->sum_padding_left == kHLFDIntroSize + (with_helpers ? (mode == 1 ? 34 : 11) : 0),
                    "branch padding was lost or counted twice");
            uint32_t offset = 0;
            for (uint16_t i = 0; i < chain->tunnels.len; ++i)
                chain->tunnels.tuns[i]->onIndex(chain->tunnels.tuns[i], i, &offset);
            require(offset == chain->sum_line_state_size, "branch line-state layout was incomplete");
        }
    }
    tunnelchainDestroy(chain);
    for (size_t i = 0; i < ARRAY_SIZE(nodes); ++i)
        tunnelDestroy(nodes[i].instance);
    tunnelDestroy(client.instance);
    cJSON_Delete(client.node_json);
    memoryFree(client.type);
    memoryZero(configured_nodes, sizeof(configured_nodes));
}

int main(void)
{
    caseSettings();
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        caseTopology(mode, false, false, 0);
        caseTopology(mode, true, false, 0);
        caseTopology(mode, false, true, 0);
    }
    replace_chain = true;
    caseTopology(1, true, false, 0);
    replace_chain = false;
    for (unsigned invalid = 1; invalid <= 6; ++invalid)
        caseTopology(1, false, false, invalid);
    puts("halfduplexclient_paths_test: all cases passed");
    return 0;
}
