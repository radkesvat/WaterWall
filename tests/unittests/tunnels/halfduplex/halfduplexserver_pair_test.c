/*
 * Covers: HalfDuplexServer pair configuration and assembled topology.
 * Setup: real constructors, PipeTunnel wrappers, chaining, and layer solver;
 * only configuration-node lookup is wrapped. All normal lines remain absent.
 * Cases: malformed/missing/recursive peers; primary/secondary discovery order;
 * multiple secondary inlets; inserted application helper; state/padding layout.
 * Cross-group application cycles fail from every discovery seed, while finite
 * group paths and unrelated nodes with a settings.pair field remain valid.
 * Limits: exact callback routing is covered by the reentrant suite, and worker
 * migration plus TLS/KCP traffic are covered by worker and integration suites.
 * CTest: waterwall.halfduplexserver_pair_unit
 */
#include "HalfDuplexServer/interface.h"
#include "HalfDuplexServer/structure.h"
#include "node_layer_solver.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static node_t   *configured_nodes[8];
static tunnel_t *application_helper;

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

static node_t makeServer(const char *name)
{
    node_t node    = nodeHalfDuplexServerGet();
    node.name      = (char *) name;
    node.hash_name = calcHashBytes(name, stringLength(name));
    return node;
}

static void setConfig(node_t *node, const char *json)
{
    node->node_json = cJSON_Parse(json);
    require(node->node_json != NULL, "fixture JSON did not parse");
    node->node_settings_json = cJSON_GetObjectItemCaseSensitive(node->node_json, "settings");
    node->next               = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(node->node_json, "next"));
    node->hash_next          = node->next != NULL ? calcHashBytes(node->next, stringLength(node->next)) : 0;
}

static void caseSettings(void)
{
    node_t primary      = makeServer("primary");
    node_t secondary    = makeServer("secondary");
    node_t wrong        = makeNode("wrong", kNodeFlagChainEnd);
    configured_nodes[0] = &primary;
    configured_nodes[1] = &secondary;
    configured_nodes[2] = &wrong;
    setConfig(&primary, "{\"next\":\"application\"}");
    const struct
    {
        const char *json;
        bool        valid;
    } cases[] = {
        {"{\"next\":\"application\"}", true},
        {"{\"next\":\"application\",\"settings\":{}}", true},
        {"{\"settings\":{\"pair\":\"primary\"}}", true},
        {"{}", false},
        {"{\"next\":null}", false},
        {"{\"next\":42}", false},
        {"{\"next\":\"\"}", false},
        {"{\"next\":\"application\\u0000suffix\"}", false},
        {"{\"next\":\"application\",\"settings\":[]}", false},
        {"{\"settings\":{\"pair\":null}}", false},
        {"{\"settings\":{\"pair\":false}}", false},
        {"{\"settings\":{\"pair\":42}}", false},
        {"{\"settings\":{\"pair\":\"\"}}", false},
        {"{\"settings\":{\"pair\":\"primary\\u0000suffix\"}}", false},
        {"{\"settings\":{\"pair\":\"missing\"}}", false},
        {"{\"settings\":{\"pair\":\"secondary\"}}", false},
        {"{\"settings\":{\"pair\":\"wrong\"}}", false},
        {"{\"next\":\"application\",\"settings\":{\"pair\":\"primary\"}}", false},
        {"{\"next\":null,\"settings\":{\"pair\":\"primary\"}}", false},
    };
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        testCaseSet(cases[i].json);
        setConfig(&secondary, cases[i].json);
        tunnel_t *wrapper = halfduplexserverTunnelCreate(&secondary);
        require((wrapper != NULL) == cases[i].valid, "configuration acceptance violated the pair contract");
        if (wrapper != NULL)
            wrapper->onDestroy(wrapper, wwLifecycleStartupRollback());
        cJSON_Delete(secondary.node_json);
    }
    cJSON_Delete(primary.node_json);
    const char *invalid_primaries[] = {
        "{}",
        "{\"next\":null}",
        "{\"next\":\"\"}",
        "{\"settings\":{\"pair\":\"secondary\"}}",
        "{\"next\":\"application\",\"settings\":{\"pair\":\"secondary\"}}",
    };
    setConfig(&secondary, "{\"settings\":{\"pair\":\"primary\"}}");
    for (size_t i = 0; i < ARRAY_SIZE(invalid_primaries); ++i)
    {
        testCaseSet(invalid_primaries[i]);
        setConfig(&primary, invalid_primaries[i]);
        tunnel_t *first  = halfduplexserverTunnelCreate(&primary);
        tunnel_t *second = halfduplexserverTunnelCreate(&secondary);
        require(first == NULL || second == NULL, "pair target without a primary application path survived");
        if (first != NULL)
            first->onDestroy(first, wwLifecycleStartupRollback());
        if (second != NULL)
            second->onDestroy(second, wwLifecycleStartupRollback());
        cJSON_Delete(primary.node_json);
    }
    cJSON_Delete(secondary.node_json);
    memoryFree(primary.type);
    memoryFree(secondary.type);
    memoryZero(configured_nodes, sizeof(configured_nodes));
}

static void insertApplicationHelper(tunnel_t *target, tunnel_chain_t *chain)
{
    require(tunnelInsertBefore(target, application_helper, chain), "application helper insertion failed");
    tunnelDefaultOnChain(target, chain);
}

static void caseTopology(unsigned first, bool with_helper, bool second_secondary, bool wrong_layer)
{
    char label[128];
    snprintf(label,
             sizeof(label),
             "HalfDuplexServer pair first=%u helper=%u multiple=%u wrong-layer=%u",
             first,
             with_helper,
             second_secondary,
             wrong_layer);
    testCaseSet(label);
    node_t servers[] = {makeServer("primary"), makeServer("secondary"), makeServer("secondary2")};
    node_t nodes[]   = {makeNode("head", kNodeFlagChainHead),
                        makeNode("head2", kNodeFlagChainHead),
                        makeNode("head3", kNodeFlagChainHead),
                        makeNode("application", kNodeFlagChainEnd),
                        makeNode("application.helper", 0)};
    for (size_t i = 0; i < ARRAY_SIZE(servers); ++i)
        configured_nodes[i] = &servers[i];
    for (size_t i = 0; i < ARRAY_SIZE(nodes); ++i)
        configured_nodes[ARRAY_SIZE(servers) + i] = &nodes[i];
    setConfig(&servers[0], "{\"next\":\"application\"}");
    setConfig(&servers[1], "{\"settings\":{\"pair\":\"primary\"}}");
    setConfig(&servers[2], "{\"settings\":{\"pair\":\"primary\"}}");
    const unsigned count = second_secondary ? 3 : 2;
    for (unsigned i = 0; i < count; ++i)
    {
        servers[i].instance = halfduplexserverTunnelCreate(&servers[i]);
        require(servers[i].instance != NULL, "valid pair constructor failed");
        nodes[i].hash_next = servers[i].hash_name;
        nodes[i].next      = servers[i].name;
    }
    for (size_t i = 0; i < ARRAY_SIZE(nodes); ++i)
    {
        nodes[i].required_padding_left = (uint16_t) (i + 1);
        nodes[i].instance              = tunnelCreate(&nodes[i], 0, 32);
        require(nodes[i].instance != NULL, "fixture allocation failed");
    }
    application_helper = nodes[4].instance;
    if (with_helper)
        nodes[3].instance->onChain = insertApplicationHelper;
    if (wrong_layer)
        nodes[1].layer_group = nodes[1].layer_group_next_node = kNodeLayer3;

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    // Discover an unbound server first, then each independent listener chain.
    servers[first].instance->onChain(servers[first].instance, tunnelchainCreate(0));
    for (unsigned i = 0; i < count; ++i)
    {
        const unsigned index = (i + first) % count;
        tunnel_t      *head  = nodes[index].instance;
        head->onChain(head, tunnelchainCreate(0));
    }
    ww_startup_result_t result = wwStartupContextEnd(&startup);
    require(wwStartupSucceeded(result), "valid pair topology did not assemble");
    tunnel_chain_t            *chain  = tunnelGetChain(servers[0].instance);
    node_layer_solver_status_t status = {0};
    const bool                 solved = nodeLayerSolveChain(chain, &status);
    if (! solved && ! wrong_layer)
        fprintf(stderr, "Layer solver: %s\n", status.message);
    require(solved != wrong_layer, "paired ingress layer constraint was lost");
    tunnel_t *primary = servers[0].instance->next;
    require(primary != NULL && primary->node == &servers[0], "primary wrapper lost its child");
    halfduplexserver_tstate_t *owner = tunnelGetState(primary);
    require(owner->owner == primary && owner->wrapper == servers[0].instance,
            "primary did not retain its owner/wrapper identity");
    require(primary->next == (with_helper ? application_helper : nodes[3].instance),
            "primary application path skipped an inserted helper");
    for (unsigned i = 0; i < count; ++i)
    {
        tunnel_t                  *wrapper = servers[i].instance;
        tunnel_t                  *child   = wrapper->next;
        halfduplexserver_tstate_t *state   = tunnelGetState(child);
        require(tunnelGetChain(wrapper) == chain && tunnelGetChain(child) == chain &&
                    tunnelGetChain(nodes[i].instance) == chain,
                "paired listener/wrapper/child was omitted from the shared chain");
        require(state->owner == primary && state->wrapper == wrapper, "secondary resolved to the wrong owner/wrapper");
        require(wrapper->prev == nodes[i].instance && child->prev == wrapper,
                "paired transport lost its own return path");
        require(i == 0 || child->next == NULL, "secondary acquired an independent application path");
    }
    require(chain->tunnels.len == count * 3 + 1 + (with_helper ? 1 : 0),
            "paired chain omitted or double-registered a tunnel");
    uint32_t offset  = 0;
    uint32_t padding = 0;
    for (uint16_t i = 0; i < chain->tunnels.len; ++i)
    {
        tunnel_t *tunnel = chain->tunnels.tuns[i];
        tunnel->onIndex(tunnel, i, &offset);
        padding += tunnel->node->required_padding_left;
    }
    require(offset == chain->sum_line_state_size && padding == chain->sum_padding_left,
            "paired state/padding layout was incomplete");
    require(servers[0].instance->next->lstate_offset != servers[1].instance->next->lstate_offset,
            "two HalfDuplexServer ingress states overlap");
    tunnelchainDestroy(chain);
    for (unsigned i = 0; i < count; ++i)
        servers[i].instance->onDestroy(servers[i].instance, wwLifecycleStartupRollback());
    for (size_t i = 0; i < ARRAY_SIZE(servers); ++i)
    {
        cJSON_Delete(servers[i].node_json);
        memoryFree(servers[i].type);
    }
    for (size_t i = 0; i < ARRAY_SIZE(nodes); ++i)
        tunnelDestroy(nodes[i].instance);
    memoryZero(configured_nodes, sizeof(configured_nodes));
}

static void caseCyclicApplicationPath(bool through_inlet)
{
    testCaseSet(through_inlet ? "primary application path cycles through secondary listener"
                              : "primary application path cycles through secondary");
    node_t primary      = makeServer("primary");
    node_t secondary    = makeServer("secondary");
    node_t inlet        = makeNode("inlet", kNodeFlagChainHead);
    configured_nodes[0] = &primary;
    configured_nodes[1] = &secondary;
    configured_nodes[2] = &inlet;
    setConfig(&primary, through_inlet ? "{\"next\":\"inlet\"}" : "{\"next\":\"secondary\"}");
    setConfig(&secondary, "{\"settings\":{\"pair\":\"primary\"}}");
    inlet.next         = secondary.name;
    inlet.hash_next    = secondary.hash_name;
    primary.instance   = halfduplexserverTunnelCreate(&primary);
    secondary.instance = halfduplexserverTunnelCreate(&secondary);
    inlet.instance     = tunnelCreate(&inlet, 0, 0);
    require(primary.instance != NULL && secondary.instance != NULL && inlet.instance != NULL,
            "cycle fixture construction failed before topology validation");
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    tunnel_chain_t *chain = tunnelchainCreate(0);
    secondary.instance->onChain(secondary.instance, chain);
    require(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "pair cycle escaped startup rejection");
    tunnelchainDestroy(chain);
    primary.instance->onDestroy(primary.instance, wwLifecycleStartupRollback());
    secondary.instance->onDestroy(secondary.instance, wwLifecycleStartupRollback());
    tunnelDestroy(inlet.instance);
    cJSON_Delete(primary.node_json);
    cJSON_Delete(secondary.node_json);
    memoryFree(primary.type);
    memoryFree(secondary.type);
    memoryZero(configured_nodes, sizeof(configured_nodes));
}

static void caseApplicationPathAcrossGroups(unsigned first, bool cyclic, bool foreign_pair)
{
    char label[128];
    snprintf(label,
             sizeof(label),
             "HalfDuplexServer cross-group path first=%u cyclic=%u foreign-pair=%u",
             first,
             cyclic,
             foreign_pair);
    testCaseSet(label);
    node_t servers[] = {makeServer("p1"), makeServer("p2"), makeServer("s1"), makeServer("s2")};
    node_t nodes[]   = {makeNode("head1", kNodeFlagChainHead),
                        makeNode("head2", kNodeFlagChainHead),
                        makeNode("head3", kNodeFlagChainHead),
                        makeNode("application", kNodeFlagChainEnd)};
    for (size_t i = 0; i < ARRAY_SIZE(servers); ++i)
        configured_nodes[i] = &servers[i];
    const unsigned node_count = cyclic ? 2 : ARRAY_SIZE(nodes);
    for (unsigned i = 0; i < node_count; ++i)
        configured_nodes[ARRAY_SIZE(servers) + i] = &nodes[i];
    setConfig(&servers[0], "{\"next\":\"s2\"}");
    setConfig(&servers[1], cyclic ? "{\"next\":\"s1\"}" : "{\"next\":\"application\"}");
    setConfig(&servers[2], "{\"settings\":{\"pair\":\"p1\"}}");
    setConfig(&servers[3], "{\"settings\":{\"pair\":\"p2\"}}");
    // A similarly named setting in another node type is not a HalfDuplex edge.
    if (foreign_pair)
        setConfig(&nodes[3], "{\"settings\":{\"pair\":\"p1\"}}");
    for (unsigned i = 0; i < ARRAY_SIZE(servers); ++i)
    {
        servers[i].instance = halfduplexserverTunnelCreate(&servers[i]);
        require(servers[i].instance != NULL, "cross-group constructor failed before topology validation");
    }
    for (unsigned i = 0; i < node_count; ++i)
    {
        if (i < 3)
        {
            nodes[i].next      = servers[i].name;
            nodes[i].hash_next = servers[i].hash_name;
        }
        nodes[i].instance = tunnelCreate(&nodes[i], 0, 0);
        require(nodes[i].instance != NULL, "cross-group head/application allocation failed");
    }

    // Model NodeManager discovery, including both listener inputs and wrappers.
    node_t *discovery[] = {
        &nodes[0], &nodes[1], &servers[0], &servers[1], &servers[2], &servers[3], &nodes[2], &nodes[3]};
    const unsigned       count   = cyclic ? 6 : ARRAY_SIZE(discovery);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    for (unsigned i = 0; i < count && ! startupFailurePending(); ++i)
    {
        tunnel_t *tunnel = discovery[(first + i) % count]->instance;
        if (tunnelGetChain(tunnel) == NULL)
            tunnel->onChain(tunnel, tunnelchainCreate(0));
    }
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    require(wwStartupSucceeded(result) != cyclic,
            cyclic ? "cross-group pair cycle escaped startup rejection" : "finite cross-group path was rejected");
    if (! cyclic)
    {
        tunnel_chain_t            *chain  = tunnelGetChain(servers[0].instance);
        node_layer_solver_status_t status = {0};
        require(nodeLayerSolveChain(chain, &status), "finite cross-group path failed layer validation");
        for (unsigned i = 0; i < count; ++i)
            require(tunnelGetChain(discovery[i]->instance) == chain, "finite path omitted a group or listener");
        require(servers[0].instance->next->next == servers[3].instance &&
                    servers[1].instance->next->next == nodes[3].instance,
                "finite path lost its intermediate group or terminal application");
    }

    // Partial startup may leave several chains; collect before freeing any.
    tunnel_chain_t *chains[ARRAY_SIZE(discovery)] = {0};
    unsigned        chain_count                   = 0;
    for (unsigned i = 0; i < count; ++i)
    {
        tunnel_chain_t *chain = tunnelGetChain(discovery[i]->instance);
        if (chain == NULL)
            continue;
        bool found = false;
        for (unsigned j = 0; j < chain_count; ++j)
            found |= chains[j] == chain;
        if (! found)
            chains[chain_count++] = chain;
    }
    for (unsigned i = 0; i < chain_count; ++i)
        tunnelchainDestroy(chains[i]);
    for (size_t i = 0; i < ARRAY_SIZE(servers); ++i)
    {
        servers[i].instance->onDestroy(servers[i].instance, wwLifecycleStartupRollback());
        cJSON_Delete(servers[i].node_json);
        memoryFree(servers[i].type);
    }
    for (unsigned i = 0; i < node_count; ++i)
    {
        tunnelDestroy(nodes[i].instance);
        cJSON_Delete(nodes[i].node_json);
    }
    memoryZero(configured_nodes, sizeof(configured_nodes));
}

int main(void)
{
    caseSettings();
    caseCyclicApplicationPath(false);
    caseCyclicApplicationPath(true);
    for (unsigned first = 0; first < 6; ++first)
        caseApplicationPathAcrossGroups(first, true, false);
    for (unsigned first = 0; first < 8; ++first)
    {
        caseApplicationPathAcrossGroups(first, false, false);
        caseApplicationPathAcrossGroups(first, false, true);
    }
    for (unsigned first = 0; first < 2; ++first)
        for (unsigned helper = 0; helper < 2; ++helper)
            for (unsigned multiple = 0; multiple < 2; ++multiple)
                caseTopology(first, helper != 0, multiple != 0, false);
    caseTopology(2, true, true, false);
    caseTopology(1, false, false, true);
    puts("halfduplexserver_pair_test: all cases passed");
    return 0;
}
