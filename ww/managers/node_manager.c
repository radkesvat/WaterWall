#include "node_manager.h"
#include "chain.h"
#include "global_state.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "utils/json_helpers.h"

enum
{
    kVecCap     = 8,
    kNodeMapCap = 36
};

#define i_type map_node_t // NOLINT
#define i_key  hash_t     // NOLINT
#define i_val  node_t *   // NOLINT
#include "stc/hmap.h"

#define i_type vec_chains_t     // NOLINT
#define i_key  tunnel_chain_t * // NOLINT
#include "stc/vec.h"

typedef struct node_manager_config_s
{
    config_file_t *config_file;
    map_node_t     node_map;
    vec_chains_t   chains;

} node_manager_config_t;

#define i_type vec_configs_t           // NOLINT
#define i_key  node_manager_config_t * // NOLINT
#include "stc/vec.h"

typedef struct node_manager_s
{
    vec_configs_t configs;
} node_manager_t;

static node_manager_t *state;

static int createTunnelInstances(node_manager_config_t *cfg, tunnel_t **t_array, int max_size)
{
    int index = 0;
    c_foreach(p1, map_node_t, cfg->node_map)
    {
        node_t *n1 = p1.ref->second;
        assert(n1 != NULL && n1->instance == NULL);
        t_array[index++] = n1->instance = n1->createHandle(n1);

        if (n1->instance == NULL)
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") create() returned NULL handle", n1->name);
            terminateProgram(1);
        }

        if (index == max_size + 1)
        {
            LOGF("NodeManager: too many nodes in config");
            terminateProgram(1);
        }
    }
    return index;
}

static void assignChainsToTunnels(tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        tunnel_t *tunnel = t_array[i];
        if (tunnel->chain == NULL)
        {
            tunnel_chain_t *tc = tunnelchainCreate(getWorkersCount() - WORKER_ADDITIONS);
            tunnel->onChain(tunnel, tc);
        }
    }
}

static void finalizeTunnelChains(node_manager_config_t *cfg, tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        tunnel_t *tunnel = t_array[i];
        if (tunnelchainIsFinalized(tunnelGetChain(tunnel)) == false)
        {
            tunnelchainFinalize(tunnelGetChain(tunnel));
            vec_chains_t_push(&cfg->chains, tunnelGetChain(tunnel));

            uint16_t index = 0;
            uint16_t mem_offset = 0;
            for (int tci = 0; tci < tunnelGetChain(tunnel)->tunnels.len; tci++)
            {
                tunnel_t *tunnel_in_chain = tunnelGetChain(tunnel)->tunnels.tuns[tci];
                tunnel_in_chain->onIndex(tunnel_in_chain, index++, &mem_offset);
            }
            assert(mem_offset == tunnelGetChain(tunnel)->sum_line_state_size);
        }
    }
}

static void validateTunnelChains(tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        if (t_array[i]->next == NULL && t_array[i]->prev == NULL && !(t_array[i]->node->flags & kNodeFlagNoChain))
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") is not chained", t_array[i]->node->name);
            terminateProgram(1);
        }

        if (t_array[i]->next == NULL && !(t_array[i]->node->flags & kNodeFlagChainEnd))
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") at the end of the chain but dose not have "
                 "flagkNodeFlagChainEnd",
                 t_array[i]->node->name);
            terminateProgram(1);
        }
        if (t_array[i]->prev == NULL && !(t_array[i]->node->flags & kNodeFlagChainHead))
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") at the start of the chain but dose not have "
                 "flagkNodeFlagChainHead",
                 t_array[i]->node->name);
            terminateProgram(1);
        }
    }
}

static void prepareTunnels(tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        assert(t_array[i] != NULL);
        t_array[i]->onPrepair(t_array[i]);
    }
}

static void startTunnels(tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        assert(t_array[i] != NULL);
        tunnel_t *tunnel = t_array[i];
        tunnelGetChain(tunnel)->started = true;
        tunnel->onStart(tunnel);
    }
}

static void initializePacketTunnels(tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        assert(t_array[i] != NULL);
        tunnel_t *tunnel = t_array[i];
        if (tunnel->prev == NULL && tunnel->node->flags & kNodeFlagChainHead &&
            tunnel->node->layer_group == kNodeLayer3)
        {
            assert(tunnelGetChain(tunnel)->packet_chain_init_sent == false);

            tunnelGetChain(tunnel)->packet_chain_init_sent = true;
            for (wid_t wi = 0; wi < getWorkersCount() - WORKER_ADDITIONS; wi++)
            {
                line_t *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(tunnel), wi);
                tunnelNextUpStreamInit(tunnel, l);
                assert(lineIsAlive(l));
            }
        }
    }
}

static void runNodes(node_manager_config_t *cfg)
{
    enum
    {
        kMaxTarraySize = 512
    };

    tunnel_t *t_array[kMaxTarraySize] = {0};
    int tunnels_count = createTunnelInstances(cfg, t_array, kMaxTarraySize);

    if (tunnels_count == 0)
    {
        LOGW("NodeManager:  0 nodes in config");
        return;
    }

    assignChainsToTunnels(t_array, tunnels_count);
    finalizeTunnelChains(cfg, t_array, tunnels_count);
    validateTunnelChains(t_array, tunnels_count);
    prepareTunnels(t_array, tunnels_count);
    startTunnels(t_array, tunnels_count);
    initializePacketTunnels(t_array, tunnels_count);
}

static void validateNodeChainPath(node_t *start_node, node_manager_config_t *cfg)
{
    node_t *current_node = start_node;
    int path_length = 0;

    while (current_node->hash_next != 0)
    {
        path_length++;
        node_t *next_node = nodemanagerGetConfigNodeByHash(cfg, current_node->hash_next);
        if (next_node == NULL)
        {
            LOGF("Node Map Failure: Error in config file!  (path: %s)  (name: %s)", 
                 cfg->config_file->file_path, cfg->config_file->name);
            LOGF("Node Map Failure: node \"%s\" could not find it's next node \"%s\"", 
                 current_node->name, current_node->next);
            terminateProgram(1);
        }
        current_node = next_node;
        if (path_length > 200)
        {
            LOGF("Node Map Failure: circular reference deteceted");
            terminateProgram(1);
        }
    }
}

static void pathWalk(node_manager_config_t *cfg)
{
    c_foreach(p1, map_node_t, cfg->node_map)
    {
        node_t *node = p1.ref->second;
        validateNodeChainPath(node, cfg);
    }
}

static void validateChainHeadNodes(node_manager_config_t *cfg)
{
    c_foreach(n1, map_node_t, cfg->node_map)
    {
        if ((n1.ref->second->flags & kNodeFlagChainHead) == kNodeFlagChainHead)
        {
            return;
        }
    }
    LOGF("NodeMap: detecetd 0 chainhead nodes");
    terminateProgram(1);
}

static void cycleProcess(node_manager_config_t *cfg)
{
    c_foreach(n1, map_node_t, cfg->node_map)
    {
        hash_t next_hash = n1.ref->second->hash_next;
        if (next_hash == 0)
        {
            continue;
        }
    }

    validateChainHeadNodes(cfg);
}

static void parseNodeJsonFields(cJSON *node_json, node_manager_config_t *cfg, 
                                char **node_name, char **node_type, char **node_next, int *node_version)
{
    if (!getStringFromJsonObject(node_name, node_json, "name"))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes[x]->name (string field) was empty or invalid",
             cfg->config_file->file_path);
        terminateProgram(1);
    }

    if (!getStringFromJsonObject(node_type, node_json, "type"))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes[x]->type (string field) was empty or invalid",
             cfg->config_file->file_path);
        terminateProgram(1);
    }
    
    getStringFromJsonObject(node_next, node_json, "next");
    getIntFromJsonObjectOrDefault(node_version, node_json, "version", 0);
}

static node_t *createAndLoadNode(const char *node_type, hash_t hash_type)
{
    node_t *new_node = nodemanagerNewNode();
    *new_node = nodelibraryLoadByTypeHash(hash_type);
    
    if (new_node->hash_type != hash_type)
    {
        LOGF("NodeManager: node creation failure: library \"%s\" (hash: %lx) could not be loaded ", 
             node_type, hash_type);
        terminateProgram(1);
    }
    
    return new_node;
}

static void setupNodeProperties(node_t *node, char *node_name, char *node_type, char *node_next,
                               int node_version, hash_t hash_name, hash_t hash_type, hash_t hash_next,
                               cJSON *node_json, node_manager_config_t *cfg)
{
    node->name = node_name;
    node->type = node_type;
    node->next = node_next;
    node->hash_name = hash_name;
    node->hash_type = hash_type;
    node->hash_next = hash_next;
    node->version = (uint32_t)node_version;
    node->node_json = node_json;
    node->node_settings_json = cJSON_GetObjectItemCaseSensitive(node_json, "settings");
    node->node_manager_config = cfg;
}

static void registerNodeInMap(node_t *node, node_manager_config_t *cfg)
{
    map_node_t *map = &(cfg->node_map);
    
    if (map_node_t_contains(map, node->hash_name))
    {
        LOGF("NodeManager: duplicate node \"%s\" (hash: %lx) ", node->name, node->hash_name);
        terminateProgram(1);
    }
    
    map_node_t_insert(map, node->hash_name, node);
}

void nodemanagerCreateNodeInstance(node_manager_config_t *cfg, cJSON *node_json)
{
    char *node_name = NULL;
    char *node_type = NULL;
    char *node_next = NULL;
    int node_version = 0;

    parseNodeJsonFields(node_json, cfg, &node_name, &node_type, &node_next, &node_version);

    hash_t hash_name = calcHashBytes(node_name, strlen(node_name));
    hash_t hash_type = calcHashBytes(node_type, strlen(node_type));
    hash_t hash_next = node_next != NULL ? calcHashBytes(node_next, strlen(node_next)) : 0x0;

    node_t *new_node = createAndLoadNode(node_type, hash_type);
    setupNodeProperties(new_node, node_name, node_type, node_next, node_version, 
                       hash_name, hash_type, hash_next, node_json, cfg);
    registerNodeInMap(new_node, cfg);
}

node_t *nodemanagerGetConfigNodeByHash(node_manager_config_t *cfg, hash_t hash_node_name)
{
    map_node_t_iter iter = map_node_t_find(&(cfg->node_map), hash_node_name);
    if (iter.ref == map_node_t_end(&(cfg->node_map)).ref)
    {
        return NULL;
    }
    return (iter.ref->second);
}

node_t *nodemanagerGetConfigNodeByName(node_manager_config_t *cfg, const char *name)
{
    return nodemanagerGetConfigNodeByHash(cfg, calcHashBytes(name, stringLength(name)));
}

node_t *nodemanagerNewNode(void)
{
    node_t *new_node = memoryAllocate(sizeof(node_t));
    memorySet(new_node, 0, sizeof(node_t));
    return new_node;
}

static void createAllNodeInstances(node_manager_config_t *cfg)
{
    cJSON *nodes_json = cfg->config_file->nodes;
    cJSON *node_json = NULL;
    cJSON_ArrayForEach(node_json, nodes_json)
    {
        nodemanagerCreateNodeInstance(cfg, node_json);
    }
}

static void startInstallingConfigFile(node_manager_config_t *cfg)
{
    createAllNodeInstances(cfg);
    cycleProcess(cfg);
    pathWalk(cfg);
    runNodes(cfg);
}

struct node_manager_s *nodemanagerGetState(void)
{
    return state;
}

void nodemanagerSetState(struct node_manager_s *new_state)
{
    assert(state == NULL);
    state = new_state;
}

static node_manager_config_t *createNodeManagerConfig(config_file_t *config_file)
{
    node_manager_config_t *cfg = memoryAllocate(sizeof(node_manager_config_t));
    *cfg = (node_manager_config_t) {
        .config_file = config_file, 
        .node_map = map_node_t_with_capacity(kNodeMapCap), 
        .chains = vec_chains_t_init()
    };
    return cfg;
}

void nodemanagerRunConfigFile(config_file_t *config_file)
{
    node_manager_config_t *cfg = createNodeManagerConfig(config_file);
    vec_configs_t_push(&(state->configs), cfg);
    startInstallingConfigFile(cfg);
}

node_manager_t *nodemanagerCreate(void)
{
    assert(state == NULL);

    state = memoryAllocate(sizeof(node_manager_t));
    memorySet(state, 0, sizeof(node_manager_t));

    state->configs = vec_configs_t_with_capacity(kVecCap);

    return state;
}

void nodemanagerDestroyNode(node_t *node)
{
    tunnel_t *t = node->instance;
    if (t)
    {
        t->onDestroy(t);
        node->instance = NULL;
    }
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryFree(node);
}

void nodemanagerDestroyConfig(node_manager_config_t *cfg)
{
    c_foreach(node_key_pair, map_node_t, cfg->node_map)
    {
        node_t *node = (node_key_pair.ref)->second;
        nodemanagerDestroyNode(node);
    }
    
    c_foreach(chain, vec_chains_t, cfg->chains)
    {
        tunnelchainDestroy(*chain.ref);
    }
    
    map_node_t_drop(&cfg->node_map);
    vec_chains_t_drop(&cfg->chains);
    configfileDestroy(cfg->config_file);
    memoryFree(cfg);
}

void nodemanagerDestroy(void)
{
    if (state == NULL)
    {
        return;
    }
    
    c_foreach(conf, vec_configs_t, state->configs)
    {
        nodemanagerDestroyConfig(*conf.ref);
    }
    
    vec_configs_t_drop(&state->configs);
    memoryFree(state);
    state = NULL;
}
