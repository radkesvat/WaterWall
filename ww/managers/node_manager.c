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

static void runNodes(node_manager_config_t *cfg)
{
    enum
    {
        kMaxTarraySize = 512
    };

    tunnel_t *t_array[kMaxTarraySize] = {0};

    int tunnels_count = 0;
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

            if (index == kMaxTarraySize + 1)
            {
                LOGF("NodeManager: too many nodes in config");
                terminateProgram(1);
            }
        }
        tunnels_count = index;
    }

    if (tunnels_count == 0)
    {
        LOGW("NodeManager:  0 nodes in config");
        return;
    }

    {
        for (int i = 0; i < tunnels_count; i++)
        {

            tunnel_t *tunnel = t_array[i];
            if (tunnel->chain == NULL)
            {
                tunnel_chain_t *tc = tunnelchainCreate(getWorkersCount() - WORKER_ADDITIONS);
                vec_chains_t_push(&cfg->chains, tc);
                tunnel->onChain(tunnel, tc);
            }
        }
    }

    {
        for (int i = 0; i < tunnels_count; i++)
        {
            tunnel_t *tunnel = t_array[i];
            if (tunnelchainIsFinalized(tunnelGetChain(tunnel)) == false)
            {
                tunnelchainFinalize(tunnelGetChain(tunnel));
                uint16_t index      = 0;
                uint16_t mem_offset = 0;
                for (int tci = 0; tci < tunnelGetChain(tunnel)->tunnels.len; tci++)
                {
                    tunnel_t *tunnel_in_chain = tunnelGetChain(tunnel)->tunnels.tuns[tci];

                    tunnel_in_chain->onIndex(tunnel_in_chain, index++, &mem_offset);
                }
            }
        }
    }

    {
        for (int i = 0; i < tunnels_count; i++)
        {
            if (t_array[i]->chain == NULL && ! (t_array[i]->node->flags & kNodeFlagNoChain))
            {
                LOGF("NodeManager: node startup failure: node (\"%s\") is not chained", t_array[i]->node->name);
                terminateProgram(1);
            }

            if (t_array[i]->next == NULL && ! (t_array[i]->node->flags & kNodeFlagChainEnd))
            {
                LOGF("NodeManager: node startup failure: node (\"%s\") at the end of the chain but dose not have "
                     "flagkNodeFlagChainEnd",
                     t_array[i]->node->name);
                terminateProgram(1);
            }
            if (t_array[i]->prev == NULL && ! (t_array[i]->node->flags & kNodeFlagChainHead))
            {
                LOGF("NodeManager: node startup failure: node (\"%s\") at the start of the chain but dose not have "
                     "flagkNodeFlagChainHead",
                     t_array[i]->node->name);
                terminateProgram(1);
            }
        }
    }
    {
        for (int i = 0; i < tunnels_count; i++)
        {
            assert(t_array[i] != NULL);
            t_array[i]->onPrepair(t_array[i]);
        }
    }
    {
        for (int i = 0; i < tunnels_count; i++)
        {
            assert(t_array[i] != NULL);
            tunnel_t *tunnel                = t_array[i];
            tunnelGetChain(tunnel)->started = true;
            tunnel->onStart(tunnel);
        }
    }
    {
        // send packt tunnels init
        for (int i = 0; i < tunnels_count; i++)
        {
            assert(t_array[i] != NULL);
            tunnel_t *tunnel = t_array[i];
            if (tunnel->prev == NULL && tunnel->node->flags & kNodeFlagChainHead &&
                tunnel->node->layer_group == kNodeLayer3)
            {
                // this is a packet tunnel, we need to send init to it ( for each worker )
                assert(tunnelGetChain(tunnel)->packet_chain_init_sent == false);

                tunnelGetChain(tunnel)->packet_chain_init_sent = true;
                for (wid_t wi = 0; wi < getWorkersCount() - WORKER_ADDITIONS; wi++)
                {
                    line_t *l = tunnelchainGetPacketLine(tunnelGetChain(tunnel), wi);

                    tunnelNextUpStreamInit(tunnel, l);
                    assert(lineIsAlive(l));
                }
            }
        }
    }
}

static void pathWalk(node_manager_config_t *cfg)
{

    c_foreach(p1, map_node_t, cfg->node_map)
    {
        node_t *n1 = p1.ref->second;

        int c = 0;
        while (true)
        {
            if (n1->hash_next == 0)
            {
                break;
            }
            c++;
            node_t *n2 = nodemanagerGetConfigNodeByHash(cfg, n1->hash_next);
            if (n2 == NULL)
            {
                LOGF("Node Map Failure: Error in config file!  (path: %s)  (name: %s)", cfg->config_file->file_path,
                     cfg->config_file->name);
                LOGF("Node Map Failure: node \"%s\" could not find it's next node \"%s\"", n1->name, n1->next);
                terminateProgram(1);
            }
            n1 = n2;
            if (c > 200)
            {
                LOGF("Node Map Failure: circular reference deteceted");
                terminateProgram(1);
            }
        }
    }
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

    // very basic check to see if there is no route starter node
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
}

void nodemanagerCreateNodeInstance(node_manager_config_t *cfg, cJSON *node_json)
{
    char *node_name    = NULL;
    char *node_type    = NULL;
    char *node_next    = NULL;
    int   node_version = 0;

    if (! getStringFromJsonObject(&(node_name), node_json, "name"))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes[x]->name (string field) was empty or invalid",
             cfg->config_file->file_path);
        terminateProgram(1);
    }

    if (! getStringFromJsonObject(&(node_type), node_json, "type"))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes[x]->type (string field) was empty or invalid",
             cfg->config_file->file_path);
        terminateProgram(1);
    }
    getStringFromJsonObject(&(node_next), node_json, "next");
    getIntFromJsonObjectOrDefault(&(node_version), node_json, "version", 0);

    hash_t hash_name = calcHashBytes(node_name, strlen(node_name));
    hash_t hash_type = calcHashBytes(node_type, strlen(node_type));
    hash_t hash_next = node_next != NULL ? calcHashBytes(node_next, strlen(node_next)) : 0x0;

    // load lib
    node_t *new_node = nodemanagerNewNode();
    *new_node        = nodelibraryLoadByTypeHash(hash_type);
    if (new_node->hash_type != hash_type)
    {
        LOGF("NodeManager: node creation failure: library \"%s\" (hash: %lx) could not be loaded ", node_type,
             hash_type);
        terminateProgram(1);
    }
    else
    {
        LOGD("%-18s: library \"%s\" loaded successfully", node_name, node_type);
    }
    new_node->name      = node_name;
    new_node->type      = node_type;
    new_node->next      = node_next;
    new_node->hash_name = hash_name;
    new_node->hash_type = hash_type;
    new_node->hash_next = hash_next;
    new_node->version   = (uint32_t) node_version;

    new_node->node_json           = node_json;
    new_node->node_settings_json  = cJSON_GetObjectItemCaseSensitive(node_json, "settings");
    new_node->node_manager_config = cfg;

    map_node_t *map = &(cfg->node_map);

    if (map_node_t_contains(map, new_node->hash_name))
    {
        LOGF("NodeManager: duplicate node \"%s\" (hash: %lx) ", new_node->name, new_node->hash_name);
        terminateProgram(1);
    }
    map_node_t_insert(map, new_node->hash_name, new_node);
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

static void startInstallingConfigFile(node_manager_config_t *cfg)
{
    cJSON *nodes_json = cfg->config_file->nodes;
    cJSON *node_json  = NULL;
    cJSON_ArrayForEach(node_json, nodes_json)
    {
        nodemanagerCreateNodeInstance(cfg, node_json);
    }

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

void nodemanagerRunConfigFile(config_file_t *config_file)
{

    node_manager_config_t *cfg = memoryAllocate(sizeof(node_manager_config_t));

    *cfg = (node_manager_config_t) {
        .config_file = config_file, .node_map = map_node_t_with_capacity(kNodeMapCap), .chains = vec_chains_t_init()};
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
        // LOGD("NodeManager: destroying tunnel %s",node->name);
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
