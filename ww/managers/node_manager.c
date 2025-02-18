#include "node_manager.h"
#include "chain.h"
#include "global_state.h"
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

typedef struct node_manager_config_s
{
    config_file_t *config_file;
    map_node_t     node_map;

} node_manager_config_t;

#define i_type vec_configs_t         // NOLINT
#define i_key  node_manager_config_t // NOLINT
#include "stc/vec.h"

typedef struct node_manager_s
{
    vec_configs_t configs;
} node_manager_t;

static node_manager_t *state;

// void nodemanagerRunNode(node_manager_config_t *cfg, node_t *n1, uint8_t chain_index)
// {
//     if (n1 == NULL)
//     {
//         LOGF("Node Map Failure: please check the graph");
//         exit(1);
//     }

//     if (n1->hash_next != 0)
//     {
//         node_t *n2 = nodemanagerGetNodeInstance(cfg, n1->hash_next);

//         if (n2->instance == NULL)
//         {
//             nodemanagerRunNode(cfg, n2, chain_index + 1);
//         }

//         LOGD("NodeManager: starting node \"%s\"", n1->name);
//         n1->instance = n1->createHandle(n1);

//         if (n1->instance == NULL)
//         {
//             LOGF("NodeManager: node startup failure: node (\"%s\") create() returned NULL handle", n1->name);
//             exit(1);
//         }

//         memoryCopy((uint8_t *) &(n1->instance->chain_index), &chain_index, sizeof(uint8_t));

//         tunnelBind(n1->instance, n2->instance);
//     }
//     else
//     {
//         LOGD("NodeManager: starting node \"%s\"", n1->name);
//         n1->instance = n1->createHandle(n1);
//         atomic_thread_fence(memory_order_release);
//         if (n1->instance == NULL)
//         {
//             LOGF("NodeManager: node startup failure: node (\"%s\") create() returned NULL handle", n1->name);
//             exit(1);
//         }
//         memoryCopy((uint8_t *) &(n1->instance->chain_index), &chain_index, sizeof(uint8_t));
//     }
// }

static void runNodes(node_manager_config_t *cfg)
{
    enum
    {
        kMaxTarraySize = 512
    };

    tunnel_t *t_starters_array[kMaxTarraySize] = {0};
    tunnel_t *t_array[kMaxTarraySize]          = {0};

    int tunnels_count         = 0;
    int starter_tunnels_count = 0;
    {
        int index          = 0;
        int index_starters = 0;
        c_foreach(p1, map_node_t, cfg->node_map)
        {
            node_t *n1 = p1.ref->second;
            assert(n1 != NULL && n1->instance == NULL);
            t_array[index++] = n1->instance = n1->createHandle(n1);

            if (n1->instance == NULL)
            {
                LOGF("NodeManager: node startup failure: node (\"%s\") create() returned NULL handle", n1->name);
                exit(1);
            }

            if (nodeHasFlagChainHead(n1))
            {
                t_starters_array[index_starters++] = n1->instance;
            }
            if (index == kMaxTarraySize + 1)
            {
                LOGF("NodeManager: too many nodes in config");
                exit(1);
            }
        }
        tunnels_count         = index;
        starter_tunnels_count = index_starters;
    }

    if (tunnels_count == 0)
    {
        LOGW("NodeManager:  0 nodes in config");
        return;
    }

    tunnel_t *t_array_cpy[kMaxTarraySize];
    memoryCopy(t_array_cpy, t_array, sizeof(t_array_cpy));

    {
        for (int i = 0; i < tunnels_count; i++)
        {
            tunnel_t *tunnel = t_array[i];

            if (tunnel == NULL || ! nodeHasFlagChainHead(tunnelGetNode(tunnel)))
            {
                continue;
            }

            tunnel_chain_t *tc = tunnelchainCreate(getWorkersCount());
            tunnel->onChain(tunnel, tc);

            tunnelchainFinalize(tc);

            for (int cti = 0; cti < tc->tunnels.len; cti++)
            {
                for (int ti = 0; ti < tunnels_count; ti++)
                {
                    if (t_array[ti] == tc->tunnels.tuns[cti])
                    {
                        t_array[ti] = NULL;
                        break;
                    }
                }
            }
        }
    }

    {
        for (int i = 0; i < starter_tunnels_count; i++)
        {
            tunnel_t *tunnel = t_starters_array[i];

            if (tunnel == NULL)
            {
                continue;
            }

            tunnel_array_t ta         = {0};
            uint16_t       index      = 0;
            uint16_t       mem_offset = 0;
            tunnel->onIndex(tunnel, &ta, &index, &mem_offset);
            tunnelGetChain(tunnel)->tunnels = ta;

            for (int cti = 0; cti < ta.len; cti++)
            {
                for (int ti = 0; ti < starter_tunnels_count; ti++)
                {
                    if (t_starters_array[ti] == ta.tuns[cti])
                    {
                        t_starters_array[ti] = NULL;
                        break;
                    }
                }
            }
        }
    }
    {
        for (int i = 0; i < tunnels_count; i++)
        {
            if (t_array_cpy[i]->chain == NULL && ! (t_array_cpy[i]->node->flags & kNodeFlagNoChain))
            {
                LOGF("NodeManager: node startup failure: node (\"%s\") is not chained", t_array_cpy[i]->node->name);
                exit(1);
            }
        }
    }
    {
        for (int i = 0; i < tunnels_count; i++)
        {
            assert(t_array_cpy[i] != NULL);
            t_array_cpy[i]->onPrepair(t_array_cpy[i]);
        }
    }
    {
        for (int i = 0; i < tunnels_count; i++)
        {
            assert(t_array_cpy[i] != NULL);
            tunnel_t *tunnel = t_array_cpy[i];
            tunnel->onStart(tunnel);
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
            node_t *n2 = nodemanagerGetNodeInstance(cfg, n1->hash_next);
            if (n2 == NULL)
            {
                LOGF("Node Map Failure: Error in config file!  (path: %s)  (name: %s)", cfg->config_file->file_path,cfg->config_file->name);
                LOGF("Node Map Failure: node \"%s\" could not find it's next node \"%s\"", n1->name, n1->next);
                exit(1);
            }
            n1 = n2;
            if (c > 200)
            {
                LOGF("Node Map Failure: circular reference deteceted");
                exit(1);
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
        exit(1);
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
        exit(1);
    }

    if (! getStringFromJsonObject(&(node_type), node_json, "type"))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes[x]->type (string field) was empty or invalid",
             cfg->config_file->file_path);
        exit(1);
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
        exit(1);
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
        exit(1);
    }
    map_node_t_insert(map, new_node->hash_name, new_node);
}

node_t *nodemanagerGetNodeInstance(node_manager_config_t *cfg, hash_t hash_node_name)
{
    map_node_t_iter iter = map_node_t_find(&(cfg->node_map), hash_node_name);
    if (iter.ref == map_node_t_end(&(cfg->node_map)).ref)
    {
        return NULL;
    }
    return (iter.ref->second);
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

    node_manager_config_t cfg = {.config_file = config_file, .node_map = map_node_t_with_capacity(kNodeMapCap)};
    startInstallingConfigFile(&cfg);
    vec_configs_t_push(&(state->configs), cfg);
}

node_manager_t *nodemanagerCreate(void)
{
    assert(state == NULL);

    state = memoryAllocate(sizeof(node_manager_t));
    memorySet(state, 0, sizeof(node_manager_t));

    state->configs = vec_configs_t_with_capacity(kVecCap);

    return state;
}
