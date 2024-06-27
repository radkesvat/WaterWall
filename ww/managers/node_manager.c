#include "node_manager.h"
#include "basic_types.h"
#include "cJSON.h"
#include "config_file.h"
#include "library_loader.h"
#include "loggers/core_logger.h"
#include "node.h"
#include "stc/common.h"
#include "tunnel.h"
#include "utils/hashutils.h"
#include "utils/jsonutils.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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

void runNode(node_manager_config_t *cfg, node_t *n1, uint8_t chain_index)
{
    if (n1 == NULL)
    {
        LOGF("Node Map Failure: please check the graph");
        exit(1);
    }
    if (n1->hash_next != 0)
    {
        node_t *n2 = getNode(cfg, n1->hash_next);

        if (n2->instance == NULL)
        {
            runNode(cfg, n2, chain_index + 1);
        }

        LOGD("NodeManager: starting node \"%s\"", n1->name);
        n1->instance_context.chain_index = chain_index;
        n1->instance                     = n1->lib->createHandle(&(n1->instance_context));
        atomic_thread_fence(memory_order_release);
        if (n1->instance == NULL)
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") create() returned NULL handle", n1->name);
            exit(1);
        }

        memcpy((uint8_t *) &(n1->instance->chain_index), &chain_index, sizeof(uint8_t));

        chain(n1->instance, n2->instance);
    }
    else
    {
        LOGD("NodeManager: starting node \"%s\"", n1->name);
        n1->instance_context.chain_index = chain_index;
        n1->instance                     = n1->lib->createHandle(&(n1->instance_context));
        atomic_thread_fence(memory_order_release);
        if (n1->instance == NULL)
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") create() returned NULL handle", n1->name);
            exit(1);
        }
        memcpy((uint8_t *) &(n1->instance->chain_index), &chain_index, sizeof(uint8_t));
    }
}

static void runNodes(node_manager_config_t *cfg)
{
begin:;
    c_foreach(p1, map_node_t, cfg->node_map)
    {
        node_t *n1 = p1.ref->second;
        if (n1 != NULL && n1->instance == NULL && n1->route_starter == true)
        {
            runNode(cfg, n1, 0);
            goto begin;
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
            node_t *n2 = getNode(cfg, n1->hash_next);
            n1         = n2;
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

        bool found = false;
        c_foreach(n2, map_node_t, cfg->node_map)
        {
            if (next_hash == n2.ref->second->hash_name)
            {
                ++(n2.ref->second->refrenced);
                if (n2.ref->second->refrenced > 1)
                {
                    LOGF("Node Map Failure: no more than 1 node can be chained to node (\"%s\")", n2.ref->second->name);
                    exit(1);
                }
                // LOGD("%-17s -> %s", n1.ref->second->name, n2.ref->second->name);

                found = true;
            }
        }
        if (! found)
        {
            LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", n1.ref->second->name,
                 n1.ref->second->next);
            exit(1);
        }
    }
    {
        bool found = false;
        c_foreach(n1, map_node_t, cfg->node_map)
        {
            if (n1.ref->second->route_starter)
            {
                found                         = true;
                n1.ref->second->route_starter = true;
            }
        }
        if (! found)
        {
            LOGW("NodeMap: detecetd 0 chainhead nodes, the");
        }
    }
}

void registerNode(node_manager_config_t *cfg, node_t *new_node, cJSON *node_settings)
{
    new_node->hash_name = CALC_HASH_BYTES(new_node->name, strlen(new_node->name));
    new_node->hash_type = CALC_HASH_BYTES(new_node->type, strlen(new_node->type));
    if (new_node->next)
    {
        new_node->hash_next = CALC_HASH_BYTES(new_node->next, strlen(new_node->next));
    }
    // load lib
    tunnel_lib_t lib = loadTunnelLibByHash(new_node->hash_type);
    if (lib.hash_name == 0)
    {
        LOGF("NodeManager: node creation failure: library \"%s\" (hash: %lx) could not be loaded ", new_node->type,
             new_node->hash_type);
        exit(1);
    }
    else
    {
        LOGD("%-18s: library \"%s\" loaded successfully", new_node->name, new_node->type);
    }
    new_node->metadata = lib.getMetadataHandle();
    if ((new_node->metadata.flags & kNodeFlagChainHead) == kNodeFlagChainHead)
    {
        new_node->route_starter = true;
    }
    struct tunnel_lib_s *heap_lib = malloc(sizeof(struct tunnel_lib_s));
    memset(heap_lib, 0, sizeof(struct tunnel_lib_s));
    *heap_lib     = lib;
    new_node->lib = heap_lib;

    node_instance_context_t new_node_ctx = {0};

    new_node_ctx.node_json           = NULL;
    new_node_ctx.node_settings_json  = node_settings;
    new_node_ctx.node                = new_node;
    new_node_ctx.node_manager_config = cfg;

    new_node->instance_context = new_node_ctx;

    map_node_t *map = &(cfg->node_map);

    if (map_node_t_contains(map, new_node->hash_name))
    {
        LOGF("NodeManager: duplicate node \"%s\" (hash: %lx) ", new_node->name, new_node->hash_name);
        exit(1);
    }
    map_node_t_insert(map, new_node->hash_name, new_node);
}

node_t *getNode(node_manager_config_t *cfg, hash_t hash_node_name)
{
    map_node_t_iter iter = map_node_t_find(&(cfg->node_map), hash_node_name);
    if (iter.ref == map_node_t_end(&(cfg->node_map)).ref)
    {
        return NULL;
    }
    return (iter.ref->second);
}

node_t *newNode(void)
{
    node_t *new_node = malloc(sizeof(node_t));
    memset(new_node, 0, sizeof(node_t));
    return new_node;
}

static void startParsingFile(node_manager_config_t *cfg)
{
    cJSON *nodes_json = cfg->config_file->nodes;
    cJSON *node_json  = NULL;
    cJSON_ArrayForEach(node_json, nodes_json)
    {
        node_t *new_node = newNode();
        if (! getStringFromJsonObject(&(new_node->name), node_json, "name"))
        {
            LOGF("JSON Error: config file \"%s\" -> nodes[x]->name (string field) was empty or invalid",
                 cfg->config_file->file_path);
            exit(1);
        }

        if (! getStringFromJsonObject(&(new_node->type), node_json, "type"))
        {
            LOGF("JSON Error: config file \"%s\" -> nodes[x]->type (string field) was empty or invalid",
                 cfg->config_file->file_path);
            exit(1);
        }
        getStringFromJsonObject(&(new_node->next), node_json, "next");
        getIntFromJsonObjectOrDefault((int *) &(new_node->version), node_json, "version", 0);
        registerNode(cfg, new_node, cJSON_GetObjectItemCaseSensitive(node_json, "settings"));
    }
    cycleProcess(cfg);
    pathWalk(cfg);
    runNodes(cfg);
}

struct node_manager_s *getNodeManager(void)
{
    return state;
}
void setNodeManager(struct node_manager_s *new_state)
{
    assert(state == NULL);
    state = new_state;
}

void runConfigFile(config_file_t *config_file)
{

    node_manager_config_t cfg = {.config_file = config_file, .node_map = map_node_t_with_capacity(kNodeMapCap)};
    startParsingFile(&cfg);
    vec_configs_t_push(&(state->configs), cfg);
}

node_manager_t *createNodeManager(void)
{
    assert(state == NULL);

    state = malloc(sizeof(node_manager_t));
    memset(state, 0, sizeof(node_manager_t));

    state->configs = vec_configs_t_with_capacity(kVecCap);

    return state;
}
