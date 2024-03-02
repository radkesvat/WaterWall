#include "node_manager.h"
#include "loggers/core_logger.h"
#include "utils/jsonutils.h"
#include "utils/hashutils.h"
#include "config_file.h"
#include "library_loader.h"

#define i_type map_node_t
#define i_key hash_t
#define i_val node_t *

#include "stc/hmap.h"

typedef struct node_manager_s
{
    config_file_t *config_file;
    map_node_t node_map;

} node_manager_t;

static node_manager_t *state;

void runNode(node_t *n1, size_t chain_index)
{
    if (n1 == NULL)
    {
        LOGF("Node Map Failure: please check the graph");
        exit(1);
    }
    if (n1->hash_next != 0)
    {
        node_t *n2 = getNode(n1->hash_next);

        if (n2->instance == NULL)
        {
            runNode(n2, chain_index + 1);
        }

        LOGD("Starting node \"%s\"", n1->name);
        n1->instance_context.chain_index = chain_index;
        n1->instance = n1->lib->creation_proc(&(n1->instance_context));
        if (n1->instance == NULL)
        {
            LOGF("Node Startup Failure: node (\"%s\") create() returned NULL handle", n1->name);
            exit(1);
        }

        n1->instance->chain_index = chain_index;
        chain(n1->instance, n2->instance);
    }
    else
    {
        LOGD("Starting node \"%s\"", n1->name);
        n1->instance_context.chain_index = chain_index;
        n1->instance = n1->lib->creation_proc(&(n1->instance_context));
        if (n1->instance == NULL)
        {
            LOGF("Node Startup Failure: node (\"%s\") create() returned NULL handle", n1->name);
            exit(1);
        }
        n1->instance->chain_index = chain_index;

    }
}

static void runNodes()
{
    c_foreach(p1, map_node_t, state->node_map)
    {
        node_t *n1 = p1.ref->second;
        if (n1 != NULL && n1->instance == NULL && n1->route_starter == true)
            runNode(n1, 0);
    }
}

static void pathWalk()
{

    c_foreach(p1, map_node_t, state->node_map)
    {
        node_t *n1 = p1.ref->second;

        int c = 0;
        while (true)
        {
            if (n1->hash_next == 0)
                break;
            c++;
            node_t *n2 = getNode(n1->hash_next);
            n1 = n2;
            if (c > 200)
            {
                LOGF("Node Map Failure: circular reference deteceted");
                exit(1);
            }
        }
    }
}

static void cycleProcess()
{
    c_foreach(n1, map_node_t, state->node_map)
    {

        hash_t next_hash = n1.ref->second->hash_next;
        if (next_hash == 0)
            continue;

        bool found = false;
        c_foreach(n2, map_node_t, state->node_map)
        {
            if (next_hash == n2.ref->second->hash_name)
            {
                ++(n2.ref->second->refrenced);
                if (n2.ref->second->refrenced > 1)
                {
                    LOGF("Node Map Failure: no more than 1 node can be chained to node (\"%s\")", n2.ref->second->name);
                    exit(1);
                }
                LOGD("(\"%s\").next -> (\"%s\") ", n1.ref->second->name, n2.ref->second->name);

                found = true;
            }
        }
        if (!found)
        {
            LOGF("Node Map Failure: node (\"%s\")->next (\"%s\") not found", n1.ref->second->name, n1.ref->second->next);
            exit(1);
        }
    }
    {
        bool found = false;
        c_foreach(n1, map_node_t, state->node_map)
        {
            if (n1.ref->second->metadata.flags & TFLAG_ROUTE_STARTER == TFLAG_ROUTE_STARTER)
            {
                found = true;
                n1.ref->second->route_starter = true;
            }
        }
        if (!found)
        {
            LOGW("Node Map has detecetd 0 listener nodes...");
        }
    }
}

static void startParsingFiles()
{
    cJSON *nodes_json = state->config_file->nodes;
    cJSON *node_json = NULL;
    cJSON_ArrayForEach(node_json, nodes_json)
    {

        node_t *new_node = malloc(sizeof(node_t));
        memset(new_node, 0, sizeof(node_t));
        if (!getStringFromJsonObject(&(new_node->name), node_json, "name"))
        {
            LOGF("JSON Error: config file \"%s\" -> nodes[x]->name (string field) was empty or invalid", state->config_file->file_path);
            exit(1);
        }
        new_node->hash_name = calcHashLen(new_node->name, strlen(new_node->name));

        if (!getStringFromJsonObject(&(new_node->type), node_json, "type"))
        {
            LOGF("JSON Error: config file \"%s\" -> nodes[x]->type (string field) was empty or invalid", state->config_file->file_path);
            exit(1);
        }
        new_node->hash_type = calcHashLen(new_node->type, strlen(new_node->type));

        if (getStringFromJsonObject(&(new_node->next), node_json, "next"))
        {

            new_node->hash_next = calcHashLen(new_node->next, strlen(new_node->next));
        }
        int int_ver = 0;
        if (getIntFromJsonObject(&int_ver, node_json, "version"))
            new_node->version = int_ver;

        // load lib
        tunnel_lib_t lib = loadTunnelLibByHash(new_node->hash_type);
        if (lib.hash_name == 0)
        {
            LOGF("Node Creation Failure: library \"%s\" (hash: %lx) could not be loaded ", new_node->type,
                 new_node->hash_type);
            exit(1);
        }
        else
        {
            LOGD("\"%s\": library \"%s\" loaded successfully", new_node->name, new_node->type);
        }
        new_node->metadata = lib.getmetadata_proc();
        struct tunnel_lib_s *heap_lib = malloc(sizeof(struct tunnel_lib_s));
        memset(heap_lib, 0, sizeof(struct tunnel_lib_s));
        *heap_lib = lib;
        new_node->lib = heap_lib;



        cJSON *js_settings = cJSON_GetObjectItemCaseSensitive(node_json, "settings");

        node_instance_context_t new_node_ctx = {0};

        new_node_ctx.node_json = node_json;
        new_node_ctx.node_settings_json = js_settings;
        new_node_ctx.self_node_handle = new_node;
        new_node_ctx.self_file_handle = state->config_file;

        new_node->instance_context = new_node_ctx;
        map_node_t *map = &(state->node_map);

        if (map_node_t_contains(map, new_node->hash_name))
        {
            LOGF("Duplicate node \"%s\" (hash: %lx) ", new_node->name, new_node->hash_name);
        }
        map_node_t_insert(map, new_node->hash_name, new_node);
    }
    cycleProcess();
    pathWalk();
    runNodes();
}

node_t *getNode(hash_t hash_node_name)
{
    map_node_t_iter iter = map_node_t_find(&(state->node_map), hash_node_name);
    if (iter.ref == map_node_t_end(&(state->node_map)).ref)
        return NULL;
    return (iter.ref->second);
}

static tunnel_t *getTunnel(hash_t hash_node_name)
{
    map_node_t_iter iter = map_node_t_find(&(state->node_map), hash_node_name);
    if (iter.ref == map_node_t_end(&(state->node_map)).ref)
        return NULL;

    return (iter.ref->second)->instance;
}

struct node_manager_s *getNodeManager()
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
    state->config_file = config_file;
    startParsingFiles();
}

node_manager_t *createNodeManager()
{
    assert(state == NULL);

    state = malloc(sizeof(node_manager_t));
    memset(state, 0, sizeof(node_manager_t));
    state->node_map = map_node_t_with_capacity(50);
    return state;
}
