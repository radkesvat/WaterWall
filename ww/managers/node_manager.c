#include "node_manager.h"
#include "loggers/core_logger.h"
#include "utils/jsonutils.h"
#include "utils/hashutils.h"
#include "config_file.h"

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

static void pathWalk()
{
}


static void startParsingFiles()
{
    cJSON *nodes_json = state->config_file->nodes;
    cJSON *node_json = NULL;
    cJSON_ArrayForEach(node_json, nodes_json)
    {

        node_t *node_instance = malloc(sizeof(node_t));
        memset(node_instance, 0, sizeof(node_t));
        if (!getStringFromJsonObject(&(node_instance->name), node_json, "name"))
        {
            LOGF("JSON Error: config file \"%s\" -> nodes[x]->name (string field) was empty or invalid", state->config_file->file_path);
            exit(1);
        }
        node_instance->hash_name = calcHashLen(node_instance->name, strlen(node_instance->name));

        if (!getStringFromJsonObject(&(node_instance->type), node_json, "type"))
        {
            LOGF("JSON Error: config file \"%s\" -> nodes[x]->type (string field) was empty or invalid", state->config_file->file_path);
            exit(1);
        }
        node_instance->hash_type = calcHashLen(node_instance->type, strlen(node_instance->type));

        if (getStringFromJsonObject(&(node_instance->next), node_json, "next"))
        {

            node_instance->hash_next = calcHashLen(node_instance->next, strlen(node_instance->next));
        }
        int int_ver = 0;
        if (getIntFromJsonObject(&int_ver, node_json, "version"))
            node_instance->version = int_ver;
        
        
    }
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
