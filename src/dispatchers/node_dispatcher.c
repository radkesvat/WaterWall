#include "node_dispatcher.h"
#include "loggers/core_logger.h"
#include "utils/jsonutils.h"

static node_map_t *all_nodes = NULL;
static node_array_t *listener_nodes = NULL;

void initNodeDispatcher()
{
    if (all_nodes != NULL)
    {
        LOGF("initSocketDispatcher called twice!");
        exit(1);
    }
    all_nodes = malloc(sizeof(node_map_t));
    *all_nodes = node_map_t_with_capacity(50);
    listener_nodes = malloc(sizeof(node_array_t));
    *listener_nodes = node_array_t_with_capacity(50);
}

static void includeNode(const cJSON *node_json)
{
    cJSON *type_name = cJSON_GetObjectItemCaseSensitive(node_json, "type");
    cJSON *next_name = cJSON_GetObjectItemCaseSensitive(node_json, "next");
    cJSON *settings = cJSON_GetObjectItemCaseSensitive(node_json, "settings");
    node_t *node = malloc(sizeof(node_t));

    if (!getStringFromJsonObject(&(node->name), node_json, "name"))
    {
        LOGF("JSON ERROR: ConfigFile->nodes[x]->name (string field) : The data was empty or invalid.");
        exit(1);
    }

    if (!getStringFromJsonObject(&(node->type_name), node_json, "type"))
    {
        LOGF("JSON ERROR: ConfigFile->nodes[x]->type (string field) : The data was empty or invalid.");
        exit(1);
    }

    if (!getStringFromJsonObject(&(node->next_name), node_json, "next"))
    {
        LOGF("JSON ERROR: ConfigFile->nodes[x]->next (string field) : The data was empty or invalid.");
        exit(1);
    }

    if ((cJSON_IsObject(settings) && (settings->valuestring != NULL)))
    {
        node->settings = settings;
    }
}

void includeNodeFile(char *data_json)
{
    cJSON *json = cJSON_Parse(data_json);
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "name");

    if (!(cJSON_IsString(name) && (name->valuestring != NULL)))
    {
        LOGW("JSON Warning: ConfigFile->name (string field) : The data was empty or invalid.");
    }

    const cJSON *author = cJSON_GetObjectItemCaseSensitive(json, "author");

    if (!(cJSON_IsString(author) && (author->valuestring != NULL)))
    {
        LOGW("JSON Warning: ConfigFile->author (string field) : The data was empty or invalid.");
    }

    const cJSON *minimum_version = cJSON_GetObjectItemCaseSensitive(json, "minimum_version");
    if (!(cJSON_IsNumber(minimum_version) && (minimum_version->valuedouble != 0)))
    {
        LOGW("JSON Warning: ConfigFile->minimum_version (number field) : The data was empty or invalid.");
    }

    const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(json, "nodes");
    if (!(cJSON_IsArray(nodes) && (nodes->child != NULL)))
    {
        LOGW("JSON Warning: ConfigFile->nodes (array field) : The data was empty or invalid.");
    }

    const cJSON *single_node = NULL;
    cJSON_ArrayForEach(single_node, nodes)
    {
        includeNode(single_node);
    }
}

void startParsingFiles(node_dispatcher_state_t *state);

void includeConfigFile(node_dispatcher_state_t *state, char *data_json)
{
    if (state->file != NULL)
    {
        LOGF("Please only include 1 file in core json, because multiple file parsing is not implemented yet.");
        exit(1);
    }
    state->file = malloc(sizeof(node_dispatcher_state_t));
    memset(state->file, 0, sizeof(node_dispatcher_state_t));

    
    config_file_t *file = state->file;
    cJSON *json = cJSON_Parse(data_json);


    
}

node_dispatcher_state_t *createNodeDispatcher()
{
    node_dispatcher_state_t *state = malloc(sizeof(node_dispatcher_state_t));
    memset(state, 0, sizeof(node_dispatcher_state_t));
    return state;
}
