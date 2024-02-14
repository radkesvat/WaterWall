#include "node_dispatcher.h"
#include "hv/hlog.h"

static node_map_t *all_nodes = NULL;
static node_array_t *listener_nodes = NULL;

void initNodeDispatcher()
{
    if (all_nodes != NULL)
    {
        LOGF("initSocketDispatcher called twice!", NULL);
        exit(1);
    }
    all_nodes = malloc(sizeof(node_map_t));
    *all_nodes = node_map_t_with_capacity(50);
    listener_nodes = malloc(sizeof(node_array_t));
    *listener_nodes = node_array_t_with_capacity(50);
}

static void includeNode(const cJSON *node_json)
{
    cJSON *name = cJSON_GetObjectItemCaseSensitive(node_json, "name");
    cJSON *type_name = cJSON_GetObjectItemCaseSensitive(node_json, "type");
    cJSON *next_name = cJSON_GetObjectItemCaseSensitive(node_json, "next");
    cJSON *settings = cJSON_GetObjectItemCaseSensitive(node_json, "settings");
    node_t *node = malloc(sizeof(node_t));

    if (!(cJSON_IsString(name) && (name->valuestring != NULL)))
    {
        LOGF("JSON ERROR: ConfigFile->nodes[x]->name (string field) : The data was empty or invalid.", NULL);
        exit(1);
    }

    node->name = malloc(strlen(name->valuestring) + 1);
    strcpy(node->name, name->valuestring);

    if (!(cJSON_IsString(type_name) && (type_name->valuestring != NULL)))
    {
        LOGF("JSON ERROR: ConfigFile->nodes[x]->type (string field) : The data was empty or invalid.", NULL);
        exit(1);
    }

    node->type_name = malloc(strlen(type_name->valuestring) + 1);
    strcpy(node->type_name, type_name->valuestring);

    if ((cJSON_IsString(next_name) && (next_name->valuestring != NULL)))
    {

        node->next_name = malloc(strlen(next_name->valuestring) + 1);
        strcpy(node->next_name, next_name->valuestring);
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
        LOGW("JSON Warning: ConfigFile->name (string field) : The data was empty or invalid.", NULL);
    }

    const cJSON *author = cJSON_GetObjectItemCaseSensitive(json, "author");
    if (!(cJSON_IsString(author) && (author->valuestring != NULL)))
    {
        LOGW("JSON Warning: ConfigFile->author (string field) : The data was empty or invalid.", NULL);
    }

    const cJSON *minimum_version = cJSON_GetObjectItemCaseSensitive(json, "minimum_version");
    if (!(cJSON_IsNumber(minimum_version) && (minimum_version->valuedouble != 0)))
    {
        LOGW("JSON Warning: ConfigFile->minimum_version (number field) : The data was empty or invalid.", NULL);
    }

    const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(json, "nodes");
    if (!(cJSON_IsArray(nodes) && (nodes->child != NULL)))
    {
        LOGW("JSON Warning: ConfigFile->nodes (array field) : The data was empty or invalid.", NULL);
    }

    const cJSON *single_node = NULL;
    cJSON_ArrayForEach(single_node, nodes)
    {
        includeNode(single_node);
    }
}

node_t *getNode(hash_t hash)
{
    return NULL;
}

node_array_t *getListenerNodes()
{
    return listener_nodes;
}

void parseNodes()
{
}
