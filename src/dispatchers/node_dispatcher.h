#pragma once

#include "node.h"
#include "utils/jsonutils.h"
#include "hv/hmutex.h"

typedef struct node_dispatcher_state_s
{
    hmutex_t mutex;
    nodes_file_t file;

} node_dispatcher_state_t;

void includeNodeFile(char *data_json);

node_t *getNode(hash_t hash);

node_array_t *getListenerNodes();

void parseNodes();

void initNodeDispatcher();
