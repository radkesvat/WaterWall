#pragma once

#include "config_file.h"
#include "hv/hmutex.h"
//  configFile:
//      info
//
//      Node1:
//              info
//              tunnel1
//      Node2:
//              info
//              tunnel2
//      Node3:
//              info
//              tunnel3
//
//
// * Nodes inside each file are isaloted.

typedef struct node_dispatcher_state_s
{
    config_file_t *file;
    map_node_t map;

} node_dispatcher_state_t;

// you should use getTunnel, getNode can give you a uninitialized node in certain conditions
// you are responsible for checking / creating the chain if you use getNode!
node_t *getNode(node_dispatcher_state_t *state, hash_t hash_node_name);

tunnel_t *getTunnel(node_dispatcher_state_t* state,hash_t hash_tunnel_name);

// private :

void startParsingFiles(node_dispatcher_state_t *state);
void includeConfigFile(node_dispatcher_state_t *state, char *data_json);

node_dispatcher_state_t *createNodeDispatcher();
