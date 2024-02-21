#pragma once

#include "config_file.h"
#include "hv/hmutex.h"
#include "node.h"

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

struct node_manager_s;

// you should use getTunnel, getNode can give you a uninitialized node in certain conditions
// you are responsible for checking / creating the chain if you use getNode!
node_t *getNode(hash_t hash_node_name);

tunnel_t *getTunnel(hash_t hash_node_name);


void runConfigFile(config_file_t *config_file);


struct node_manager_s * getNodeManager();
void setNodeManager(struct node_manager_s *state);
struct node_manager_s *createNodeManager();