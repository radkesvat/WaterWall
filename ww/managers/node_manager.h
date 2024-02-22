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

void runNode(node_t *n1,size_t chain_index);
node_t *getNode(hash_t hash_node_name);



void runConfigFile(config_file_t *config_file);


struct node_manager_s * getNodeManager();
void setNodeManager(struct node_manager_s *state);
struct node_manager_s *createNodeManager();