#pragma once

#include "basic_types.h"
#include "cJSON.h"
#include "config_file.h"
#include "node.h"
#include <stddef.h>

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

void                   runNode(node_t *n1, size_t chain_index);
node_t                *getNode(hash_t hash_node_name);
node_t                *newNode(void);
void                   registerNode(node_t *new_node, cJSON *node_settings);
void                   runConfigFile(config_file_t *config_file);
struct node_manager_s *getNodeManager(void);
void                   setNodeManager(struct node_manager_s *state);
struct node_manager_s *createNodeManager(void);
