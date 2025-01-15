#pragma once

#include "wlibc.h"
#include "cJSON.h"
#include "config_file.h"
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
struct node_manager_config_s;
typedef struct node_manager_config_s node_manager_config_t;

void                   runNode(node_manager_config_t *cfg, node_t *n1, uint8_t chain_index);
node_t                *getNode(node_manager_config_t *cfg, hash_t hash_node_name);
node_t                *newNode(void);
void                   registerNode(node_manager_config_t *cfg, node_t *new_node, cJSON *node_settings);
void                   runConfigFile(config_file_t *config_file);
struct node_manager_s *getNodeManager(void);
void                   setNodeManager(struct node_manager_s *state);
struct node_manager_s *createNodeManager(void);
