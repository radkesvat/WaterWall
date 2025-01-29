#pragma once

#include "cJSON.h"
#include "config_file.h"
#include "node.h"
#include "wlibc.h"


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

void                   nodemanagerRunNode(node_manager_config_t *cfg, node_t *n1, uint8_t chain_index);
node_t                *nodemanagerGetNode(node_manager_config_t *cfg, hash_t hash_node_name);
node_t                *nodemanagerNewNode(void);
void                   nodemanagerRegisterNode(node_manager_config_t *cfg, node_t *new_node, cJSON *node_settings);
void                   nodemanagerRunConfigFile(config_file_t *config_file);
struct node_manager_s *nodemanagerGetState(void);
void                   nodemanagerSetState(struct node_manager_s *state);
struct node_manager_s *nodemanagerCreate(void);
