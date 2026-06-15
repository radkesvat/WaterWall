#pragma once

/*
 * Node manager APIs for parsing node configs, building chains, and lifecycle.
 */

#include "cJSON.h"
#include "node_builder/config_file.h"
#include "node_builder/node_library.h"
#include "wlibc.h"
#include "worker.h"

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

/**
 * @brief Run one node in a config chain context.
 *
 * @param cfg Node manager config.
 * @param n1 Node to run.
 * @param chain_index Chain index.
 */
void nodemanagerRunNode(node_manager_config_t *cfg, node_t *n1, uint8_t chain_index);

/**
 * @brief Find a node in config by hashed name.
 *
 * @param cfg Node manager config.
 * @param hash_node_name Hashed node name.
 * @return node_t* Found node or NULL.
 */
node_t *nodemanagerGetConfigNodeByHash(node_manager_config_t *cfg, hash_t hash_node_name);

/**
 * @brief Find a node in config by plain name.
 *
 * @param cfg Node manager config.
 * @param name Node name.
 * @return node_t* Found node or NULL.
 */
node_t *nodemanagerGetConfigNodeByName(node_manager_config_t *cfg, const char *name);

/**
 * @brief Allocate and zero-initialize a new node object.
 *
 * @return node_t* Allocated node.
 */
node_t *nodemanagerNewNode(void);

/**
 * @brief Build a node instance from one node JSON object.
 *
 * @param cfg Node manager config.
 * @param node_json Node JSON object.
 */
void nodemanagerCreateNodeInstance(node_manager_config_t *cfg, cJSON *node_json);

/**
 * @brief Run a parsed config file through node manager pipeline.
 *
 * @param config_file Parsed config file.
 */
void nodemanagerRunConfigFile(config_file_t *config_file);

/**
 * @brief Stop one node runtime instance without destroying owned memory.
 *
 * @param node Node object.
 */
void nodemanagerStopNode(node_t *node);

/**
 * @brief Stop all chained tunnel runtime instances in one config.
 *
 * @param cfg Config object.
 */
void nodemanagerStopConfig(node_manager_config_t *cfg);

/**
 * @brief Stop all loaded chained tunnel runtime instances.
 */
void nodemanagerStop(void);

/**
 * @brief Stop worker-local resources owned by all loaded tunnel instances.
 *
 * Must be called on the worker identified by @p wid before that worker's loop
 * and pools are destroyed.
 *
 * @param wid Worker whose local tunnel resources should be stopped.
 */
void nodemanagerStopWorkerResources(wid_t wid);

/**
 * @brief Get global node manager state pointer.
 *
 * @return struct node_manager_s* Current global state.
 */
struct node_manager_s *nodemanagerGetState(void);

/**
 * @brief Set global node manager state pointer.
 *
 * @param state External state object.
 */
void nodemanagerSetState(struct node_manager_s *state);

/**
 * @brief Create and initialize global node manager state.
 *
 * @return struct node_manager_s* Created manager state.
 */
struct node_manager_s *nodemanagerCreate(void);

/**
 * @brief Destroy one node and its runtime instance.
 *
 * @param node Node object.
 */
void nodemanagerDestroyNode(node_t *node);

// stop workers that running config files before calling this
/**
 * @brief Destroy one node-manager config and all owned resources.
 *
 * @param cfg Config object.
 */
void nodemanagerDestroyConfig(node_manager_config_t *cfg);

// stop workers that running config files before calling this
/**
 * @brief Destroy global node manager and all loaded configs.
 */
void nodemanagerDestroy(void);
