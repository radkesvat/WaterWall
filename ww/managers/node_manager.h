#pragma once

/*
 * Node manager APIs for parsing node configs, building chains, and lifecycle.
 */

#include "cJSON.h"
#include "node_builder/config_file.h"
#include "node_builder/node_library.h"
#include "startup.h"
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
 * @brief Build a top-level config node from one node JSON object.
 *
 * This API is only valid while NodeManager is loading the config's declared
 * nodes. A tunnel that owns an internal child node should keep that child
 * private, configure it with nodeConfigureChild(), and manage its tunnel
 * lifecycle itself. Internal children do not belong in the config node map.
 *
 * @param cfg Node manager config.
 * @param node_json Node JSON object.
 */
void nodemanagerCreateNodeInstance(node_manager_config_t *cfg, cJSON *node_json);

/**
 * @brief Construct one top-level or private child tunnel and validate its callback table.
 *
 * A constructor may return NULL for an ordinary allocation/configuration
 * failure. A non-NULL tunnel with a missing flow or lifecycle callback violates
 * the tunnel contract and terminates startup before onChain can run.
 *
 * @param node Node whose createHandle is invoked.
 * @return tunnel_t* Constructed, callback-complete tunnel, or NULL on normal
 *         construction failure.
 */
tunnel_t *nodemanagerCreateTunnelInstance(node_t *node);

/**
 * @brief Run a parsed config file through node manager pipeline.
 *
 * @param config_file Parsed config file.
 */
ww_startup_result_t nodemanagerRunConfigFile(config_file_t *config_file);

/**
 * @brief Stop all loaded chained tunnel runtime instances.
 */
void nodemanagerQuiesceRequest(const ww_lifecycle_context_t *context);
void nodemanagerQuiesceWorker(wid_t wid, const ww_lifecycle_context_t *context);
void nodemanagerQuiesceWait(const ww_lifecycle_context_t *context);
void nodemanagerStop(const ww_lifecycle_context_t *context);

/**
 * @brief Stop worker-local resources owned by all loaded tunnel instances.
 *
 * Must be called on the worker identified by @p wid before that worker's loop
 * and pools are destroyed.
 *
 * @param wid Worker whose local tunnel resources should be stopped.
 */
void nodemanagerStopWorkerResources(wid_t wid, const ww_lifecycle_context_t *context);

/* Internal worker task, exposed so the packet-line death contract can be
 * exercised against the production callback rather than a copied model. */
void nodemanagerInitializeLineOnTargetWorker(void *worker, void *tunnel, void *line, void *unused);

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
