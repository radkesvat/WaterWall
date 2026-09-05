/*
 * Builds node instances from config files and orchestrates tunnel chains.
 */

#include "node_manager.h"
#include "chain.h"
#include "global_state.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "net/node_layer_solver.h"
#include "node_builder/config_policy.h"
#include "utils/json_helpers.h"

enum
{
    kNmConfigsVectorCap = 8,
    kMaxNodesPerConfig  = 512
};

#define i_type map_node_t // NOLINT
#define i_key  hash_t     // NOLINT
#define i_val  node_t *   // NOLINT
#include "stc/hmap.h"

#define i_type vec_chains_t     // NOLINT
#define i_key  tunnel_chain_t * // NOLINT
#include "stc/vec.h"

typedef enum node_map_phase_e
{
    kNodeMapPhaseCollecting = 0,
    kNodeMapPhaseFrozen
} node_map_phase_t;

typedef struct node_manager_config_s
{
    config_file_t   *config_file;
    map_node_t       node_map;
    vec_chains_t     chains;
    node_map_phase_t node_map_phase;

} node_manager_config_t;

#define i_type vec_configs_t           // NOLINT
#define i_key  node_manager_config_t * // NOLINT
#include "stc/vec.h"

typedef struct node_manager_s
{
    vec_configs_t          configs;
    atomic_bool            quiesce_request_started;
    atomic_bool            quiesce_wait_started;
    atomic_bool            stop_started;
    ww_lifecycle_context_t stop_context;
    bool                   stop_context_set;
} node_manager_t;

static node_manager_t *nodemanager_gstate;

static const char *findMissingTunnelCallback(const tunnel_t *tunnel)
{
#define RETURN_MISSING_TUNNEL_CALLBACK(slot)                                                                           \
    if (tunnel->slot == NULL)                                                                                          \
    {                                                                                                                  \
        return #slot;                                                                                                  \
    }

    RETURN_MISSING_TUNNEL_CALLBACK(fnInitU)
    RETURN_MISSING_TUNNEL_CALLBACK(fnInitD)
    RETURN_MISSING_TUNNEL_CALLBACK(fnPayloadU)
    RETURN_MISSING_TUNNEL_CALLBACK(fnPayloadD)
    RETURN_MISSING_TUNNEL_CALLBACK(fnEstU)
    RETURN_MISSING_TUNNEL_CALLBACK(fnEstD)
    RETURN_MISSING_TUNNEL_CALLBACK(fnFinU)
    RETURN_MISSING_TUNNEL_CALLBACK(fnFinD)
    RETURN_MISSING_TUNNEL_CALLBACK(fnPauseU)
    RETURN_MISSING_TUNNEL_CALLBACK(fnPauseD)
    RETURN_MISSING_TUNNEL_CALLBACK(fnResumeU)
    RETURN_MISSING_TUNNEL_CALLBACK(fnResumeD)
    RETURN_MISSING_TUNNEL_CALLBACK(onChain)
    RETURN_MISSING_TUNNEL_CALLBACK(onIndex)
    RETURN_MISSING_TUNNEL_CALLBACK(onPrepare)
    RETURN_MISSING_TUNNEL_CALLBACK(onStart)
    RETURN_MISSING_TUNNEL_CALLBACK(onQuiesceRequest)
    RETURN_MISSING_TUNNEL_CALLBACK(onWorkerQuiesce)
    RETURN_MISSING_TUNNEL_CALLBACK(onQuiesceWait)
    RETURN_MISSING_TUNNEL_CALLBACK(onWorkerStop)
    RETURN_MISSING_TUNNEL_CALLBACK(onStop)
    RETURN_MISSING_TUNNEL_CALLBACK(onDestroy)

#undef RETURN_MISSING_TUNNEL_CALLBACK

    return NULL;
}

tunnel_t *nodemanagerCreateTunnelInstance(node_t *node)
{
    if (node == NULL || node->createHandle == NULL)
    {
        LOGF("NodeManager: node instance construction received an invalid node or createHandle");
        startupFailureRecord(1);
        return NULL;
    }

    tunnel_t *tunnel = node->createHandle(node);
    if (tunnel == NULL)
    {
        return NULL;
    }

    const char *missing_callback = findMissingTunnelCallback(tunnel);
    if (missing_callback != NULL)
    {
        LOGF("NodeManager: node (\"%s\") returned an instance with NULL callback \"%s\"",
             configPolicyDiagnostic(node->name),
             missing_callback);
        tunnelDestroy(tunnel);
        startupFailureRecord(1);
        return NULL;
    }

    return tunnel;
}

/**
 * @brief Create tunnel instances for all nodes in a config.
 *
 * @param cfg Node manager config.
 * @param t_array Output array of created tunnels.
 * @param max_size Maximum supported tunnels.
 * @return int Number of created tunnel instances.
 */
static int createTunnelInstances(node_manager_config_t *cfg, tunnel_t **t_array, int max_size)
{
    if (cfg->node_map_phase != kNodeMapPhaseFrozen)
    {
        LOGF("NodeManager: config node map must be frozen before tunnel creation");
        startupFailureRecord(1);
        return -1;
    }

    int index = 0;

    c_foreach(p1, map_node_t, cfg->node_map)
    {
        node_t *n1 = p1.ref->second;
        assert(n1 != NULL && n1->instance == NULL);

        if (index >= max_size)
        {
            LOGF("NodeManager: too many nodes in config");
            startupFailureRecord(1);
            return -1;
        }

        t_array[index++] = n1->instance = nodemanagerCreateTunnelInstance(n1);
        if (UNLIKELY(startupFailurePending() || n1->instance == NULL))
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") create() returned NULL handle",
                 configPolicyDiagnostic(n1->name));
            startupFailureRecord(1);
            return -1;
        }
    }
    return index;
}

/**
 * @brief Assign chain objects to tunnel instances that are not chained yet.
 *
 * @param t_array Tunnel instance array.
 * @param tunnels_count Number of tunnel instances.
 */
static void assignChainsToTunnels(tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        tunnel_t *tunnel = t_array[i];
        if (tunnel->chain == NULL)
        {
            tunnel_chain_t *tc = tunnelchainCreate(getWorkersCount());
            if (UNLIKELY(tc == NULL))
            {
                LOGF("NodeManager: failed to allocate tunnel-chain metadata for node \"%s\"",
                     configPolicyDiagnostic(tunnel->node->name));
                startupFailureRecord(1);
                return;
            }
            tunnel->onChain(tunnel, tc);
            if (UNLIKELY(startupFailurePending()))
            {
                return;
            }
        }
    }
}

/**
 * @brief Finalize chains, store them, and compute per-tunnel line offsets.
 *
 * @param cfg Node manager config.
 * @param t_array Tunnel instance array.
 * @param tunnels_count Number of tunnel instances.
 */
static void finalizeTunnelChains(node_manager_config_t *cfg, tunnel_t **t_array, int tunnels_count)
{
    for (int i = 0; i < tunnels_count; i++)
    {
        tunnel_t       *tunnel = t_array[i];
        tunnel_chain_t *chain  = tunnelGetChain(tunnel);
        if (chain == NULL)
        {
            continue;
        }

        if (tunnelchainIsFinalized(chain) == false)
        {
            /*
             * Validation has already driven solve/onSolvedTopology to a fixed
             * point. Indexing is a one-shot layout phase over immutable
             * topology; onIndex callbacks may consume the final layer cache.
             */
            if (UNLIKELY(! chain->layer_solution_ready))
            {
                LOGF("NodeManager: tunnel chain has not been validated/solved before finalization");
                startupFailureRecord(1);
                return;
            }

            uint16_t index      = 0;
            uint32_t mem_offset = 0;
            for (int tci = 0; tci < chain->tunnels.len; tci++)
            {
                tunnel_t *tunnel_in_chain = chain->tunnels.tuns[tci];
                if (UNLIKELY(tunnel_in_chain->lstate_size > UINT32_MAX - mem_offset))
                {
                    LOGF("NodeManager: total line-state size overflow while indexing chain");
                    startupFailureRecord(1);
                    return;
                }

                uint32_t expected_offset = mem_offset + tunnel_in_chain->lstate_size;
                tunnel_in_chain->onIndex(tunnel_in_chain, index++, &mem_offset);
                if (UNLIKELY(mem_offset != expected_offset))
                {
                    LOGF("NodeManager: invalid line-state offset after indexing node (\"%s\")",
                         configPolicyDiagnostic(tunnel_in_chain->node->name));
                    startupFailureRecord(1);
                    return;
                }
            }
            if (UNLIKELY(mem_offset != chain->sum_line_state_size))
            {
                LOGF("NodeManager: indexed line-state size does not match chain total");
                startupFailureRecord(1);
                return;
            }

            tunnelchainFinalize(chain);
            if (UNLIKELY(vec_chains_t_push(&cfg->chains, chain) == NULL))
            {
                LOGF("NodeManager: failed to publish finalized tunnel chain");
                startupFailureRecord(1);
                return;
            }
        }
    }
}

/**
 * @brief Validate resulting tunnel topology, capability constraints, and layer groups.
 *
 * @param t_array Tunnel instance array.
 * @param tunnels_count Number of tunnel instances.
 */
static void validateTunnelChains(tunnel_t **t_array, int tunnels_count)
{
    tunnel_chain_t *unique_chains[kMaxNodesPerConfig] = {0};
    int             unique_chain_count                = 0;

    for (int i = 0; i < tunnels_count; i++)
    {
        tunnel_t *t = t_array[i];
        assert(t != NULL && t->node != NULL);

        if (t->chain == NULL)
        {
            LOGF("NodeManager: node startup failure: node (\"%s\") is not in an assembled chain",
                 configPolicyDiagnostic(t->node->name));
            startupFailureRecord(1);
            return;
        }

        tunnel_chain_t *c     = t->chain;
        bool            found = false;
        for (int j = 0; j < unique_chain_count; j++)
        {
            if (unique_chains[j] == c)
            {
                found = true;
                break;
            }
        }
        if (! found)
        {
            assert(unique_chain_count < kMaxNodesPerConfig);
            unique_chains[unique_chain_count++] = c;
        }
    }

    for (int j = 0; j < unique_chain_count; j++)
    {
        tunnel_chain_t *chain = unique_chains[j];

        /*
         * A layer-dependent hook may materialize private tunnels, invalidating
         * the current edge solution. Re-solve after each reported mutation so
         * no later hook observes stale domains. Indexing begins only after this
         * phase reaches a fixed point.
         */
        for (uint16_t topology_changes = 0;;)
        {
            node_layer_solver_status_t status = {0};
            if (! nodeLayerSolveChain(chain, &status))
            {
                LOGF("NodeManager: node startup failure: %s", configPolicyDiagnostic(status.message));
                startupFailureRecord(1);
                return;
            }

            bool topology_changed = false;
            for (uint16_t i = 0; i < chain->tunnels.len; ++i)
            {
                tunnel_t *tunnel = chain->tunnels.tuns[i];
                assert(tunnel != NULL);

                if (tunnel->onSolvedTopology != NULL && tunnel->onSolvedTopology(tunnel, chain))
                {
                    topology_changed = true;
                    break;
                }
                if (UNLIKELY(startupFailurePending()))
                {
                    return;
                }
            }

            if (! topology_changed)
            {
                break;
            }
            if (UNLIKELY(startupFailurePending()))
            {
                return;
            }

            topology_changes++;
            if (topology_changes >= kMaxChainLen)
            {
                LOGF("NodeManager: solved-topology expansion did not converge");
                startupFailureRecord(1);
                return;
            }
        }
    }
}

typedef void (*TunnelLifecycleFn)(tunnel_t *t);

static void runTunnelOnPrepare(tunnel_t *t)
{
    ww_startup_context_t callback_scope = {0};
    wwStartupContextBegin(&callback_scope);
    t->onPrepare(t);
    discard wwStartupContextEnd(&callback_scope);
}

/**
 * @brief Invoke one lifecycle callback for every tunnel in every finalized chain.
 *
 * @param cfg Node manager config.
 * @param callback Lifecycle callback to run.
 */
static void runTunnelLifecycleOnChains(node_manager_config_t *cfg, TunnelLifecycleFn callback)
{
    c_foreach(chain, vec_chains_t, cfg->chains)
    {
        tunnel_chain_t *tunnel_chain = *chain.ref;
        assert(tunnel_chain != NULL);

        for (uint16_t i = 0; i < tunnel_chain->tunnels.len; i++)
        {
            tunnel_t *tunnel = tunnel_chain->tunnels.tuns[i];
            assert(tunnel != NULL);
            callback(tunnel);
            if (UNLIKELY(startupFailurePending()))
            {
                return;
            }
        }
    }
}

/**
 * @brief Invoke preparation callback for every tunnel in every finalized chain.
 *
 * @param cfg Node manager config.
 */
static void prepareTunnels(node_manager_config_t *cfg)
{
    runTunnelLifecycleOnChains(cfg, runTunnelOnPrepare);
}

/**
 * @brief Start all tunnels after preparation and chain finalization.
 *
 * @param cfg Node manager config.
 */
static void startTunnels(node_manager_config_t *cfg)
{
    c_foreach(chain, vec_chains_t, cfg->chains)
    {
        tunnel_chain_t *tunnel_chain = *chain.ref;
        assert(tunnel_chain != NULL);

        tunnel_chain->started = true;

        for (uint16_t i = 0; i < tunnel_chain->tunnels.len; i++)
        {
            tunnel_t *tunnel = tunnel_chain->tunnels.tuns[i];
            assert(tunnel != NULL);
            ww_startup_context_t callback_scope = {0};
            wwStartupContextBegin(&callback_scope);
            tunnel->onStart(tunnel);
            discard wwStartupContextEnd(&callback_scope);
            if (UNLIKELY(startupFailurePending()))
            {
                return;
            }
        }
    }
}

void nodemanagerInitializeLineOnTargetWorker(void *worker, void *_tunnel, void *_line, void *arg3)
{
    discard worker;
    discard arg3;
    assert(_tunnel != NULL);
    assert(_line != NULL);

    tunnel_t *tunnel = (tunnel_t *) _tunnel;
    line_t   *line   = (line_t *) _line;

    assert(lineIsOnCurrentEventWorker(line));

    if (! lineCallWithRef(line, tunnelNextUpStreamInit, tunnel))
    {
        /*
         * Category D: a persistent worker packet line is process-lifetime state
         * that may not die at runtime. Once that contract is violated, orderly
         * teardown can no longer assume line state is structurally valid, so
         * this runs on a worker but must still hard-abort.
         */
        LOGF("NodeManager: node startup failure: line initialization failed for node (\"%s\") on worker %d",
             configPolicyDiagnostic(tunnel->node->name),
             workerWIDForLog(getWID()));
        abortProgramNow(1);
        return;
    }
}

static bool tunnelIsManagerPacketInitHead(const tunnel_chain_t *chain, uint16_t index)
{
    assert(chain != NULL);
    assert(chain->layer_solution_ready);
    assert(index < chain->tunnels.len);

    const tunnel_t *tunnel = chain->tunnels.tuns[index];
    assert(tunnel != NULL && tunnel->node != NULL);

    return tunnel->prev == NULL && tunnel->next != NULL &&
           (tunnel->node->flags & kNodeFlagChainHead) != 0 &&
           tunnelchainGetResolvedNextLayer(chain, index) == kLayerDomainL3;
}

/**
 * @brief Send initial line events for packet-layer chain heads.
 *
 * @param cfg Node manager config.
 */
static bool initializePacketTunnels(node_manager_config_t *cfg)
{
    c_foreach(chain_ref, vec_chains_t, cfg->chains)
    {
        tunnel_chain_t *chain = *chain_ref.ref;
        assert(chain != NULL);
        if (chain->tunnels.len == 0 || chain->packet_chain_init_sent)
        {
            continue;
        }

        assert(chain->layer_solution_ready);
        bool admitted_any_head = false;

        for (uint16_t ti = 0; ti < chain->tunnels.len; ++ti)
        {
            if (! tunnelIsManagerPacketInitHead(chain, ti))
            {
                continue;
            }

            tunnel_t *head = chain->tunnels.tuns[ti];
            for (wid_t wi = 0; wi < getWorkersCount(); wi++)
            {
                line_t *l = tunnelchainGetWorkerPacketLine(chain, wi);
                if (UNLIKELY(sendWorkerMessageForceQueueWithCleanup(
                                 wi, &nodemanagerInitializeLineOnTargetWorker, NULL, head, l, NULL) !=
                             kWorkerMessageSubmitAccepted))
                {
                    LOGF("NodeManager: failed to admit packet-chain Init for node \"%s\" on worker %d",
                         configPolicyDiagnostic(head->node->name),
                         workerWIDForLog(wi));
                    return false;
                }
            }
            admitted_any_head = true;
        }

        if (admitted_any_head)
        {
            /* Worker loops are still behind workers_run_flag, so publication
             * follows complete admission while execution remains deferred
             * until after every prepare/start hook. */
            chain->packet_chain_init_sent = true;
        }
    }
    return true;
}

/**
 * @brief Execute full node startup pipeline for one config.
 *
 * @param cfg Node manager config.
 */
static void runNodes(node_manager_config_t *cfg)
{
    tunnel_t *t_array[kMaxNodesPerConfig] = {0};
    int       tunnels_count               = createTunnelInstances(cfg, t_array, kMaxNodesPerConfig);

    if (tunnels_count < 0)
    {
        return;
    }
    if (tunnels_count == 0)
    {
        LOGW("NodeManager:  0 nodes in config");
        return;
    }

    assignChainsToTunnels(t_array, tunnels_count);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    validateTunnelChains(t_array, tunnels_count);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    finalizeTunnelChains(cfg, t_array, tunnels_count);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    if (UNLIKELY(! initializePacketTunnels(cfg)))
    {
        /* Already-admitted messages remain owned by their worker queues and are
         * reclaimed by startup-failure teardown. Packet lines themselves stay
         * chain-owned and are released only by tunnelchainDestroy(). */
        startupFailureRecord(1);
        return;
    }

    prepareTunnels(cfg);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    startTunnels(cfg);
}

/**
 * @brief Validate that one node path has valid `next` links and no long cycles.
 *
 * @param start_node Starting node.
 * @param cfg Node manager config.
 */
static void validateNodeChainPath(node_t *start_node, node_manager_config_t *cfg)
{
    node_t *current_node = start_node;
    int     path_length  = 0;

    while (current_node->hash_next != 0)
    {
        path_length++;
        node_t *next_node = nodemanagerGetConfigNodeByHash(cfg, current_node->hash_next);
        if (next_node == NULL)
        {
            LOGF("Node Map Failure: Error in config file!  (path: %s)  (name: %s)",
                 configPolicyDiagnostic(cfg->config_file->file_path),
                 configPolicyDiagnostic(cfg->config_file->name));
            LOGF("Node Map Failure: node \"%s\" could not find it's next node \"%s\"",
                 configPolicyDiagnostic(current_node->name),
                 configPolicyDiagnostic(current_node->next));
            startupFailureRecord(1);
            return;
        }
        current_node = next_node;
        if (path_length > 200)
        {
            LOGF("Node Map Failure: circular reference deteceted");
            startupFailureRecord(1);
            return;
        }
    }
}

/**
 * @brief Validate chain path integrity for all nodes in config.
 *
 * @param cfg Node manager config.
 */
static void pathWalk(node_manager_config_t *cfg)
{
    c_foreach(p1, map_node_t, cfg->node_map)
    {
        node_t *node = p1.ref->second;
        validateNodeChainPath(node, cfg);
        if (UNLIKELY(startupFailurePending()))
        {
            return;
        }
    }
}

/**
 * @brief Ensure at least one chain-head node exists in config.
 *
 * @param cfg Node manager config.
 */
static void validateChainHeadNodes(node_manager_config_t *cfg)
{
    c_foreach(n1, map_node_t, cfg->node_map)
    {
        if ((n1.ref->second->flags & kNodeFlagChainHead) == kNodeFlagChainHead)
        {
            return;
        }
    }
    LOGF("NodeMap: detecetd 0 chainhead nodes");
    startupFailureRecord(1);
}

/**
 * @brief Run cycle-related validations for current config graph.
 *
 * @param cfg Node manager config.
 */
static void cycleProcess(node_manager_config_t *cfg)
{
    validateChainHeadNodes(cfg);
}

/**
 * @brief Parse required/optional node fields from JSON object.
 *
 * @param node_json Source JSON object.
 * @param cfg Node manager config.
 * @param node_name Output node name.
 * @param node_type Output node type.
 * @param node_next Output next-node name.
 * @param node_version Output node version.
 */
static void parseNodeJsonFields(cJSON *node_json, node_manager_config_t *cfg, char **node_name, char **node_type,
                                char **node_next, int *node_version)
{
    if (! getStringFromJsonObject(node_name, node_json, "name"))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes[x]->name (string field) was empty or invalid",
             configPolicyDiagnostic(cfg->config_file->file_path));
        startupFailureRecord(1);
        return;
    }

    if (! getStringFromJsonObject(node_type, node_json, "type"))
    {
        LOGF("JSON Error: config file \"%s\" -> nodes[x]->type (string field) was empty or invalid",
             configPolicyDiagnostic(cfg->config_file->file_path));
        startupFailureRecord(1);
        return;
    }

    getStringFromJsonObject(node_next, node_json, "next");
    getIntFromJsonObjectOrDefault(node_version, node_json, "version", 0);
}

/**
 * @brief Allocate a node object and load base node template from library.
 *
 * @param node_type Node type string.
 * @param hash_type Hashed node type.
 * @return node_t* Allocated and loaded node object.
 */
static node_t *createAndLoadNode(const char *node_type, hash_t hash_type)
{
    node_t *new_node = nodemanagerNewNode();
    if (UNLIKELY(new_node == NULL))
    {
        LOGF("NodeManager: failed to allocate node metadata for type \"%s\"", configPolicyDiagnostic(node_type));
        startupFailureRecord(1);
        return NULL;
    }
    *new_node = nodelibraryLoadByTypeHash(hash_type);

    if (new_node->hash_type != hash_type)
    {
        LOGF("NodeManager: node creation failure: library \"%s\" (hash: %lx) could not be loaded ",
             configPolicyDiagnostic(node_type),
             hash_type);
        memoryFree(new_node);
        startupFailureRecord(1);
        return NULL;
    }

    return new_node;
}

/**
 * @brief Fill node runtime/config properties after library load.
 *
 * @param node Destination node object.
 * @param node_name Node name.
 * @param node_type Node type.
 * @param node_next Next-node name (optional).
 * @param node_version Node version.
 * @param hash_name Hashed node name.
 * @param hash_type Hashed node type.
 * @param hash_next Hashed next node name.
 * @param node_json Original node JSON.
 * @param cfg Owner config.
 */
static void setupNodeProperties(node_t *node, char *node_name, char *node_type, char *node_next, int node_version,
                                hash_t hash_name, hash_t hash_type, hash_t hash_next, cJSON *node_json,
                                node_manager_config_t *cfg)
{
    node->name                = node_name;
    node->type                = node_type;
    node->next                = node_next;
    node->hash_name           = hash_name;
    node->hash_type           = hash_type;
    node->hash_next           = hash_next;
    node->version             = (uint32_t) node_version;
    node->node_json           = node_json;
    node->node_settings_json  = cJSON_GetObjectItemCaseSensitive(node_json, "settings");
    node->node_manager_config = cfg;
}

/**
 * @brief Reject duplicate singleton node types inside one config.
 *
 * @param node Node being registered.
 * @param cfg Node manager config.
 */
static void validateSingletonNodeType(node_t *node, node_manager_config_t *cfg)
{
    if ((node->flags & kNodeFlagSingleton) == 0)
    {
        return;
    }

    c_foreach(existing_pair, map_node_t, cfg->node_map)
    {
        node_t *existing_node = existing_pair.ref->second;
        if (existing_node->hash_type != node->hash_type)
        {
            continue;
        }

        LOGF("NodeManager: singleton node type \"%s\" can only appear once per config file \"%s\" "
             "(conflicting nodes: \"%s\" and \"%s\")",
             configPolicyDiagnostic(node->type),
             configPolicyDiagnostic(cfg->config_file->file_path),
             configPolicyDiagnostic(existing_node->name),
             configPolicyDiagnostic(node->name));
        startupFailureRecord(1);
        return;
    }
}

/**
 * @brief Insert node into config map and reject duplicate names.
 *
 * @param node Node object.
 * @param cfg Node manager config.
 */
static void registerNodeInMap(node_t *node, node_manager_config_t *cfg)
{
    map_node_t *map = &(cfg->node_map);

    /*
     * This map contains only nodes declared by the config. A tunnel that needs
     * an internal child should embed/configure it with nodeConfigureChild() and
     * own its lifecycle; registering children here couples their creation to
     * hash iteration and is forbidden once config loading is complete.
     */
    if (cfg->node_map_phase != kNodeMapPhaseCollecting)
    {
        LOGF("NodeManager: cannot register node \"%s\" after the config node map was frozen; "
             "internal child nodes must remain private to their parent tunnel",
             configPolicyDiagnostic(node->name));
        startupFailureRecord(1);
        return;
    }

    if (map_node_t_contains(map, node->hash_name))
    {
        LOGF("NodeManager: duplicate node \"%s\" (hash: %lx) ", configPolicyDiagnostic(node->name), node->hash_name);
        startupFailureRecord(1);
        return;
    }

    if (map_node_t_size(map) >= kMaxNodesPerConfig)
    {
        LOGF("NodeManager: config file \"%s\" exceeds the maximum of %d nodes",
             configPolicyDiagnostic(cfg->config_file->file_path),
             kMaxNodesPerConfig);
        startupFailureRecord(1);
        return;
    }
    validateSingletonNodeType(node, cfg);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    map_node_t_result result = map_node_t_insert(map, node->hash_name, node);

    if (result.ref == NULL || ! result.inserted)
    {
        LOGF("NodeManager: failed to register node \"%s\"", configPolicyDiagnostic(node->name));
        startupFailureRecord(1);
    }
}

void nodemanagerCreateNodeInstance(node_manager_config_t *cfg, cJSON *node_json)
{
    char *node_name    = NULL;
    char *node_type    = NULL;
    char *node_next    = NULL;
    int   node_version = 0;

    parseNodeJsonFields(node_json, cfg, &node_name, &node_type, &node_next, &node_version);
    if (UNLIKELY(startupFailurePending()))
    {
        memoryFree(node_name);
        memoryFree(node_type);
        memoryFree(node_next);
        return;
    }

    hash_t hash_name = calcHashBytes(node_name, strlen(node_name));
    hash_t hash_type = calcHashBytes(node_type, strlen(node_type));
    hash_t hash_next = node_next != NULL ? calcHashBytes(node_next, strlen(node_next)) : 0x0;

    node_t *new_node = createAndLoadNode(node_type, hash_type);
    if (UNLIKELY(new_node == NULL))
    {
        memoryFree(node_name);
        memoryFree(node_type);
        memoryFree(node_next);
        return;
    }
    setupNodeProperties(
        new_node, node_name, node_type, node_next, node_version, hash_name, hash_type, hash_next, node_json, cfg);
    registerNodeInMap(new_node, cfg);
    if (UNLIKELY(startupFailurePending() && ! map_node_t_contains(&cfg->node_map, new_node->hash_name)))
    {
        nodemanagerDestroyNode(new_node);
    }
}

node_t *nodemanagerGetConfigNodeByHash(node_manager_config_t *cfg, hash_t hash_node_name)
{
    map_node_t_iter iter = map_node_t_find(&(cfg->node_map), hash_node_name);
    if (iter.ref == map_node_t_end(&(cfg->node_map)).ref)
    {
        return NULL;
    }
    return (iter.ref->second);
}

node_t *nodemanagerGetConfigNodeByName(node_manager_config_t *cfg, const char *name)
{
    return nodemanagerGetConfigNodeByHash(cfg, calcHashBytes(name, stringLength(name)));
}

node_t *nodemanagerNewNode(void)
{
    node_t *new_node = memoryAllocateZero(sizeof(node_t));
    return new_node;
}

/**
 * @brief Create node runtime objects for every node JSON entry.
 *
 * @param cfg Node manager config.
 */
static void createAllNodeInstances(node_manager_config_t *cfg)
{
    cJSON *nodes_json = cfg->config_file->nodes;
    cJSON *node_json  = NULL;

    int nodes_count = cJSON_GetArraySize(nodes_json);
    if (nodes_count > kMaxNodesPerConfig)
    {
        LOGF("NodeManager: config file \"%s\" contains %d nodes; the maximum is %d",
             configPolicyDiagnostic(cfg->config_file->file_path),
             nodes_count,
             kMaxNodesPerConfig);
        startupFailureRecord(1);
        return;
    }

    cJSON_ArrayForEach(node_json, nodes_json)
    {
        nodemanagerCreateNodeInstance(cfg, node_json);
        if (UNLIKELY(startupFailurePending()))
        {
            return;
        }
    }
}

static void freezeNodeMap(node_manager_config_t *cfg)
{
    if (cfg->node_map_phase != kNodeMapPhaseCollecting)
    {
        LOGF("NodeManager: config node map invariant failed before freezing");
        startupFailureRecord(1);
        return;
    }

    cfg->node_map_phase = kNodeMapPhaseFrozen;
}

/**
 * @brief Parse, validate, and run all nodes for one config.
 *
 * @param cfg Node manager config.
 */
static void startInstallingConfigFile(node_manager_config_t *cfg)
{
    createAllNodeInstances(cfg);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    freezeNodeMap(cfg);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    cycleProcess(cfg);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    pathWalk(cfg);
    if (UNLIKELY(startupFailurePending()))
    {
        return;
    }
    runNodes(cfg);
}

struct node_manager_s *nodemanagerGetState(void)
{
    return nodemanager_gstate;
}

void nodemanagerSetState(struct node_manager_s *new_state)
{
    assert(nodemanager_gstate == NULL);
    nodemanager_gstate = new_state;
}

/**
 * @brief Allocate node-manager config container for one parsed config file.
 *
 * @param config_file Parsed config file.
 * @return node_manager_config_t* Created config wrapper.
 */
static node_manager_config_t *createNodeManagerConfig(config_file_t *config_file)
{
    node_manager_config_t *cfg = memoryAllocateZero(sizeof(node_manager_config_t));
    if (UNLIKELY(cfg == NULL))
    {
        LOGF("NodeManager: failed to allocate config metadata");
        return NULL;
    }
    cfg->config_file    = config_file;
    cfg->node_map       = map_node_t_init();
    cfg->chains         = vec_chains_t_init();
    cfg->node_map_phase = kNodeMapPhaseCollecting;

    if (! map_node_t_reserve(&cfg->node_map, kMaxNodesPerConfig) ||
        ! vec_chains_t_reserve(&cfg->chains, kMaxNodesPerConfig))
    {
        LOGF("NodeManager: failed to reserve fixed config registries for %d nodes", kMaxNodesPerConfig);
        map_node_t_drop(&cfg->node_map);
        vec_chains_t_drop(&cfg->chains);
        memoryFree(cfg);
        return NULL;
    }

    return cfg;
}

ww_startup_result_t nodemanagerRunConfigFile(config_file_t *config_file)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);

    node_manager_config_t *cfg = createNodeManagerConfig(config_file);
    if (UNLIKELY(cfg == NULL))
    {
        configfileDestroy(config_file);
        startupFailureRecord(1);
        return wwStartupContextEnd(&startup);
    }

    if (UNLIKELY(vec_configs_t_push(&nodemanager_gstate->configs, cfg) == NULL))
    {
        nodemanagerDestroyConfig(cfg);
        LOGF("NodeManager: failed to publish config metadata");
        startupFailureRecord(1);
        return wwStartupContextEnd(&startup);
    }
    startInstallingConfigFile(cfg);
    return wwStartupContextEnd(&startup);
}

void nodemanagerQuiesceRequest(const ww_lifecycle_context_t *context)
{
    if (nodemanager_gstate == NULL ||
        atomicExchangeExplicit(&nodemanager_gstate->quiesce_request_started, true, memory_order_relaxed))
    {
        return;
    }

    c_foreach(conf, vec_configs_t, nodemanager_gstate->configs)
    {
        node_manager_config_t *cfg = *conf.ref;
        if (cfg == NULL)
        {
            continue;
        }
        c_foreach(chain, vec_chains_t, cfg->chains)
        {
            tunnel_chain_t *tunnel_chain = *chain.ref;
            for (uint16_t i = 0; i < tunnel_chain->tunnels.len; i++)
            {
                tunnel_t *tunnel = tunnel_chain->tunnels.tuns[i];
                tunnel->onQuiesceRequest(tunnel, context);
            }
        }
    }
}

void nodemanagerQuiesceWait(const ww_lifecycle_context_t *context)
{
    if (nodemanager_gstate == NULL ||
        atomicExchangeExplicit(&nodemanager_gstate->quiesce_wait_started, true, memory_order_relaxed))
    {
        return;
    }

    c_foreach(conf, vec_configs_t, nodemanager_gstate->configs)
    {
        node_manager_config_t *cfg = *conf.ref;
        if (cfg == NULL)
        {
            continue;
        }
        c_foreach(chain, vec_chains_t, cfg->chains)
        {
            tunnel_chain_t *tunnel_chain = *chain.ref;
            for (uint16_t i = 0; i < tunnel_chain->tunnels.len; i++)
            {
                tunnel_t *tunnel = tunnel_chain->tunnels.tuns[i];
                tunnel->onQuiesceWait(tunnel, context);
            }
        }
    }
}

void nodemanagerStop(const ww_lifecycle_context_t *context)
{
    if (nodemanager_gstate == NULL ||
        atomicExchangeExplicit(&nodemanager_gstate->stop_started, true, memory_order_relaxed))
    {
        return;
    }
    nodemanager_gstate->stop_context     = *context;
    nodemanager_gstate->stop_context_set = true;

    c_foreach(conf, vec_configs_t, nodemanager_gstate->configs)
    {
        node_manager_config_t *cfg = *conf.ref;
        if (cfg == NULL)
        {
            continue;
        }
        c_foreach(chain, vec_chains_t, cfg->chains)
        {
            tunnel_chain_t *tunnel_chain = *chain.ref;
            for (uint16_t i = 0; i < tunnel_chain->tunnels.len; i++)
            {
                tunnel_t *tunnel = tunnel_chain->tunnels.tuns[i];
                tunnel->onStop(tunnel, context);
            }
        }
    }
}

void nodemanagerQuiesceWorker(wid_t wid, const ww_lifecycle_context_t *context)
{
    if (nodemanager_gstate == NULL)
    {
        return;
    }
    assert(currentThreadIsEventWorkerWID(wid));

    c_foreach(conf, vec_configs_t, nodemanager_gstate->configs)
    {
        node_manager_config_t *cfg = *conf.ref;
        if (cfg == NULL)
        {
            continue;
        }

        c_foreach(chain, vec_chains_t, cfg->chains)
        {
            tunnel_chain_t *tunnel_chain = *chain.ref;
            for (uint16_t i = 0; i < tunnel_chain->tunnels.len; i++)
            {
                tunnel_t *tunnel = tunnel_chain->tunnels.tuns[i];
                tunnel->onWorkerQuiesce(tunnel, wid, context);
            }
        }
    }
}

void nodemanagerStopWorkerResources(wid_t wid, const ww_lifecycle_context_t *context)
{
    /*
     * The worker has closed producer/message admission and SocketManager has
     * drained its UDP sources. Other source owners may still await their hook:
     * chain storage order does not guarantee callback topology order. Each hook
     * drains its own lines without requiring borrowed sets to be empty. The event loop, tail adapters,
     * tunnel state, and line/buffer pools are still alive throughout this pass.
     */
    if (nodemanager_gstate == NULL)
    {
        return;
    }

    // Called from the worker tearing itself down, for its own slot only.
    assert(currentThreadIsEventWorkerWID(wid));

    c_foreach(conf, vec_configs_t, nodemanager_gstate->configs)
    {
        node_manager_config_t *cfg = *conf.ref;
        if (cfg == NULL)
        {
            continue;
        }

        c_foreach(chain, vec_chains_t, cfg->chains)
        {
            tunnel_chain_t *tunnel_chain = *chain.ref;
            assert(tunnel_chain != NULL);

            for (uint16_t i = 0; i < tunnel_chain->tunnels.len; i++)
            {
                tunnel_t *tunnel = tunnel_chain->tunnels.tuns[i];
                assert(tunnel != NULL);
                tunnel->onWorkerStop(tunnel, wid, context);
            }
        }
    }
}

node_manager_t *nodemanagerCreate(void)
{
    assert(nodemanager_gstate == NULL);

    node_manager_t *state = memoryAllocateZero(sizeof(*state));
    if (UNLIKELY(state == NULL))
    {
        return NULL;
    }

    state->configs = vec_configs_t_init();
    if (UNLIKELY(! vec_configs_t_reserve(&state->configs, kNmConfigsVectorCap)))
    {
        vec_configs_t_drop(&state->configs);
        memoryFree(state);
        return NULL;
    }
    atomicStoreRelaxed(&state->quiesce_request_started, false);
    atomicStoreRelaxed(&state->quiesce_wait_started, false);
    atomicStoreRelaxed(&state->stop_started, false);

    nodemanager_gstate = state;
    return state;
}

void nodemanagerDestroyNode(node_t *node)
{
    tunnel_t *t = node->instance;
    if (t)
    {
        const ww_lifecycle_context_t *context = nodemanager_gstate != NULL && nodemanager_gstate->stop_context_set
                                                    ? &nodemanager_gstate->stop_context
                                                    : wwLifecycleStartupRollback();
        t->onDestroy(t, context);
        node->instance = NULL;
    }
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryFree(node);
}

void nodemanagerDestroyConfig(node_manager_config_t *cfg)
{
    /*
     * Layer/topology validation intentionally runs before chain finalization and
     * publication. A startup failure in that interval still leaves assembled
     * chains owned through their configured tunnel instances, so collect those
     * pointers before onDestroy() invalidates the instances. Published chains
     * are included first and deduplicated against the same instance pointers.
     */
    tunnel_chain_t *owned_chains[kMaxNodesPerConfig] = {0};
    int             owned_chain_count                = 0;

    c_foreach(chain, vec_chains_t, cfg->chains)
    {
        owned_chains[owned_chain_count++] = *chain.ref;
    }

    c_foreach(node_key_pair, map_node_t, cfg->node_map)
    {
        node_t         *node  = node_key_pair.ref->second;
        tunnel_chain_t *chain = node->instance != NULL ? node->instance->chain : NULL;
        if (chain == NULL)
        {
            continue;
        }

        bool already_owned = false;
        for (int i = 0; i < owned_chain_count; ++i)
        {
            if (owned_chains[i] == chain)
            {
                already_owned = true;
                break;
            }
        }
        if (! already_owned)
        {
            assert(owned_chain_count < kMaxNodesPerConfig);
            owned_chains[owned_chain_count++] = chain;
        }
    }

    c_foreach(node_key_pair, map_node_t, cfg->node_map)
    {
        node_t *node = (node_key_pair.ref)->second;
        nodemanagerDestroyNode(node);
    }

    for (int i = 0; i < owned_chain_count; ++i)
    {
        tunnelchainDestroy(owned_chains[i]);
    }

    map_node_t_drop(&cfg->node_map);
    vec_chains_t_drop(&cfg->chains);
    configfileDestroy(cfg->config_file);
    memoryFree(cfg);
}

void nodemanagerDestroy(void)
{
    if (nodemanager_gstate == NULL)
    {
        return;
    }

    c_foreach(conf, vec_configs_t, nodemanager_gstate->configs)
    {
        nodemanagerDestroyConfig(*conf.ref);
    }

    vec_configs_t_drop(&nodemanager_gstate->configs);
    memoryFree(nodemanager_gstate);
    nodemanager_gstate = NULL;
}
