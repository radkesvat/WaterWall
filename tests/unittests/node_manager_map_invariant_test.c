/*
 * NodeManager's config map is a fixed, load-time-only registry. Internal child
 * nodes are owned by their parent tunnel and must never be inserted here.
 */

#include "wwapi.h"

#include "managers/node_manager.c" // NOLINT: exercises the private map invariants

static char test_config_path[] = "node-manager-map-invariant-test.json";
static char test_config_name[] = "node-manager-map-invariant-test";
static char test_node_name[]   = "configured-node";

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static node_manager_config_t *createTestConfig(config_file_t *config_file)
{
    *config_file = (config_file_t) {
        .file_path = test_config_path,
        .name      = test_config_name,
    };
    return createNodeManagerConfig(config_file);
}

static void initializeTestNode(node_t *node, size_t index)
{
    *node = (node_t) {
        .name      = test_node_name,
        .hash_name = (hash_t) index + 1U,
    };
}

static void destroyTestConfig(node_manager_config_t *cfg)
{
    map_node_t_drop(&cfg->node_map);
    vec_chains_t_drop(&cfg->chains);
    memoryFree(cfg);
}

static void testMaximumFitsWithoutGrowth(void)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);

    config_file_t          config_file          = {0};
    node_manager_config_t *cfg                  = createTestConfig(&config_file);
    node_t                *nodes                = memoryAllocateZero(sizeof(*nodes) * kMaxNodesPerConfig);
    const isize_t          initial_bucket_count = map_node_t_bucket_count(&cfg->node_map);

    require(map_node_t_capacity(&cfg->node_map) >= kMaxNodesPerConfig,
            "the config node map did not reserve the logical maximum");

    for (size_t i = 0; i < kMaxNodesPerConfig; ++i)
    {
        initializeTestNode(&nodes[i], i);
        registerNodeInMap(&nodes[i], cfg);
        require(map_node_t_bucket_count(&cfg->node_map) == initial_bucket_count,
                "the config node map grew while loading an allowed node");
    }

    require(map_node_t_size(&cfg->node_map) == kMaxNodesPerConfig,
            "the config node map did not retain every allowed node");
    freezeNodeMap(cfg);
    require(cfg->node_map_phase == kNodeMapPhaseFrozen, "the config node map did not enter the frozen phase");
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    require(wwStartupSucceeded(result), "NodeManager rejected a valid maximum-sized node map");

    destroyTestConfig(cfg);
    memoryFree(nodes);
}

static void testExceedMaximumRecordsStartupFailure(void)
{
    config_file_t          config_file = {0};
    node_manager_config_t *cfg         = createTestConfig(&config_file);
    node_t                *nodes       = memoryAllocateZero(sizeof(*nodes) * (kMaxNodesPerConfig + 1U));

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    for (size_t i = 0; i <= kMaxNodesPerConfig; ++i)
    {
        initializeTestNode(&nodes[i], i);
        registerNodeInMap(&nodes[i], cfg);
    }
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    require(result.exit_code == 1, "NodeManager did not report a node beyond the configured maximum");
    require(map_node_t_size(&cfg->node_map) == kMaxNodesPerConfig,
            "NodeManager inserted a node beyond the configured maximum");

    destroyTestConfig(cfg);
    memoryFree(nodes);
}

static void testFrozenMapMutationRecordsStartupFailure(void)
{
    config_file_t          config_file = {0};
    node_manager_config_t *cfg         = createTestConfig(&config_file);
    node_t                 node        = {0};

    freezeNodeMap(cfg);
    initializeTestNode(&node, 0);
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    registerNodeInMap(&node, cfg);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);
    require(result.exit_code == 1, "NodeManager did not report mutation after freezing the config map");
    require(map_node_t_size(&cfg->node_map) == 0, "NodeManager mutated the frozen config map");

    destroyTestConfig(cfg);
}

int main(void)
{
    testMaximumFitsWithoutGrowth();
    testExceedMaximumRecordsStartupFailure();
    testFrozenMapMutationRecordsStartupFailure();
    return 0;
}
