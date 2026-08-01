/*
 * NodeManager's config map is a fixed, load-time-only registry. Internal child
 * nodes are owned by their parent tunnel and must never be inserted here.
 */

#include "wwapi.h"

#include "managers/node_manager.c" // NOLINT: exercises the private map invariants

#include <sys/wait.h>
#include <unistd.h>

enum
{
    kUnexpectedChildReturn = 91
};

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
    config_file_t          config_file          = {0};
    node_manager_config_t *cfg                  = createTestConfig(&config_file);
    node_t                *nodes                = memoryAllocateZero(sizeof(*nodes) * kMaxNodesPerConfig);
    const isize_t          initial_bucket_count = cfg->node_map_bucket_count;

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

    destroyTestConfig(cfg);
    memoryFree(nodes);
}

static void runFatalChild(void (*child_routine)(void), const char *label)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork NodeManager invariant child");

    if (child == 0)
    {
        child_routine();
        _Exit(kUnexpectedChildReturn);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for NodeManager invariant child");
    require(WIFEXITED(status), label);
    require(WEXITSTATUS(status) == 1, label);
}

static void exceedMaximumInChild(void)
{
    config_file_t          config_file = {0};
    node_manager_config_t *cfg         = createTestConfig(&config_file);
    node_t                *nodes       = memoryAllocateZero(sizeof(*nodes) * (kMaxNodesPerConfig + 1U));

    for (size_t i = 0; i <= kMaxNodesPerConfig; ++i)
    {
        initializeTestNode(&nodes[i], i);
        registerNodeInMap(&nodes[i], cfg);
    }
}

static void mutateFrozenMapInChild(void)
{
    config_file_t          config_file = {0};
    node_manager_config_t *cfg         = createTestConfig(&config_file);
    node_t                 node        = {0};

    freezeNodeMap(cfg);
    initializeTestNode(&node, 0);
    registerNodeInMap(&node, cfg);
}

int main(void)
{
    testMaximumFitsWithoutGrowth();
    runFatalChild(exceedMaximumInChild, "NodeManager did not reject a node beyond the configured maximum");
    runFatalChild(mutateFrozenMapInChild, "NodeManager did not reject mutation after freezing the config map");
    return 0;
}
