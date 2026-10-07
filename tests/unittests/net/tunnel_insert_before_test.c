/*
 * Covers: startup helper insertion before an unchained target, including ordinary
 * adjacency, side branches, chain metadata, and rejected insertion.
 * Setup: Plain tunnels and an unfinalized zero-worker chain; no lines. Linux wraps
 * node lookup to check onward callback suppression after insertion failure.
 * Checks: The callable branch entry includes the helper, a side branch preserves
 * the owner's next link, insertion invalidates layer caches, and capacity failure
 * leaves bindings and chain ownership unchanged.
 * CTest: waterwall.tunnel_insert_before_unit
 */
#include "loggers/internal_logger.h"
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static tunnel_t *createTunnel(node_t *node, size_t line_state_size)
{
    tunnel_t *t = tunnelCreate(node, 0, line_state_size);
    require(t != NULL, "failed to create tunnel");
    return t;
}

static void testInsertion(bool side_branch)
{
    testCaseSet(side_branch ? "side branch insertion" : "ordinary insertion");
    node_t    node        = {.name = (char *) "target", .type = (char *) "TestTunnel", .required_padding_left = 3};
    node_t    helper_node = {.name = (char *) "helper", .type = (char *) "DomainResolver", .required_padding_left = 7};
    tunnel_t *previous    = createTunnel(&node, 32);
    tunnel_t *target      = createTunnel(&node, 32);
    tunnel_t *helper      = createTunnel(&helper_node, 64);
    tunnel_t *primary     = createTunnel(&node, 0);
    tunnel_chain_t *chain = tunnelchainCreate(0);
    require(chain != NULL, "failed to create chain");

    tunnelBind(previous, side_branch ? primary : target);
    if (side_branch)
    {
        tunnelBindDown(previous, target);
    }
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    startupFailureRecord(7);
    require(! tunnelInsertBefore(target, helper, chain), "insertion proceeded after a pending startup failure");
    require(wwStartupContextEnd(&startup).exit_code == 7, "insertion changed the pending startup failure");
    require(previous->next == (side_branch ? primary : target) && target->prev == previous,
            "pending startup failure allowed target rewiring");
    require(helper->prev == NULL && helper->next == NULL && helper->chain == NULL && target->chain == NULL,
            "pending startup failure allowed helper binding or chain registration");
    require(chain->tunnels.len == 0 && chain->sum_padding_left == 0 && chain->sum_line_state_size == 0,
            "pending startup failure changed chain metadata");

    wwStartupContextBegin(&startup);
    tunnelchainInsert(chain, previous);
    if (side_branch)
    {
        tunnelchainInsert(chain, primary);
    }
    const uint16_t initial_length     = chain->tunnels.len;
    const uint16_t initial_padding    = chain->sum_padding_left;
    const uint32_t initial_state_size = chain->sum_line_state_size;
    chain->layer_solution_ready       = true;
    memorySet(chain->resolved_prev_layer, kNodeLayer4, sizeof(chain->resolved_prev_layer));
    memorySet(chain->resolved_next_layer, kNodeLayer4, sizeof(chain->resolved_next_layer));

    require(tunnelInsertBefore(target, helper, chain), "helper insertion failed");
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "helper insertion failed startup");
    require(previous->next == (side_branch ? primary : helper), "insertion changed the wrong predecessor link");
    require(helper->prev == previous && helper->next == target && target->prev == helper,
            "helper was not bound before target");
    require(tunnelGetBranchEntry(previous, target) == helper, "branch entry bypassed inserted helper");
    require(chain->tunnels.len == initial_length + 1 && chain->tunnels.tuns[initial_length] == helper,
            "helper was not appended in construction order");
    require(helper->chain == chain && target->chain == NULL, "insertion changed the wrong chain ownership");
    require(chain->sum_padding_left == initial_padding + helper_node.required_padding_left &&
                chain->sum_line_state_size == initial_state_size + helper->lstate_size,
            "helper requirements were not included in chain metadata");
    require(! chain->layer_solution_ready, "insertion kept a stale solved layer snapshot");
    for (uint16_t i = 0; i < kMaxChainLen; ++i)
    {
        require(chain->resolved_prev_layer[i] == 0 && chain->resolved_next_layer[i] == 0,
                "insertion kept stale resolved layer domains");
    }

    tunnelchainDestroy(chain);
    tunnelDestroy(primary);
    tunnelDestroy(helper);
    tunnelDestroy(target);
    tunnelDestroy(previous);
}

static void testCapacityFailure(void)
{
    testCaseSet("capacity rejection");
    node_t          node   = {.name = (char *) "target", .type = (char *) "TestTunnel", .required_padding_left = 1};
    tunnel_t       *target = createTunnel(&node, 32);
    tunnel_t       *helper = createTunnel(&node, 64);
    tunnel_t       *existing[kMaxChainLen];
    tunnel_chain_t *chain = tunnelchainCreate(0);
    require(chain != NULL, "failed to create chain");
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    for (uint16_t i = 0; i < kMaxChainLen; ++i)
    {
        existing[i] = createTunnel(&node, 32);
        tunnelchainInsert(chain, existing[i]);
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "maximum-size chain was rejected");
    tunnelBind(existing[0], target);

    wwStartupContextBegin(&startup);
    require(! tunnelInsertBefore(target, helper, chain), "helper was accepted beyond the chain node limit");
    require(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "rejected insertion did not fail startup");
    require(existing[0]->next == target && target->prev == existing[0], "rejected insertion rewired the target");
    require(helper->prev == NULL && helper->next == NULL && helper->chain == NULL,
            "rejected helper acquired bindings or chain ownership");
    require(target->chain == NULL, "rejected insertion registered the target");
    require(chain->tunnels.len == kMaxChainLen && chain->sum_padding_left == kMaxChainLen &&
                chain->sum_line_state_size == kMaxChainLen * 32,
            "rejected insertion changed chain metadata");
    for (uint16_t i = 0; i < kMaxChainLen; ++i)
    {
        require(chain->tunnels.tuns[i] == existing[i] && existing[i]->chain == chain,
                "rejected insertion changed existing chain membership");
    }

    tunnelchainDestroy(chain);
    for (uint16_t i = 0; i < kMaxChainLen; ++i)
    {
        tunnelDestroy(existing[i]);
    }
    tunnelDestroy(helper);
    tunnelDestroy(target);
}

#if WW_TUNNEL_LOOKUP_WRAP_TEST
static node_t  *configured_next;
static unsigned onward_callbacks;

node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash);
node_t *__wrap_nodemanagerGetConfigNodeByHash(node_manager_config_t *config, hash_t hash)
{
    require(config == NULL && configured_next != NULL && hash == configured_next->hash_name,
            "unexpected configured next lookup");
    return configured_next;
}

static void countOnwardCallback(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
    ++onward_callbacks;
}

static void testDefaultChainFailure(bool with_helper)
{
    testCaseSet(with_helper ? "default chaining after final helper slot" : "default chaining on full chain");
    node_t          next_node   = {.name = (char *) "next", .type = (char *) "TestTunnel", .hash_name = 1};
    node_t          target_node = {.name      = (char *) "target",
                                   .type      = (char *) "TestTunnel",
                                   .next      = next_node.name,
                                   .hash_next = next_node.hash_name};
    node_t          node        = {.name = (char *) "existing", .type = (char *) "TestTunnel"};
    tunnel_t       *target      = createTunnel(&target_node, 32);
    tunnel_t       *helper      = with_helper ? createTunnel(&node, 32) : NULL;
    tunnel_t       *next        = createTunnel(&next_node, 32);
    tunnel_t       *existing[kMaxChainLen];
    const uint16_t  initial_length = kMaxChainLen - (with_helper ? 1 : 0);
    tunnel_chain_t *chain          = tunnelchainCreate(0);
    require(chain != NULL, "failed to create chain");
    next_node.instance           = next;
    next->onChain                = countOnwardCallback;
    configured_next              = &next_node;
    onward_callbacks             = 0;
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    for (uint16_t i = 0; i < initial_length; ++i)
    {
        existing[i] = createTunnel(&node, 32);
        tunnelchainInsert(chain, existing[i]);
    }
    tunnelBind(existing[0], target);
    if (with_helper)
    {
        require(tunnelInsertBefore(target, helper, chain), "helper did not fill the last free slot");
    }
    require(! startupFailurePending(), "chain setup unexpectedly failed");

    target->onChain(target, chain);
    require(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "default chaining did not reject excess target");
    require(onward_callbacks == 0, "default chaining invoked next after its own insertion failed");
    require(chain->tunnels.len == kMaxChainLen && target->chain == NULL && next->chain == NULL,
            "failed default chaining changed chain membership");

    configured_next = NULL;
    tunnelchainDestroy(chain);
    for (uint16_t i = 0; i < initial_length; ++i)
    {
        tunnelDestroy(existing[i]);
    }
    if (helper != NULL)
    {
        tunnelDestroy(helper);
    }
    tunnelDestroy(next);
    tunnelDestroy(target);
}
#endif

int main(void)
{
    testCaseSet("tunnel_insert_before_test");
    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create logger");
    setInternalLogger(logger);
    testInsertion(false);
    testInsertion(true);
    testCapacityFailure();
#if WW_TUNNEL_LOOKUP_WRAP_TEST
    testDefaultChainFailure(false);
    testDefaultChainFailure(true);
#endif
    internaloggerDestroy();
    return 0;
}
