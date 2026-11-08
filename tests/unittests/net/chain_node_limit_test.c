/*
 * Covers: chain node limit; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: 64-, 65-, and 256-node chains and arrays, indexed insertion, and 256/257-node merges.
 * Checks: A rejected 257th tunnel leaves input contents, metadata, and ownership intact;
 * diagnostics state the 256-node maximum.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.chain_node_limit_unit
 */
#include "loggers/internal_logger.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"

static char log_message[1024];


static void captureLog(int level, const char *buf, int len)
{
    discard level;
    snprintf(log_message, sizeof(log_message), "%.*s", len, buf);
}

static void requireLimitFailure(ww_startup_context_t *startup)
{
    require(wwStartupContextEnd(startup).exit_code == 1, "oversized chain did not fail startup");
    require(strstr(log_message, "maximum of 256 nodes per chain") != NULL,
            "chain-limit error did not clearly state the 256-node maximum");
}

static void testInsertionLimit(tunnel_t **tunnels)
{
    tunnel_chain_t      *chain   = tunnelchainCreate(0);
    ww_startup_context_t startup = {0};
    require(chain != NULL, "failed to allocate chain");
    wwStartupContextBegin(&startup);
    const uint16_t sizes[] = {64, 65, 256};
    for (size_t size = 0; size < ARRAY_SIZE(sizes); ++size)
    {
        for (uint16_t i = chain->tunnels.len; i < sizes[size]; ++i)
        {
            tunnelchainInsert(chain, tunnels[i]);
        }
        require(! startupFailurePending(), "valid chain size was rejected");
        require(chain->tunnels.len == sizes[size], "valid chain size lost a tunnel");
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "256-node chain was rejected");

    const uint16_t positions[] = {0, 128, 256};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i)
    {
        log_message[0] = '\0';
        wwStartupContextBegin(&startup);
        tunnelchainInsertAt(chain, tunnels[256], positions[i]);
        requireLimitFailure(&startup);
        require(chain->tunnels.len == 256, "rejected insertion changed the chain length");
        require(chain->sum_padding_left == 256 && chain->sum_line_state_size == 256 * 32,
                "rejected insertion changed chain requirements");
        require(tunnels[256]->chain == NULL, "rejected tunnel acquired chain ownership");
        for (uint16_t j = 0; j < 256; ++j)
        {
            require(chain->tunnels.tuns[j] == tunnels[j] && tunnels[j]->chain == chain,
                    "rejected insertion changed chain contents or tunnel ownership");
        }
    }
    tunnelchainDestroy(chain);
    for (uint16_t i = 0; i < 256; ++i)
    {
        tunnels[i]->chain = NULL;
    }
}

static void testIndexedInsertion(tunnel_t **tunnels)
{
    const uint16_t positions[] = {0, 128, 255};
    for (size_t position = 0; position < ARRAY_SIZE(positions); ++position)
    {
        tunnel_chain_t *chain = tunnelchainCreate(0);
        require(chain != NULL, "failed to allocate indexed-insertion chain");
        ww_startup_context_t startup = {0};
        wwStartupContextBegin(&startup);
        for (uint16_t i = 0; i < 255; ++i)
        {
            tunnelchainInsert(chain, tunnels[i]);
        }
        tunnelchainInsertAt(chain, tunnels[255], positions[position]);
        require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "indexed insertion to 256 nodes was rejected");
        require(chain->tunnels.len == 256, "indexed insertion did not fill the chain");
        for (uint16_t i = 0; i < 256; ++i)
        {
            const uint16_t source = i == positions[position] ? 255 : i < positions[position] ? i : i - 1;
            require(chain->tunnels.tuns[i] == tunnels[source] && tunnels[source]->chain == chain,
                    "indexed insertion misplaced a tunnel or its ownership");
        }
        tunnelchainDestroy(chain);
        for (uint16_t i = 0; i < 256; ++i)
        {
            tunnels[i]->chain = NULL;
        }
    }
}

static void testArrayLimit(tunnel_t **tunnels)
{
    tunnel_array_t       array   = {0};
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    const uint16_t sizes[] = {64, 65, 256};
    for (size_t size = 0; size < ARRAY_SIZE(sizes); ++size)
    {
        for (uint16_t i = array.len; i < sizes[size]; ++i)
        {
            tunnelarrayInsert(&array, tunnels[i]);
        }
        require(! startupFailurePending(), "valid tunnel array size was rejected");
        require(array.len == sizes[size], "valid tunnel array size lost a tunnel");
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "256-node tunnel array was rejected");
    log_message[0] = '\0';
    wwStartupContextBegin(&startup);
    tunnelarrayInsert(&array, tunnels[256]);
    requireLimitFailure(&startup);
    require(array.len == 256, "rejected array insertion changed the length");
    for (uint16_t i = 0; i < 256; ++i)
    {
        require(array.tuns[i] == tunnels[i], "rejected array insertion changed the contents");
        require(tunnels[i]->chain == NULL, "standalone array acquired tunnel chain ownership");
    }
    require(tunnels[256]->chain == NULL, "rejected array tunnel acquired chain ownership");
}

static void testCombineLimit(tunnel_t **tunnels, uint16_t count)
{
    tunnel_chain_t      *destination = tunnelchainCreate(0);
    tunnel_chain_t      *source      = tunnelchainCreate(0);
    ww_startup_context_t startup     = {0};
    require(destination != NULL && source != NULL, "failed to allocate chains to combine");
    wwStartupContextBegin(&startup);
    for (uint16_t i = 0; i < count; ++i)
    {
        tunnelchainInsert(i < 128 ? destination : source, tunnels[i]);
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "failed to populate chains to combine");

    log_message[0] = '\0';
    wwStartupContextBegin(&startup);
    tunnelchainCombine(destination, source);
    if (count == 256)
    {
        require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "combined 256-node chain was rejected");
        require(destination->tunnels.len == 256, "combined chain lost a tunnel");
        require(destination->sum_padding_left == 256 && destination->sum_line_state_size == 256 * 32,
                "combined chain lost tunnel requirements");
    }
    else
    {
        requireLimitFailure(&startup);
        require(destination->tunnels.len == 128 && source->tunnels.len == 129, "rejected merge changed chain lengths");
        require(destination->sum_padding_left == 128 && destination->sum_line_state_size == 128 * 32 &&
                    source->sum_padding_left == 129 && source->sum_line_state_size == 129 * 32,
                "rejected merge changed chain requirements");
    }
    for (uint16_t i = 0; i < count; ++i)
    {
        tunnel_chain_t *owner = count == 256 || i < 128 ? destination : source;
        require(tunnels[i]->chain == owner, "merge left incorrect tunnel ownership");
        require(owner->tunnels.tuns[owner == destination ? i : i - 128] == tunnels[i],
                "merge left incorrect chain contents");
    }
    if (count != 256)
    {
        tunnelchainDestroy(source);
    }
    tunnelchainDestroy(destination);
    for (uint16_t i = 0; i < count; ++i)
    {
        tunnels[i]->chain = NULL;
    }
}

int main(void)
{
    testCaseSet("chain_node_limit_test");
    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create logger");
    loggerSetHandler(logger, captureLog);
    setInternalLogger(logger);

    node_t    node = {.type = (char *) "TestTunnel", .required_padding_left = 1};
    tunnel_t *tunnels[257];
    for (size_t i = 0; i < ARRAY_SIZE(tunnels); ++i)
    {
        tunnels[i] = tunnelCreate(&node, 0, 32);
        require(tunnels[i] != NULL, "failed to create tunnel");
    }

    testInsertionLimit(tunnels);
    testIndexedInsertion(tunnels);
    testArrayLimit(tunnels);
    testCombineLimit(tunnels, 256);
    testCombineLimit(tunnels, 257);

    for (size_t i = 0; i < ARRAY_SIZE(tunnels); ++i)
    {
        tunnelDestroy(tunnels[i]);
    }
    internaloggerDestroy();
    return 0;
}
