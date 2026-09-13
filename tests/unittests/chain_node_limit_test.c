#include "loggers/internal_logger.h"
#include "wwapi.h"

static char log_message[1024];

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void captureLog(int level, const char *buf, int len)
{
    discard level;
    snprintf(log_message, sizeof(log_message), "%.*s", len, buf);
}

static void requireLimitFailure(ww_startup_context_t *startup)
{
    require(wwStartupContextEnd(startup).exit_code == 1, "oversized chain did not fail startup");
    require(strstr(log_message, "maximum of 64 nodes per chain") != NULL,
            "chain-limit error did not clearly state the 64-node maximum");
}

static void testInsertionLimit(tunnel_t **tunnels)
{
    tunnel_chain_t      *chain   = tunnelchainCreate(0);
    ww_startup_context_t startup = {0};
    require(chain != NULL, "failed to allocate chain");
    wwStartupContextBegin(&startup);
    for (uint16_t i = 0; i < 64; ++i)
    {
        tunnelchainInsert(chain, tunnels[i]);
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "64-node chain was rejected");
    require(chain->tunnels.len == 64, "64-node chain lost a tunnel");

    const uint16_t positions[] = {0, 32, 64};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i)
    {
        log_message[0] = '\0';
        wwStartupContextBegin(&startup);
        tunnelchainInsertAt(chain, tunnels[64], positions[i]);
        requireLimitFailure(&startup);
        require(chain->tunnels.len == 64, "rejected insertion changed the chain length");
        require(tunnels[64]->chain == NULL, "rejected tunnel acquired chain ownership");
        for (uint16_t j = 0; j < 64; ++j)
        {
            require(chain->tunnels.tuns[j] == tunnels[j], "rejected insertion changed the chain contents");
        }
    }
    tunnelchainDestroy(chain);
}

static void testArrayLimit(tunnel_t **tunnels)
{
    tunnel_array_t       array   = {0};
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    for (uint16_t i = 0; i < 64; ++i)
    {
        tunnelarrayInsert(&array, tunnels[i]);
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "64-node tunnel array was rejected");
    log_message[0] = '\0';
    wwStartupContextBegin(&startup);
    tunnelarrayInsert(&array, tunnels[64]);
    requireLimitFailure(&startup);
    require(array.len == 64, "rejected array insertion changed the length");
    for (uint16_t i = 0; i < 64; ++i)
    {
        require(array.tuns[i] == tunnels[i], "rejected array insertion changed the contents");
    }
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
        tunnelchainInsert(i < 32 ? destination : source, tunnels[i]);
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "failed to populate chains to combine");

    log_message[0] = '\0';
    wwStartupContextBegin(&startup);
    tunnelchainCombine(destination, source);
    if (count == 64)
    {
        require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "combined 64-node chain was rejected");
        require(destination->tunnels.len == 64, "combined chain lost a tunnel");
    }
    else
    {
        requireLimitFailure(&startup);
        require(destination->tunnels.len == 32 && source->tunnels.len == 33, "rejected merge changed chain lengths");
    }
    for (uint16_t i = 0; i < count; ++i)
    {
        tunnel_chain_t *owner = count == 64 || i < 32 ? destination : source;
        require(tunnels[i]->chain == owner, "merge left incorrect tunnel ownership");
        require(owner->tunnels.tuns[owner == destination ? i : i - 32] == tunnels[i],
                "merge left incorrect chain contents");
    }
    if (count != 64)
    {
        tunnelchainDestroy(source);
    }
    tunnelchainDestroy(destination);
}

int main(void)
{
    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create logger");
    loggerSetHandler(logger, captureLog);
    setInternalLogger(logger);

    node_t    node = {.type = (char *) "TestTunnel"};
    tunnel_t *tunnels[65];
    for (size_t i = 0; i < 65; ++i)
    {
        tunnels[i] = tunnelCreate(&node, 0, 0);
        require(tunnels[i] != NULL, "failed to create tunnel");
    }

    testInsertionLimit(tunnels);
    testArrayLimit(tunnels);
    testCombineLimit(tunnels, 64);
    testCombineLimit(tunnels, 65);

    for (size_t i = 0; i < 65; ++i)
    {
        tunnelDestroy(tunnels[i]);
    }
    internaloggerDestroy();
    return 0;
}
