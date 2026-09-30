#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requirePresence(const tunnel_chain_t *chain, bool client, bool server)
{
    require(chain->mux_client_tunnel_present == client, "incorrect MuxClient presence");
    require(chain->mux_server_tunnel_present == server, "incorrect MuxServer presence");
}

static tunnel_t *createTunnel(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, 0, 0);
    require(t != NULL, "failed to create tunnel");
    return t;
}

static void destroyChain(tunnel_chain_t *chain)
{
    for (uint16_t i = 0; i < chain->tunnels.len; ++i)
    {
        tunnelDestroy(chain->tunnels.tuns[i]);
    }
    tunnelchainDestroy(chain);
}

static void testInsertion(bool client_first)
{
    node_t          normal = {.type = (char *) "TestTunnel"};
    node_t          client = {.type = (char *) "MuxClient"};
    node_t          server = {.type = (char *) "MuxServer"};
    tunnel_chain_t *chain  = tunnelchainCreate(0);
    require(chain != NULL, "failed to allocate chain");
    requirePresence(chain, false, false);

    tunnelchainInsert(chain, createTunnel(&normal));
    requirePresence(chain, false, false);
    tunnelchainInsertAt(chain, createTunnel(client_first ? &client : &server), 0);
    requirePresence(chain, client_first, ! client_first);
    tunnelchainInsert(chain, createTunnel(&normal));
    requirePresence(chain, client_first, ! client_first);
    tunnelchainInsertAt(chain, createTunnel(client_first ? &server : &client), 1);
    requirePresence(chain, true, true);
    tunnelchainInsert(chain, createTunnel(&client));
    tunnelchainInsert(chain, createTunnel(&server));
    requirePresence(chain, true, true);
    destroyChain(chain);
}

static void testCombine(bool destination_client, bool destination_server, bool source_client, bool source_server)
{
    node_t          client      = {.type = (char *) "MuxClient"};
    node_t          server      = {.type = (char *) "MuxServer"};
    tunnel_chain_t *destination = tunnelchainCreate(0);
    tunnel_chain_t *source      = tunnelchainCreate(0);
    require(destination != NULL && source != NULL, "failed to allocate chains to combine");

    if (destination_client)
        tunnelchainInsert(destination, createTunnel(&client));
    if (destination_server)
        tunnelchainInsert(destination, createTunnel(&server));
    if (source_client)
        tunnelchainInsert(source, createTunnel(&client));
    if (source_server)
        tunnelchainInsert(source, createTunnel(&server));
    requirePresence(destination, destination_client, destination_server);
    requirePresence(source, source_client, source_server);

    tunnelchainCombine(destination, source);
    requirePresence(destination, destination_client || source_client, destination_server || source_server);
    for (uint16_t i = 0; i < destination->tunnels.len; ++i)
    {
        require(tunnelGetChain(destination->tunnels.tuns[i]) == destination, "merge left incorrect tunnel ownership");
    }
    destroyChain(destination);
}

int main(void)
{
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    testInsertion(true);
    testInsertion(false);
    for (unsigned destination = 0; destination < 4; ++destination)
    {
        for (unsigned source = 0; source < 4; ++source)
        {
            testCombine((destination & 1U) != 0, (destination & 2U) != 0, (source & 1U) != 0, (source & 2U) != 0);
        }
    }
    require(wwStartupSucceeded(wwStartupContextEnd(&startup)), "chain construction failed");
    return 0;
}
