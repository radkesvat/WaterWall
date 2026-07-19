#include "chain.h"
#include "objects/node.h"
#include "tunnel.h"

#include <stdio.h>
#include <stdlib.h>

enum
{
    kTunnelCount   = 19,
    kLineStateSize = 3712
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

int main(void)
{
    node_t node = {
        .name        = (char *) "line-state-index-test",
        .type        = (char *) "TestTunnel",
        .layer_group = kNodeLayer4,
    };
    tunnel_chain_t *chain = tunnelchainCreate(0);
    tunnel_t       *tunnels[kTunnelCount];

    require(chain != NULL, "failed to create test chain");

    for (uint16_t i = 0; i < kTunnelCount; ++i)
    {
        tunnels[i] = tunnelCreate(&node, 0, kLineStateSize);
        require(tunnels[i] != NULL, "failed to create test tunnel");
        require(tunnels[i]->lstate_size == kLineStateSize, "unexpected aligned line-state size");
        tunnelchainInsert(chain, tunnels[i]);
    }

    uint32_t mem_offset = 0;
    for (uint16_t i = 0; i < kTunnelCount; ++i)
    {
        tunnels[i]->onIndex(tunnels[i], i, &mem_offset);
    }

    require(tunnels[18]->lstate_offset == 66816U, "19th line-state offset wrapped below 64 KiB");
    require(mem_offset == 70528U, "indexed line-state total is incorrect");
    require(mem_offset == chain->sum_line_state_size, "indexed and accumulated line-state totals differ");

    tunnelchainDestroy(chain);
    for (uint16_t i = 0; i < kTunnelCount; ++i)
    {
        tunnelDestroy(tunnels[i]);
    }

    return 0;
}
