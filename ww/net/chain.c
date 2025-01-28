#include "chain.h"

#include "loggers/internal_logger.h"
#include "node_builder/node.h"

void tunnelarrayInesert(tunnel_array_t *tc, tunnel_t *t)
{
    if (t->chain_index == kMaxChainLen)
    {
        LOGF("tunnelarrayInesert overflow!");
        exit(1);
    }

    tc->tuns[tc->len++] = t;
}

void tunnelchainInestert(tunnel_chain_t *tci, tunnel_t *t)
{
    tunnelarrayInesert(&(tci->tunnels), t);
    tci->sum_padding_left += t->node->metadata.required_padding_left;
    tci->sum_line_state_size += t->lstate_size;
}

tunnel_chain_t *tunnelChainCreate(void)
{
    tunnel_chain_t *tc = memoryAllocate(sizeof(tunnel_chain_t));

    tc->line_pool = newGenericPoolWithCap(GSTATE.masterpool_line_pools, (8) + GSTATE.ram_profile,
                                              allocLinePoolHandle, destroyLinePoolHandle);
}
