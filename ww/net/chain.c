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

void tunnelchainInsert(tunnel_chain_t *tci, tunnel_t *t)
{
    tunnelarrayInesert(&(tci->tunnels), t);
    tci->sum_padding_left += t->node->metadata.required_padding_left;
    tci->sum_line_state_size += t->lstate_size;
    t->chain = tci;
    
}

tunnel_chain_t *tunnelchainCreate(void)
{
    tunnel_chain_t *tc = memoryAllocate(sizeof(tunnel_chain_t) + sizeof(void *) * getWorkersCount());
    return tc;
}

void tunnelchainFinalize(tunnel_chain_t *tc)
{
    tc->masterpool_line_pool = masterpoolCreateWithCapacity(2 * ((8) + GSTATE.ram_profile));

    for (uint32_t i = 0; i < tc->workers_count; i++)
    {
        tc->line_pools[i] = genericpoolCreateWithDefaultAllocatorAndCapacity(
            tc->masterpool_line_pool , tc->sum_line_state_size, (8) + GSTATE.ram_profile);
    }

    
    for (int wi = 0; wi < getWorkersCount(); wi++)
    {
        bufferpoolUpdateAllocationPaddings(getWorkerBufferPool(wi), tc->sum_padding_left,
                                            tc->sum_padding_left);
    }


}

void tunnelchainDestroy(tunnel_chain_t *tc)
{
    for (uint32_t i = 0; i < tc->workers_count; i++)
    {
        genericpoolDestroy(tc->line_pools[i]);
    }
    memoryFree(tc);
}

generic_pool_t *tunnelchainGetLinePool(tunnel_chain_t *tc, uint32_t tid)
{
    return tc->line_pools[tid];
}
