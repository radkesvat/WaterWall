#include "chain.h"
#include "global_state.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "node_builder/node.h"

void tunnelarrayInsert(tunnel_array_t *tc, tunnel_t *t)
{
    if (t->chain_index == kMaxChainLen)
    {
        LOGF("tunnelarrayInsert overflow!");
        terminateProgram(1);
    }

    tc->tuns[tc->len++] = t;
}

void tunnelchainInsert(tunnel_chain_t *tci, tunnel_t *t)
{
    tunnelarrayInsert(&(tci->tunnels), t);
    tci->sum_padding_left += tunnelGetNode(t)->required_padding_left;
    tci->sum_line_state_size += t->lstate_size;
    if ((tunnelGetNode(t)->layer_group & kNodeLayer3) == kNodeLayer3)
    {
        tci->contains_packet_node = true;
    }

    t->chain = tci;
}

tunnel_chain_t *tunnelchainCreate(wid_t workers_count)
{
    size_t          size = sizeof(tunnel_chain_t) + sizeof(void *) * getWorkersCount();
    tunnel_chain_t *tc   = memoryAllocate(size);
    memorySet(tc, 0, size);
    tc->workers_count = workers_count;
    return tc;
}

void tunnelchainFinalize(tunnel_chain_t *tc)
{
    tc->masterpool_line_pool = masterpoolCreateWithCapacity(2 * ((8) + GSTATE.ram_profile));

    if (tc->contains_packet_node)
    {
        tc->packet_lines = memoryAllocate(sizeof(line_t) * tc->workers_count);
    }

    for (wid_t i = 0; i < tc->workers_count; i++)
    {
        tc->line_pools[i] = genericpoolCreateWithDefaultAllocatorAndCapacity(
            tc->masterpool_line_pool, sizeof(line_t) + tc->sum_line_state_size, (8) + GSTATE.ram_profile);

        if (tc->contains_packet_node)
        {
            tc->packet_lines[i] = lineCreate(tc->line_pools[i], i);
        }
    }

    globalstateUpdateAllocationPadding(tc->sum_padding_left);
}

void tunnelchainDestroy(tunnel_chain_t *tc)
{
    for (uint32_t i = 0; i < tc->workers_count; i++)
    {
        if (tc->contains_packet_node)
        {
            lineDestroy(tc->packet_lines[i]);
        }
        genericpoolDestroy(tc->line_pools[i]);

    }

    masterpoolDestroy(tc->masterpool_line_pool);
    memoryFree((void *) tc->packet_lines);
    memoryFree(tc);
}

generic_pool_t *tunnelchainGetLinePool(tunnel_chain_t *tc, wid_t wid)
{
    return tc->line_pools[wid];
}
