#include "chain.h"
#include "global_state.h"
#include "line.h"
#include "objects/node.h"

#include "loggers/internal_logger.h"

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
            tc->packet_lines[i] = lineCreateForWorker(i,tc->line_pools, i);
        }
    }

    globalstateUpdateAllocationPadding(tc->sum_padding_left);
    tc->finalized = true;
}

void tunnelchainDestroy(tunnel_chain_t *tc)
{
    for (uint32_t i = 0; i < tc->workers_count; i++)
    {
        if (tc->packet_lines)
        {
            lineDestroy(tc->packet_lines[i]);
        }
    }
    // since we destroyed all lines on main thread, we need to free line pools later, not there after each line
    // because on dsetruction of each line it needs pool[getWID()] to be valid
    for (uint32_t i = 0; i < tc->workers_count; i++)
    {
        if (tc->line_pools[i])
        {
            genericpoolDestroy(tc->line_pools[i]);
        }
    }

    if (tc->masterpool_line_pool)
    {
        masterpoolDestroy(tc->masterpool_line_pool);
    }

    if (tc->packet_lines)
    {
        memoryFree((void *) tc->packet_lines);
    }
    memoryFree(tc);
}

void tunnelchainCombine(tunnel_chain_t *destination, tunnel_chain_t *source)
{
    // Check if combining would exceed maximum chain length
    if (destination->tunnels.len + source->tunnels.len > kMaxChainLen)
    {
        LOGF("tunnelchainCombine: Combined chain would exceed maximum length (%d + %d > %d)", destination->tunnels.len,
             source->tunnels.len, kMaxChainLen);
        terminateProgram(1);
    }

    // Check if worker counts match
    if (destination->workers_count != source->workers_count)
    {
        LOGF("tunnelchainCombine: Worker counts don't match (%d != %d)", destination->workers_count,
             source->workers_count);
        terminateProgram(1);
    }

    // Append all tunnels from source to destination using existing insert function
    for (uint16_t i = 0; i < source->tunnels.len; i++)
    {
        tunnel_t *tunnel = source->tunnels.tuns[i];
        tunnelchainInsert(destination, tunnel);
    }

    // Clear the source chain (tunnels are now owned by destination)
    source->tunnels.len          = 0;
    source->sum_padding_left     = 0;
    source->sum_line_state_size  = 0;
    source->contains_packet_node = false;

    tunnelchainDestroy(source);
}
