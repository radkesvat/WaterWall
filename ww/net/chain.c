#include "chain.h"

/*
 * Implements tunnel chain construction, finalization, merging, and teardown.
 */

#include "global_state.h"
#include "line.h"
#include "objects/node.h"

#include "loggers/internal_logger.h"

static bool tunnelchainNodeIsMuxTunnel(const node_t *node)
{
    return stringCompare(node->type, "MuxClient") == 0 || stringCompare(node->type, "MuxServer") == 0;
}
bool tunnelchainTryComputeLineItemSize(uint32_t aggregate_lstate_size, uint32_t *item_size)
{
    const uint64_t total = (uint64_t) sizeof(line_t) + (uint64_t) aggregate_lstate_size;
    if (item_size == NULL || total > UINT32_MAX ||
        ! memoryAlignedAllocationSizeIsRepresentable((size_t) total, kCpuLineCacheSize))
    {
        return false;
    }

    *item_size = (uint32_t) total;
    return true;
}

void tunnelarrayInsert(tunnel_array_t *tc, tunnel_t *t)
{
    if (tc->len >= kMaxChainLen)
    {
        LOGF("tunnelarrayInsert overflow!");
        startupFailureRecord(1);
        return;
    }

    tc->tuns[tc->len++] = t;
}

void tunnelchainInsertAt(tunnel_chain_t *tci, tunnel_t *t, uint16_t index)
{
    if (UNLIKELY(index > tci->tunnels.len || tci->tunnels.len >= kMaxChainLen))
    {
        LOGF("tunnelchainInsertAt: invalid insertion index or full chain");
        startupFailureRecord(1);
        return;
    }

    uint16_t next_padding;
    if (UNLIKELY(
            ! tunnelchainTryAddPadding(tci->sum_padding_left, tunnelGetNode(t)->required_padding_left, &next_padding)))
    {
        LOGF("tunnelchainInsert: total left-padding size overflow");
        startupFailureRecord(1);
        return;
    }

    uint32_t next_line_state_size;
    uint32_t line_item_size;
    if (UNLIKELY(t->lstate_size > UINT32_MAX - tci->sum_line_state_size))
    {
        LOGF("tunnelchainInsert: total line-state size overflow");
        startupFailureRecord(1);
        return;
    }
    next_line_state_size = tci->sum_line_state_size + t->lstate_size;
    if (UNLIKELY(! tunnelchainTryComputeLineItemSize(next_line_state_size, &line_item_size)))
    {
        LOGF("tunnelchainInsert: complete line-pool item size exceeds uint32_t");
        startupFailureRecord(1);
        return;
    }
    discard line_item_size;

    if (index < tci->tunnels.len)
    {
        memoryMove(&tci->tunnels.tuns[index + 1],
                   &tci->tunnels.tuns[index],
                   (size_t) (tci->tunnels.len - index) * sizeof(tci->tunnels.tuns[0]));
    }
    tci->tunnels.tuns[index] = t;
    tci->tunnels.len++;
    tci->sum_padding_left     = next_padding;
    tci->sum_line_state_size  = next_line_state_size;
    tci->contains_packet_node = false;
    tci->layer_solution_ready = false;
    memoryZero(tci->resolved_prev_layer, sizeof(tci->resolved_prev_layer));
    memoryZero(tci->resolved_next_layer, sizeof(tci->resolved_next_layer));
    if (tunnelchainNodeIsMuxTunnel(tunnelGetNode(t)))
    {
        tci->mux_tunnel_present = true;
    }

    t->chain = tci;
}

void tunnelchainInsert(tunnel_chain_t *tci, tunnel_t *t)
{
    tunnelchainInsertAt(tci, t, tci->tunnels.len);
}

tunnel_chain_t *tunnelchainCreate(wid_t workers_count)
{
    const size_t count = (size_t) workers_count;
    size_t       pointer_bytes;
    if (UNLIKELY(count != 0 && sizeof(void *) > SIZE_MAX / count))
    {
        return NULL;
    }
    pointer_bytes = count * sizeof(void *);
    if (UNLIKELY(pointer_bytes > SIZE_MAX - sizeof(tunnel_chain_t)))
    {
        return NULL;
    }
    size_t          size = sizeof(tunnel_chain_t) + pointer_bytes;
    tunnel_chain_t *tc   = memoryAllocateZero(size);
    if (UNLIKELY(tc == NULL))
    {
        return NULL;
    }
    tc->workers_count = workers_count;
    return tc;
}

void tunnelchainFinalize(tunnel_chain_t *tc)
{
    uint32_t line_item_size;
    if (UNLIKELY(! tunnelchainTryComputeLineItemSize(tc->sum_line_state_size, &line_item_size)))
    {
        LOGF("tunnelchainFinalize: complete line-pool item size exceeds uint32_t");
        startupFailureRecord(1);
        return;
    }

    master_pool_t *master_pool = masterpoolCreateWithCapacity(2 * ((8) + GSTATE.ram_profile));
    if (UNLIKELY(master_pool == NULL))
    {
        LOGF("TunnelChain: failed to construct line master-pool metadata");
        startupFailureRecord(1);
        return;
    }

    line_t **packet_lines = memoryAllocate(sizeof(*packet_lines) * tc->workers_count);
    if (UNLIKELY(packet_lines == NULL))
    {
        masterpoolDestroy(master_pool);
        LOGF("TunnelChain: failed to allocate packet-line slots");
        startupFailureRecord(1);
        return;
    }

    for (wid_t i = 0; i < tc->workers_count; i++)
    {
        tc->line_pools[i] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            master_pool, line_item_size, (8) + GSTATE.ram_profile);

        if (UNLIKELY(tc->line_pools[i] == NULL))
        {
            for (wid_t cleanup = 0; cleanup < i; ++cleanup)
            {
                genericpoolDestroy(tc->line_pools[cleanup]);
                tc->line_pools[cleanup] = NULL;
            }
            memoryFree(packet_lines);
            masterpoolDestroy(master_pool);
            LOGF("TunnelChain: failed to construct line-pool metadata for worker %d", (int) i);
            startupFailureRecord(1);
            return;
        }
    }

    tc->masterpool_line_pool = master_pool;
    tc->packet_lines         = packet_lines;

    for (wid_t i = 0; i < tc->workers_count; i++)
    {
        if (tc->contains_packet_node)
        {
            packet_lines[i] = lineCreateForWorker(0, tc->line_pools, i);
        }
        else
        {
            packet_lines[i] = NULL;
        }
    }

    globalstateUpdateAllocationPadding(tc->sum_padding_left);
    tc->finalized = true;
}

bool tunnelchainIsWorkerPacketLine(tunnel_chain_t *tc, const line_t *l)
{
    if (tc == NULL || l == NULL || tc->packet_lines == NULL)
    {
        return false;
    }

    // The owning worker is the only slot a packet line can occupy, so this is an
    // exact identity check and not a scan.
    wid_t wid = lineGetWID(l);

    return workerWIDIsRegistered(wid) && wid < tc->workers_count && tc->packet_lines[wid] == l;
}

void tunnelchainDestroy(tunnel_chain_t *tc)
{
    for (uint32_t i = 0; i < tc->workers_count; i++)
    {
        if (tc->packet_lines && tc->packet_lines[i])
        {
            lineDestroy(tc->packet_lines[i]);
        }
    }
    // since we destroyed all lines on main thread, we need to free line pools later, not there after each line
    // because on dsetruction of each line it needs pool[getWID()] to be valid
    if (tc->masterpool_line_pool && masterpoolGetCheckedOut(tc->masterpool_line_pool) != 0)
    {
        LOGF("TunnelChain: line-pool family still has %zu outstanding physical reference(s) at teardown",
             masterpoolGetCheckedOut(tc->masterpool_line_pool));
        abortProgramNow(1);
    }
    for (uint32_t i = 0; i < tc->workers_count; i++)
    {
        if (tc->line_pools[i])
        {
            genericpoolDestroy(tc->line_pools[i]);
        }
    }

    if (tc->masterpool_line_pool)
    {
        masterpoolMakeEmpty(tc->masterpool_line_pool);
        masterpoolDestroy(tc->masterpool_line_pool);
    }

    if (tc->packet_lines)
    {
        memoryFree((void *) tc->packet_lines);
    }
    memoryFree(tc);
}

static bool tunnelchainLayerRelationsMatch(
    const tunnel_layer_relation_registration_t *left,
    const tunnel_layer_relation_registration_t *right)
{
    if (left->kind != right->kind)
    {
        return false;
    }

    return (left->left_tunnel == right->left_tunnel && left->left_side == right->left_side &&
            left->right_tunnel == right->right_tunnel && left->right_side == right->right_side) ||
           (left->left_tunnel == right->right_tunnel && left->left_side == right->right_side &&
            left->right_tunnel == right->left_tunnel && left->right_side == right->left_side);
}

bool tunnelchainRegisterLayerRelation(
    tunnel_chain_t              *chain,
    tunnel_t                    *left,
    tunnel_layer_side_t          left_side,
    tunnel_t                    *right,
    tunnel_layer_side_t          right_side,
    tunnel_layer_relation_kind_t kind)
{
    if (chain == NULL || left == NULL || right == NULL)
    {
        LOGF("tunnelchainRegisterLayerRelation: NULL argument provided");
        startupFailureRecord(1);
        return false;
    }

    if ((left_side != kTunnelLayerSidePrev && left_side != kTunnelLayerSideNext) ||
        (right_side != kTunnelLayerSidePrev && right_side != kTunnelLayerSideNext) ||
        (kind != kTunnelLayerRelationSame && kind != kTunnelLayerRelationOpposite))
    {
        LOGF("tunnelchainRegisterLayerRelation: invalid side or relation kind");
        startupFailureRecord(1);
        return false;
    }

    if (chain->finalized)
    {
        LOGF("tunnelchainRegisterLayerRelation: cannot register relation on finalized chain");
        startupFailureRecord(1);
        return false;
    }

    const tunnel_layer_relation_registration_t candidate = {
        .left_tunnel  = left,
        .left_side    = left_side,
        .right_tunnel = right,
        .right_side   = right_side,
        .kind         = kind,
    };

    // Check for deduplication (both direct order and symmetric swapped order)
    for (uint16_t i = 0; i < chain->layer_relations_count; i++)
    {
        const tunnel_layer_relation_registration_t *r = &chain->layer_relations[i];
        if (tunnelchainLayerRelationsMatch(r, &candidate))
        {
            return true;
        }
    }

    if (chain->layer_relations_count >= kMaxLayerRelations)
    {
        LOGF("tunnelchainRegisterLayerRelation: capacity overflow (%u >= %u)",
             chain->layer_relations_count, (unsigned int) kMaxLayerRelations);
        startupFailureRecord(1);
        return false;
    }

    tunnel_layer_relation_registration_t *reg = &chain->layer_relations[chain->layer_relations_count++];
    reg->left_tunnel                          = left;
    reg->left_side                            = left_side;
    reg->right_tunnel                         = right;
    reg->right_side                           = right_side;
    reg->kind                                 = kind;

    chain->contains_packet_node = false;
    chain->layer_solution_ready = false;
    memoryZero(chain->resolved_prev_layer, sizeof(chain->resolved_prev_layer));
    memoryZero(chain->resolved_next_layer, sizeof(chain->resolved_next_layer));
    return true;
}

void tunnelchainCombine(tunnel_chain_t *destination, tunnel_chain_t *source)
{
    if (destination->finalized || source->finalized)
    {
        LOGF("tunnelchainCombine: cannot combine finalized chains");
        startupFailureRecord(1);
        return;
    }

    // Check if combining would exceed maximum chain length
    if (destination->tunnels.len + source->tunnels.len > kMaxChainLen)
    {
        LOGF("tunnelchainCombine: Combined chain would exceed maximum length (%d + %d > %d)",
             destination->tunnels.len,
             source->tunnels.len,
             kMaxChainLen);
        startupFailureRecord(1);
        return;
    }

    // Check if worker counts match
    if (destination->workers_count != source->workers_count)
    {
        LOGF("tunnelchainCombine: Worker counts don't match (%d != %d)",
             destination->workers_count,
             source->workers_count);
        startupFailureRecord(1);
        return;
    }

    uint16_t combined_relations_count = destination->layer_relations_count;
    for (uint16_t i = 0; i < source->layer_relations_count; ++i)
    {
        const tunnel_layer_relation_registration_t *candidate = &source->layer_relations[i];
        bool duplicate = false;

        for (uint16_t j = 0; j < destination->layer_relations_count; ++j)
        {
            if (tunnelchainLayerRelationsMatch(candidate, &destination->layer_relations[j]))
            {
                duplicate = true;
                break;
            }
        }
        if (! duplicate)
        {
            for (uint16_t j = 0; j < i; ++j)
            {
                if (tunnelchainLayerRelationsMatch(candidate, &source->layer_relations[j]))
                {
                    duplicate = true;
                    break;
                }
            }
        }

        if (! duplicate && combined_relations_count++ >= kMaxLayerRelations)
        {
            LOGF("tunnelchainCombine: combined layer-relation count exceeds capacity (%u)",
                 (unsigned int) kMaxLayerRelations);
            startupFailureRecord(1);
            return;
        }
    }

    uint16_t combined_padding;
    if (UNLIKELY(
            ! tunnelchainTryAddPadding(destination->sum_padding_left, source->sum_padding_left, &combined_padding)))
    {
        LOGF("tunnelchainCombine: combined left-padding size overflow");
        startupFailureRecord(1);
        return;
    }
    discard combined_padding;

    uint32_t combined_line_state_size;
    uint32_t line_item_size;
    if (UNLIKELY(source->sum_line_state_size > UINT32_MAX - destination->sum_line_state_size))
    {
        LOGF("tunnelchainCombine: combined line-state size overflow");
        startupFailureRecord(1);
        return;
    }
    combined_line_state_size = destination->sum_line_state_size + source->sum_line_state_size;
    if (UNLIKELY(! tunnelchainTryComputeLineItemSize(combined_line_state_size, &line_item_size)))
    {
        LOGF("tunnelchainCombine: complete line-pool item size exceeds uint32_t");
        startupFailureRecord(1);
        return;
    }
    discard line_item_size;

    // Append all tunnels from source to destination using existing insert function
    for (uint16_t i = 0; i < source->tunnels.len; i++)
    {
        tunnel_t *tunnel = source->tunnels.tuns[i];
        tunnelchainInsert(destination, tunnel);
        if (UNLIKELY(startupFailurePending()))
        {
            return;
        }
    }

    // Copy all layer relation registrations from source into destination
    for (uint16_t i = 0; i < source->layer_relations_count; i++)
    {
        const tunnel_layer_relation_registration_t *r = &source->layer_relations[i];
        if (! tunnelchainRegisterLayerRelation(destination,
                                               r->left_tunnel, r->left_side,
                                               r->right_tunnel, r->right_side,
                                               r->kind))
        {
            return;
        }
    }

    // Clear the source chain (tunnels are now owned by destination)
    source->tunnels.len           = 0;
    source->sum_padding_left      = 0;
    source->sum_line_state_size   = 0;
    source->contains_packet_node  = false;
    source->mux_tunnel_present    = false;
    source->layer_solution_ready  = false;
    source->layer_relations_count = 0;
    memoryZero(source->resolved_prev_layer, sizeof(source->resolved_prev_layer));
    memoryZero(source->resolved_next_layer, sizeof(source->resolved_next_layer));

    tunnelchainDestroy(source);
}
