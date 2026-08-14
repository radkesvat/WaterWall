#pragma once

/*
 * Declares adapter tunnel helpers for chain ends and index assignment.
 */

#include "tunnel.h"

typedef enum adapter_edge_e
{
    kAdapterChainHead = 0,
    kAdapterChainEnd  = 1
} adapter_edge_t;

/**
 * @brief Create an adapter tunnel and disable invalid edge routines.
 *
 * @param node Owner node.
 * @param tstate_size Adapter state size.
 * @param lstate_size Per-line state size.
 * @param edge Chain edge occupied by the adapter.
 * @return tunnel_t* Created adapter tunnel.
 */
tunnel_t *adapterCreate(node_t *node, size_t tstate_size, size_t lstate_size, adapter_edge_t edge);
