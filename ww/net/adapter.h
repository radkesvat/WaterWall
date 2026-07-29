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
 * @brief Default chain callback for a chain-head adapter.
 *
 * @param t Adapter tunnel.
 * @param tc Chain being built.
 */
void adapterDefaultOnChainHead(tunnel_t *t, tunnel_chain_t *tc);

/**
 * @brief Default chain callback for a chain-end adapter.
 *
 * @param t Adapter tunnel.
 * @param tc Chain being built.
 */
void adapterDefaultOnChainEnd(tunnel_t *t, tunnel_chain_t *tc);

/**
 * @brief Default index assignment for a chain-head adapter.
 *
 * @param t Adapter tunnel.
 * @param index Chain index.
 * @param mem_offset Running line-state offset.
 */
void adapterDefaultOnIndexChainHead(tunnel_t *t, uint16_t index, uint32_t *mem_offset);

/**
 * @brief Default index assignment for a chain-end adapter.
 *
 * @param t Adapter tunnel.
 * @param index Chain index.
 * @param mem_offset Running line-state offset.
 */
void adapterDefaultOnIndexChainEnd(tunnel_t *t, uint16_t index, uint32_t *mem_offset);

/**
 * @brief Create an adapter tunnel and disable invalid edge routines.
 *
 * @param node Owner node.
 * @param tstate_size Adapter state size.
 * @param lstate_size Per-line state size.
 * @param edge Chain edge occupied by the adapter.
 * @return tunnel_t* Created adapter tunnel.
 */
tunnel_t *adapterCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size, adapter_edge_t edge);
