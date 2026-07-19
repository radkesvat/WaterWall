#pragma once

/*
 * Declares adapter tunnel helpers for chain ends and index assignment.
 */

#include "tunnel.h"

/**
 * @brief Default chain callback for an upstream-end adapter.
 *
 * @param t Adapter tunnel.
 * @param tc Chain being built.
 */
void adapterDefaultOnChainUpEnd(tunnel_t *t, tunnel_chain_t *tc);

/**
 * @brief Default chain callback for a downstream-end adapter.
 *
 * @param t Adapter tunnel.
 * @param tc Chain being built.
 */
void adapterDefaultOnChainDownEnd(tunnel_t *t, tunnel_chain_t *tc);


/**
 * @brief Default index assignment for an upstream-end adapter.
 *
 * @param t Adapter tunnel.
 * @param index Chain index.
 * @param mem_offset Running line-state offset.
 */
void adapterDefaultOnIndexUpEnd(tunnel_t *t, uint16_t index, uint32_t *mem_offset);

/**
 * @brief Default index assignment for a downstream-end adapter.
 *
 * @param t Adapter tunnel.
 * @param index Chain index.
 * @param mem_offset Running line-state offset.
 */
void adapterDefaultOnIndexDownEnd(tunnel_t *t, uint16_t index, uint32_t *mem_offset);


/**
 * @brief Create an adapter tunnel and disable invalid edge routines.
 *
 * @param node Owner node.
 * @param tstate_size Adapter state size.
 * @param lstate_size Per-line state size.
 * @param up_end True for an upstream edge adapter, false for downstream edge.
 * @return tunnel_t* Created adapter tunnel.
 */
tunnel_t *adapterCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size, bool up_end);










