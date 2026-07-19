#pragma once

/*
 * Declares packet-oriented tunnel defaults used by L3/L4 style nodes.
 */

#include "tunnel.h"

/**
 * @brief Create a packet tunnel with standard lifecycle pass-through routines and mandatory payload overrides.
 *
 * @param node Owner node.
 * @param tstate_size Tunnel-local state size.
 * @param lstate_size Must be zero for packet tunnels.
 * @return tunnel_t* Created packet tunnel.
 */
tunnel_t *packettunnelCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size);
