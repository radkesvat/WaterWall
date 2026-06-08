#pragma once

/*
 * Declares cross-worker pipe tunnel APIs.
 */

#include "shiftbuffer.h"
#include "tunnel.h"

/**
 * @brief Create a new pipeline tunnel.
 *
 * @param child Pointer to the child tunnel.
 * @return tunnel_t* Pointer to the created tunnel.
 */
tunnel_t *pipetunnelCreate(tunnel_t *child);

/**
 * @brief Destroy the pipeline tunnel.
 *
 * @param t Pointer to the tunnel.
 */
void pipetunnelDestroy(tunnel_t *t);

/**
 * @brief Pipe to a specific WID.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 * @param wid_to WID to pipe to.
 */
bool pipeTo(tunnel_t *t, line_t *l, wid_t wid_to);
