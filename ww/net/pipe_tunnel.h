#pragma once

/*
 * Declares cross-worker pipe tunnel APIs.
 */

#include "shiftbuffer.h"
#include "tunnel.h"

enum
{
    /* Queue charge (sbufGetQueueCharge) one direction of a piped line may have
     * waiting on the other worker. Past the high watermark the pipe pauses that
     * direction's producer on the sending worker, where it takes effect at
     * once; it resumes the producer when the other worker is down to the low
     * watermark. */
    kPipeTunnelQueueHighWater = 1U << 20,
    kPipeTunnelQueueLowWater  = 1U << 19
};

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
void pipetunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);

/**
 * @brief Pipe to a specific WID.
 * Copies ingress metadata, the source line's current mark and destination transport
 * offer before destination-worker Init.
 *
 * @param t Pointer to the tunnel.
 * @param l Pointer to the line.
 * @param wid_to WID to pipe to.
 */
bool pipeTo(tunnel_t *t, line_t *l, wid_t wid_to);
