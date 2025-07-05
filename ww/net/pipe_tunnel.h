#pragma once
#include "tunnel.h"
#include "shiftbuffer.h"

/**
 * @brief Get the size of the pipeline message.
 * 
 * @return size_t Size of the pipeline message.
 */
size_t pipeTunnelGetMesageSize(void);


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
bool pipeTo(tunnel_t *t, line_t* l, wid_t wid_to);
