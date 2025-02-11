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
 * @brief Initialize the upstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamInit(tunnel_t *t, line_t *line);

/**
 * @brief Establish the upstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamEst(tunnel_t *t, line_t *line);

/**
 * @brief Finalize the upstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamFin(tunnel_t *t, line_t *line);

/**
 * @brief Handle upstream payload.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
void pipetunnelDefaultUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload);

/**
 * @brief Pause the upstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamPause(tunnel_t *t, line_t *line);

/**
 * @brief Resume the upstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultUpStreamResume(tunnel_t *t, line_t *line);

/**
 * @brief Initialize the downstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultdownStreamInit(tunnel_t *t, line_t *line);

/**
 * @brief Establish the downstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultdownStreamEst(tunnel_t *t, line_t *line);

/**
 * @brief Finalize the downstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultdownStreamFin(tunnel_t *t, line_t *line);

/**
 * @brief Handle downstream payload.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 * @param payload Pointer to the payload.
 */
void pipetunnelDefaultdownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload);

/**
 * @brief Pause the downstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultDownStreamPause(tunnel_t *t, line_t *line);

/**
 * @brief Resume the downstream pipeline.
 * 
 * @param t Pointer to the tunnel.
 * @param line Pointer to the line.
 */
void pipetunnelDefaultDownStreamResume(tunnel_t *t, line_t *line);

/**
 * @brief Handle the tunnel chain.
 * 
 * @param t Pointer to the tunnel.
 * @param tc Pointer to the tunnel chain.
 */
void pipetunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc);

/**
 * @brief Handle the tunnel index.
 * 
 * @param t Pointer to the tunnel.
 * @param arr Pointer to the tunnel array.
 * @param index Pointer to the index.
 * @param mem_offset Pointer to the memory offset.
 */
void pipetunnelDefaultOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);

/**
 * @brief Prepare the tunnel.
 * 
 * @param t Pointer to the tunnel.
 */
void pipetunnelDefaultOnPrepair(tunnel_t *t);

/**
 * @brief Start the tunnel.
 * 
 * @param t Pointer to the tunnel.
 */
void pipetunnelDefaultOnStart(tunnel_t *t);

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
void pipeTo(tunnel_t *t, line_t* l, wid_t wid_to);
