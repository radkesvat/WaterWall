#pragma once

#include "wwapi.h"

/*
 * Tunnel half of the ENet nodes, shared by EnetClient and EnetServer.
 *
 * An association joins two normal lines through one ENet session:
 *   - the application line carries the reliable byte stream;
 *   - the carrier line carries ENet datagrams to and from a UDP adapter.
 * EnetClient borrows the application line from the previous node and creates the carrier line toward the next
 * node. EnetServer borrows the carrier line from the previous node and creates the application line toward the
 * next node when ENet admits the native connection. Only the creator of a line destroys it.
 */

typedef enum enet_endpoint_role_e
{
    kEnetClientEndpoint,
    kEnetServerEndpoint,
} enet_endpoint_role_t;

/* Immutable node-owned output mapping, borrowed for the tunnel's lifetime. Each callback uses the normal tunnel
 * dispatch helpers, so the callback direction stays visible in the node. Payload transfers its buffer on every
 * return. Common code holds references across callouts and owns state cleanup and lineDestroy(); Finish callbacks
 * only notify the adjacent node. carrier_est is NULL in the client, which consumes Est on its application line. */
typedef struct enet_output_s
{
    TunnelFlowRoutineInit    init_owned; /* starts the line this node creates */
    TunnelFlowRoutineEst     application_est;
    TunnelFlowRoutinePayload application_payload;
    TunnelFlowRoutinePause   application_pause;
    TunnelFlowRoutineResume  application_resume;
    TunnelFlowRoutineFin     application_finish;
    TunnelFlowRoutineEst     carrier_est;
    TunnelFlowRoutinePayload carrier_payload;
    TunnelFlowRoutinePause   carrier_pause;
    TunnelFlowRoutineResume  carrier_resume;
    TunnelFlowRoutineFin     carrier_finish;
} enet_output_t;

/* Creates the tunnel with the shared state, the parsed settings and the lifecycle hooks. The node registers its
 * flow callbacks on the result. Returns NULL after logging when a setting is invalid. */
tunnel_t *enetEndpointCreate(node_t *node, enet_endpoint_role_t role, const enet_output_t *output);

/* Node callbacks name the exact line role. These functions own admission, pressure composition, close order and
 * reentrant cleanup. */
void enetEndpointClientInit(tunnel_t *t, line_t *application);
void enetEndpointServerInit(tunnel_t *t, line_t *carrier);
void enetEndpointApplicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void enetEndpointCarrierPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void enetEndpointApplicationEst(tunnel_t *t, line_t *line);
void enetEndpointCarrierEst(tunnel_t *t, line_t *line);
void enetEndpointSetApplicationPaused(tunnel_t *t, line_t *line, bool paused);
void enetEndpointSetCarrierPaused(tunnel_t *t, line_t *line, bool paused);
void enetEndpointApplicationFinish(tunnel_t *t, line_t *line);
void enetEndpointCarrierFinish(tunnel_t *t, line_t *line);
