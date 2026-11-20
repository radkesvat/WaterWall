#pragma once

#include "wwapi.h"

/*
 * Tunnel half of the GNS nodes, shared by GnsClient and GnsServer.
 *
 * An association joins two normal lines through one GNS session:
 *   - the application line carries the reliable byte stream;
 *   - the carrier line carries GNS datagrams to and from a UDP adapter.
 * GnsClient borrows the application line from the previous node and creates the carrier line toward the next
 * node. GnsServer borrows the carrier line from the previous node and creates the application line toward the
 * next node when GNS admits the native connection. Only the creator of a line destroys it.
 */

typedef enum gns_endpoint_role_e
{
    kGnsClientEndpoint,
    kGnsServerEndpoint,
} gns_endpoint_role_t;

/* Immutable node-owned output mapping, borrowed for the tunnel's lifetime. Each callback uses the normal tunnel
 * dispatch helpers, so the callback direction stays visible in the node. Payload transfers its buffer on every
 * return. Common code holds references across callouts and owns state cleanup and lineDestroy(); Finish callbacks
 * only notify the adjacent node. carrier_est is NULL in the client, which consumes Est on its application line. */
typedef struct gns_output_s
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
} gns_output_t;

/* Creates the tunnel with the shared state, the parsed settings and the lifecycle hooks. The node registers its
 * flow callbacks on the result. Returns NULL after logging when a setting is invalid. */
tunnel_t *gnsEndpointCreate(node_t *node, gns_endpoint_role_t role, const gns_output_t *output);

/* Node callbacks name the exact line role. These functions own admission, pressure composition, close order and
 * reentrant cleanup. */
void gnsEndpointClientInit(tunnel_t *t, line_t *application);
void gnsEndpointServerInit(tunnel_t *t, line_t *carrier);
void gnsEndpointApplicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void gnsEndpointCarrierPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void gnsEndpointApplicationEst(tunnel_t *t, line_t *line);
void gnsEndpointCarrierEst(tunnel_t *t, line_t *line);
void gnsEndpointSetApplicationPaused(tunnel_t *t, line_t *line, bool paused);
void gnsEndpointSetCarrierPaused(tunnel_t *t, line_t *line, bool paused);
void gnsEndpointApplicationFinish(tunnel_t *t, line_t *line);
void gnsEndpointCarrierFinish(tunnel_t *t, line_t *line);
