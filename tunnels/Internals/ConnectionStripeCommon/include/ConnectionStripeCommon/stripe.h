#pragma once

#include "wwapi.h"

/* Wire integers are big endian; never serialize a native C structure.
 * Header: type(1), reserved zero(3), body length(4), byte offset(8), aux(8).
 * JOIN body: random session identifier(16), lane index(2), count(2), receive window(4).
 * DATA aux is the record index; WINDOW/CLOSE/CLOSE_ACK aux is the record boundary.
 * READY offset is the receive window and aux is the connection count.
 * Every control after JOIN travels on lane zero. */
enum
{
    kStripeHeaderSize       = 24,
    kStripeJoinSize         = 48,
    kStripeJoinBodySize     = kStripeJoinSize - kStripeHeaderSize,
    kStripeMaxConnections   = 32,
    kStripeMaxFrame         = 16384,
    kStripeMinReceiveWindow = kStripeMaxFrame,
    kStripeMaxReceiveWindow = 16 * 1024 * 1024,
    kStripeFrameWindow      = 256,
    kStripeJoin             = 1,
    kStripeReady            = 2,
    kStripeData             = 3,
    kStripeWindow           = 4,
    kStripeClose            = 5,
    kStripeCloseAck         = 6,
};

typedef enum stripe_endpoint_role_e
{
    kStripeClientEndpoint,
    kStripeServerEndpoint,
} stripe_endpoint_role_t;

typedef enum stripe_line_role_e
{
    kStripeApplicationLine,
    kStripeTransportLine,
} stripe_line_role_t;

/* Immutable node-owned output mapping, borrowed for the tunnel's lifetime.
 * Every callback is required and uses the normal tunnel dispatch helpers.
 * Payload transfers its buffer on every return. Common code retains references
 * across callouts and owns state cleanup and lineDestroy(); Finish callbacks
 * only notify the adjacent node. Init starts an owned companion; Est notifies
 * the borrowed application (client) or incoming transport (server). */
typedef struct stripe_output_s
{
    stripe_line_role_t       owned_line_role;
    TunnelFlowRoutineInit    init_owned;
    TunnelFlowRoutineEst     est_borrowed;
    TunnelFlowRoutinePayload transport_payload;
    TunnelFlowRoutinePayload application_payload;
    TunnelFlowRoutinePause   application_pause;
    TunnelFlowRoutineResume  application_resume;
    TunnelFlowRoutineFin     transport_finish;
    TunnelFlowRoutineFin     application_finish;
} stripe_output_t;

/* Creates the shared state and lifecycle hooks; the node registers its flow
 * callbacks. The server node wraps the result in PipeTunnel after registration. */
tunnel_t *connectionstripeCreate(node_t *node, stripe_endpoint_role_t role, const stripe_output_t *output);

/* Node callbacks identify the exact application/transport role. These methods
 * own admission, pressure composition, protocol progress and reentrant cleanup. */
void connectionstripeClientInit(tunnel_t *t, line_t *application);
void connectionstripeServerInit(tunnel_t *t, line_t *transport);
void connectionstripeApplicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void connectionstripeTransportPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void connectionstripeApplicationFinish(tunnel_t *t, line_t *line);
void connectionstripeTransportFinish(tunnel_t *t, line_t *line);
void connectionstripeSetApplicationPaused(tunnel_t *t, line_t *line, bool paused);
void connectionstripeSetTransportPaused(tunnel_t *t, line_t *line, bool paused);
void connectionstripeClientTransportEstablished(tunnel_t *t, line_t *line);
