#include "packet_tunnel.h"

/*
 * Implements default packet-tunnel flow routines and packet tunnel creation.
 */

#include "loggers/internal_logger.h"

// Default upstream payload function
static void packettunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    discard self;
    discard line;
    discard payload;
    LOGF("Unexpected call to default up stream payload for a packet tunnel, this function must be overridden");
    terminateProgram(1);
}

// Default downstream payload function
static void packettunnelDefaultDownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    discard self;
    discard line;
    discard payload;
    LOGF("Unexpected call to default down stream payload for a packet tunnel, this function must be overridden");
    terminateProgram(1);
}

tunnel_t *packettunnelCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size)
{
    assert(lstate_size == 0); // packet tunnels dont have lines
    discard   lstate_size;
    tunnel_t *t = tunnelCreate(node, tstate_size, 0);

    // Packet tunnels use the standard lifecycle pass-through callbacks inherited from tunnelCreate(). Payload
    // handling remains mandatory in both directions and fails loudly until the packet tunnel overrides it.
    t->fnPayloadU = packettunnelDefaultUpStreamPayload;
    t->fnPayloadD = packettunnelDefaultDownStreamPayload;

    return t;
}
