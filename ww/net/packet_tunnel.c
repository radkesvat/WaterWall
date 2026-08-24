#include "packet_tunnel.h"

/*
 * Implements default packet-tunnel flow routines and packet tunnel creation.
 */

#include "ipv4_packet_view.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "wchecksum.h"

// Default upstream payload function
static void packettunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    discard self;
    discard line;
    discard payload;
    LOGF("Unexpected call to default up stream payload for a packet tunnel, this function must be overridden");
    abortProgramNow(1);
}

// Default downstream payload function
static void packettunnelDefaultDownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload)
{
    discard self;
    discard line;
    discard payload;
    LOGF("Unexpected call to default down stream payload for a packet tunnel, this function must be overridden");
    abortProgramNow(1);
}

static packet_lifecycle_anchor_t *packettunnelGetLifecycleAnchor(tunnel_t *t)
{
    return tunnelGetState(t);
}

static void packettunnelLifecycleAnchorAbsorb(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

static void packettunnelLifecycleAnchorUpstreamFinish(tunnel_t *t, line_t *line)
{
    packet_lifecycle_anchor_t *anchor = packettunnelGetLifecycleAnchor(t);
    LOGF("%s: unexpected upstream Finish on worker packet line %d", anchor->name, workerWIDForLog(lineGetWID(line)));
    abortProgramNow(1);
}

static void packettunnelLifecycleAnchorDownstreamFinish(tunnel_t *t, line_t *line)
{
    packet_lifecycle_anchor_t *anchor = packettunnelGetLifecycleAnchor(t);
    LOGF("%s: unexpected downstream Finish on worker packet line %d", anchor->name, workerWIDForLog(lineGetWID(line)));
    abortProgramNow(1);
}

tunnel_t *packettunnelCreate(node_t *node, size_t tstate_size, size_t lstate_size)
{
    if (UNLIKELY(lstate_size != 0))
    {
        return NULL;
    }

    tunnel_t *t = tunnelCreate(node, tstate_size, 0);

    // tunnelCreate() is nullable by contract: it returns NULL on a state-size
    // overflow or an allocation failure. Callers unwind from a NULL create
    // handle, so the failure has to survive as far as them.
    if (! t)
    {
        return NULL;
    }

    // Packet tunnels use the standard lifecycle pass-through callbacks inherited from tunnelCreate(). Payload
    // handling remains mandatory in both directions and fails loudly until the packet tunnel overrides it.
    t->fnPayloadU = packettunnelDefaultUpStreamPayload;
    t->fnPayloadD = packettunnelDefaultDownStreamPayload;

    return t;
}

bool packettunnelConfigureLifecycleAnchor(tunnel_t *t, const char *name, TunnelFlowRoutinePayload write_payload,
                                          packet_lifecycle_anchor_direction_t direction)
{
    if (t == NULL || name == NULL || write_payload == NULL || t->lstate_size != 0 ||
        t->tstate_size < sizeof(packet_lifecycle_anchor_t) ||
        (direction != kPacketLifecycleAnchorPublishUpstream && direction != kPacketLifecycleAnchorPublishDownstream))
    {
        return false;
    }

    packet_lifecycle_anchor_t *anchor = packettunnelGetLifecycleAnchor(t);
    anchor->name                      = name;
    anchor->direction                 = direction;

    t->fnInitU   = packettunnelLifecycleAnchorAbsorb;
    t->fnInitD   = packettunnelLifecycleAnchorAbsorb;
    t->fnEstU    = packettunnelLifecycleAnchorAbsorb;
    t->fnEstD    = packettunnelLifecycleAnchorAbsorb;
    t->fnFinU    = packettunnelLifecycleAnchorUpstreamFinish;
    t->fnFinD    = packettunnelLifecycleAnchorDownstreamFinish;
    t->fnPauseU  = packettunnelLifecycleAnchorAbsorb;
    t->fnPauseD  = packettunnelLifecycleAnchorAbsorb;
    t->fnResumeU = packettunnelLifecycleAnchorAbsorb;
    t->fnResumeD = packettunnelLifecycleAnchorAbsorb;

    t->fnPayloadU = write_payload;
    t->fnPayloadD = write_payload;
    return true;
}

bool packettunnelLifecycleAnchorBind(tunnel_t *t)
{
    packet_lifecycle_anchor_t *anchor = packettunnelGetLifecycleAnchor(t);
    if (anchor->direction == kPacketLifecycleAnchorPublishUpstream)
    {
        anchor->publication_tunnel   = t->next;
        anchor->publication_callback = t->next != NULL ? t->next->fnPayloadU : NULL;
    }
    else
    {
        anchor->publication_tunnel   = t->prev;
        anchor->publication_callback = t->prev != NULL ? t->prev->fnPayloadD : NULL;
    }

    return anchor->publication_tunnel != NULL && anchor->publication_callback != NULL;
}

void packettunnelLifecycleAnchorPublish(tunnel_t *t, line_t *packet_line, sbuf_t *buf)
{
    packet_lifecycle_anchor_t *anchor = packettunnelGetLifecycleAnchor(t);
    if (UNLIKELY(packet_line == NULL || ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), packet_line) ||
                 anchor->publication_tunnel == NULL || anchor->publication_callback == NULL))
    {
        LOGF("%s: invalid packet-lifecycle anchor publication", anchor->name);
        abortProgramNow(1);
    }
    if (UNLIKELY(! lineIsAlive(packet_line)))
    {
        LOGF("%s: packet line was already dead during runtime", anchor->name);
        abortProgramNow(1);
    }

    lineLock(packet_line);

    anchor->publication_callback(anchor->publication_tunnel, packet_line, buf);

    if (! lineIsAlive(packet_line))
    {
        LOGF("%s: packet line died during runtime", anchor->name);
        abortProgramNow(1);
    }
    lineUnlock(packet_line);
}

bool packettunnelTakeChecksumRequest(line_t *line)
{
    const bool recalculate_checksum = line->recalculate_checksum;

    /*
     * Consume first even when the packet is malformed. A packet line is reused
     * across unrelated traffic, so a failed request must not leak into the next
     * packet handled by this worker.
     */
    line->recalculate_checksum = false;

    return recalculate_checksum;
}

bool packettunnelFinalizeChecksumRequest(bool requested, uint8_t *packet_bytes, uint32_t length)
{
    if (UNLIKELY(packet_bytes == NULL))
    {
        return false;
    }

    ipv4_packet_view_t packet = {0};
    if (UNLIKELY(! ipv4packetviewParse(packet_bytes, length, &packet) || packet.ip_total_length != length))
    {
        return false;
    }

    return ! requested || calcFullPacketChecksum(packet_bytes, length);
}

bool packettunnelConsumeChecksumRequest(line_t *line, sbuf_t *buf)
{
    const bool requested = packettunnelTakeChecksumRequest(line);
    return packettunnelFinalizeChecksumRequest(requested, sbufGetMutablePtr(buf), sbufGetLength(buf));
}
