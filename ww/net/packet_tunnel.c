#include "packet_tunnel.h"

/*
 * Implements default packet-tunnel flow routines and packet tunnel creation.
 */

#include "ipv4_packet_view.h"
#include "line.h"
#include "loggers/internal_logger.h"
#include "objects/node.h"
#include "wchecksum.h"

bool packettunnelTrustedChecksumPairEligible(const tunnel_t *source, const tunnel_t *consumer)
{
    return source != NULL && consumer != NULL && source != consumer && source->next == consumer &&
           consumer->prev == source && source->node != NULL && consumer->node != NULL &&
           source->node->layer_group == kNodeLayer3 && consumer->node->layer_group == (kNodeLayer3 | kNodeLayer4) &&
           (source->node->flags & kNodeFlagSupportsTrustedPacketChecksums) != 0 &&
           (consumer->node->flags & kNodeFlagSupportsTrustedPacketChecksums) != 0;
}

void packettunnelActivateTrustedChecksumPair(tunnel_t *source, tunnel_t *consumer)
{
    assert(packettunnelTrustedChecksumPairEligible(source, consumer));
    source->node->flags |= kNodeFlagTrustedPacketChecksumsActive;
    consumer->node->flags |= kNodeFlagTrustedPacketChecksumsActive;
}

bool packettunnelTrustedChecksumsActive(const tunnel_t *t)
{
    return (t->node->flags & kNodeFlagTrustedPacketChecksumsActive) != 0;
}

void packettunnelActivateTrustedReceiveChecksumPair(tunnel_t *source, tunnel_t *consumer)
{
    assert(packettunnelTrustedChecksumPairEligible(source, consumer));
    source->node->flags |= kNodeFlagTrustedPacketReceiveChecksumsActive;
    consumer->node->flags |= kNodeFlagTrustedPacketReceiveChecksumsActive;
}

bool packettunnelTrustedReceiveChecksumsActive(const tunnel_t *t)
{
    return (t->node->flags & (kNodeFlagTrustedPacketChecksumsActive | kNodeFlagTrustedPacketReceiveChecksumsActive)) !=
           0;
}

bool packettunnelCanEnqueueDownstreamInline(const tunnel_t *producer, const line_t *packet_line)
{
    const tunnel_t *sink = producer->prev;
    return sink != NULL && sink != producer && sink->next == producer && sink->chain == producer->chain &&
           sink->node != NULL && sink->node->layer_group == kNodeLayer3 &&
           (sink->node->flags & kNodeFlagPacketPayloadEnqueueOnly) != 0 &&
           tunnelchainIsWorkerPacketLine(producer->chain, packet_line) && lineIsOnCurrentWorker(packet_line) &&
           tunnelIsActiveForLine(sink, packet_line);
}

static void packettunnelDefaultUpStreamEst(tunnel_t *self, line_t *line)
{
    assert(self->next != NULL);
    tunnelNextUpStreamEst(self, line);
}

static void packettunnelDefaultDownStreamInit(tunnel_t *self, line_t *line)
{
    assert(self->prev != NULL);
    tunnelPrevDownStreamInit(self, line);
}

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

    // Invalid or unrepresentable state sizes remain a nullable constructor result.
    if (! t)
    {
        return NULL;
    }

    // Packet lifecycle callbacks pass through in both directions, including the two that normal tunnels reject.
    // Payload handling remains mandatory in both directions and fails loudly until overridden.
    t->fnEstU     = packettunnelDefaultUpStreamEst;
    t->fnInitD    = packettunnelDefaultDownStreamInit;
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
        anchor->publication_callback = t->next != NULL && t->next->fnPayloadU != NULL ? tunnelUpStreamPayload : NULL;
    }
    else
    {
        anchor->publication_tunnel   = t->prev;
        anchor->publication_callback = t->prev != NULL && t->prev->fnPayloadD != NULL ? tunnelDownStreamPayload : NULL;
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

    lineRef(packet_line);

    anchor->publication_callback(anchor->publication_tunnel, packet_line, buf);

    if (! lineIsAlive(packet_line))
    {
        LOGF("%s: packet line died during runtime", anchor->name);
        abortProgramNow(1);
    }
    lineUnref(packet_line);
}

bool packettunnelTakeChecksumRequest(sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));
    const bool recalculate_checksum = sbufGetRecalculateChecksum(buf);
    /* Terminal boundaries discard the packet if the repair attempt fails. */
    sbufSetRecalculateChecksum(buf, false);

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

bool packettunnelConsumeChecksumRequest(sbuf_t *buf)
{
    const bool requested = packettunnelTakeChecksumRequest(buf);
    return packettunnelFinalizeChecksumRequest(requested, sbufGetMutablePtr(buf), sbufGetLength(buf));
}

bool packettunnelReadFragmentPolicy(const cJSON *settings, device_fragment_policy_t *policy)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(settings, "fragment-policy");
    if (value == NULL)
    {
        *policy = kDeviceFragmentReassemble;
        return true;
    }
    if (cJSON_IsString(value))
    {
        if (stringCompare(value->valuestring, "reassemble") == 0)
        {
            *policy = kDeviceFragmentReassemble;
            return true;
        }
        if (stringCompare(value->valuestring, "preserve-fragments") == 0)
        {
            *policy = kDeviceFragmentPreserve;
            return true;
        }
    }
    LOGF("Device source fragment-policy must be reassemble or preserve-fragments");
    return false;
}

enum
{
    kPortedDeclarationsPerNode = kDeviceFlowPortedProtocolMax
};

typedef struct ported_declaration_s
{
    const tunnel_t *declarer;
    uint8_t         protocol;
} ported_declaration_t;

/* Startup and shutdown only, so a spin lock is enough; nothing here runs on a packet path. */
static atomic_flag           ported_declarations_lock = ATOMIC_FLAG_INIT;
static ported_declaration_t *ported_declarations;
static unsigned              ported_declaration_count;
static unsigned              ported_declaration_capacity;

static void portedDeclarationsLock(void)
{
    while (atomic_flag_test_and_set_explicit(&ported_declarations_lock, memory_order_acquire))
        ;
}

static void portedDeclarationsUnlock(void)
{
    atomic_flag_clear_explicit(&ported_declarations_lock, memory_order_release);
}

bool packettunnelDeclarePortedProtocol(tunnel_t *declarer, uint8_t protocol)
{
    assert(declarer != NULL);
    bool declared = false;
    bool at_limit = false;
    portedDeclarationsLock();
    unsigned held = 0;
    for (unsigned i = 0; i < ported_declaration_count; ++i)
    {
        if (ported_declarations[i].declarer == declarer)
        {
            if (ported_declarations[i].protocol == protocol)
            {
                declared = true;
                break;
            }
            ++held;
        }
    }
    if (! declared && held >= kPortedDeclarationsPerNode)
        at_limit = true;
    else if (! declared)
    {
        if (ported_declaration_count == ported_declaration_capacity)
        {
            ported_declaration_capacity = ported_declaration_capacity == 0 ? 16U : ported_declaration_capacity * 2U;
            ported_declarations = memoryReAllocate(ported_declarations,
                                                   (size_t) ported_declaration_capacity * sizeof(*ported_declarations));
        }
        ported_declarations[ported_declaration_count++] = (ported_declaration_t) {declarer, protocol};
        declared                                        = true;
    }
    portedDeclarationsUnlock();
    if (at_limit)
        LOGW("PacketTunnel: protocol %u was not declared as ported, the node already declares %u protocols",
             protocol,
             (unsigned) kPortedDeclarationsPerNode);
    return declared;
}

void packettunnelWithdrawPortedProtocols(tunnel_t *declarer)
{
    portedDeclarationsLock();
    unsigned kept = 0;
    for (unsigned i = 0; i < ported_declaration_count; ++i)
        if (ported_declarations[i].declarer != declarer)
            ported_declarations[kept++] = ported_declarations[i];
    ported_declaration_count = kept;
    portedDeclarationsUnlock();
}

void packettunnelGetChainPortedProtocols(const tunnel_t *t, device_flow_ported_set_t *out)
{
    assert(t != NULL && out != NULL);
    *out = (device_flow_ported_set_t) {0};
    if (t->chain == NULL)
        return;
    assert(t->chain->finalized);
    uint8_t  refused[256];
    unsigned refused_count = 0;
    portedDeclarationsLock();
    /* Ascending protocol order, so a chain over the limit refuses the same numbers on every start. */
    for (unsigned want = 0; want < 256; ++want)
    {
        bool found = false;
        for (unsigned i = 0; i < ported_declaration_count && ! found; ++i)
        {
            const ported_declaration_t *d = &ported_declarations[i];
            found                         = d->protocol == want && d->declarer->chain == t->chain;
        }
        if (found && ! deviceFlowPortedSetAdd(out, (uint8_t) want))
            refused[refused_count++] = (uint8_t) want;
    }
    portedDeclarationsUnlock();
    for (unsigned i = 0; i < refused_count; ++i)
        LOGW("PacketTunnel: protocol %u is not steered by its inner ports, a chain supports at most %u",
             refused[i],
             (unsigned) kDeviceFlowPortedProtocolMax);
}
