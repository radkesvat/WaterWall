#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kPingClientDropLogIntervalMs = 5U * 1000U,
};

static void pingclientValidatePacketLine(tunnel_t *t, line_t *l)
{
    pingclient_tstate_t *state = tunnelGetState(t);

    if (UNLIKELY(! lineIsAlive(l) || ! lineIsOnCurrentEventWorker(l) ||
                 ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l) || state->tracker == NULL || ! state->started))
    {
        LOGF("PingClient: invalid worker packet-line callback");
        abortProgramNow(1);
    }
}

static void pingclientDrop(tunnel_t *t, line_t *l, sbuf_t *buf, const char *reason)
{
    pingclient_tstate_t *state = tunnelGetState(t);
    if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPingClientDropLogIntervalMs))
    {
        LOGW("PingClient: dropping packet: %s", reason);
    }
    lineReuseBuffer(l, buf);
}

static bool pingclientConsumeInputChecksum(line_t *l, sbuf_t *buf)
{
    const bool requested = packettunnelTakeChecksumRequest(l);
    return packettunnelFinalizeChecksumRequest(requested, sbufGetMutablePtr(buf), sbufGetLength(buf));
}

void pingclientEncapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingclient_tstate_t *state = tunnelGetState(t);
    pingclientValidatePacketLine(t, l);

    if (! pingclientConsumeInputChecksum(l, buf))
    {
        pingclientDrop(t, l, buf, "outgoing input is not one complete IPv4 packet");
        return;
    }

    if (! pingwireEchoRequestPreflight(buf))
    {
        pingclientDrop(t, l, buf, "outgoing input cannot fit the IPv4/ICMP Echo carrier");
        return;
    }

    const uint16_t sequence = (uint16_t) atomicAdd(&state->next_sequence, 1U);
    if (UNLIKELY(! pingwireBuildEchoRequest(buf, &state->wire, sequence)))
    {
        LOGF("PingClient: Echo Request build failed after successful preflight");
        abortProgramNow(1);
    }

    const uint8_t *payload        = (const uint8_t *) sbufGetRawPtr(buf) + kPingWireEncapsulationOverhead;
    const uint16_t payload_length = (uint16_t) (sbufGetLength(buf) - kPingWireEncapsulationOverhead);
    if (! pingwireOutstandingRecord(state->tracker,
                                    state->digest_key,
                                    state->wire.identifier,
                                    sequence,
                                    state->wire.peer_ipv4,
                                    state->wire.local_ipv4,
                                    payload,
                                    payload_length))
    {
        pingclientDrop(t, l, buf, "could not register the outgoing Echo Request");
        return;
    }

    lineSetRecalculateChecksum(l, false);
    tunnelNextUpStreamPayload(t, l, buf);
}

void pingclientDecapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingclient_tstate_t *state = tunnelGetState(t);
    pingclientValidatePacketLine(t, l);

    if (! pingclientConsumeInputChecksum(l, buf))
    {
        pingclientDrop(t, l, buf, "downstream input is not one complete IPv4 packet");
        return;
    }

    ping_wire_envelope_t           envelope = {0};
    const ping_wire_inbound_kind_t kind =
        pingwireParseInbound(sbufGetRawPtr(buf), sbufGetLength(buf), &state->wire, &envelope);
    if (kind == kPingWireInboundUnrelated)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    if (kind == kPingWireInboundMalformed)
    {
        pingclientDrop(t, l, buf, "malformed or checksum-invalid downstream carrier");
        return;
    }
    if (kind == kPingWireInboundInvalidCarrier)
    {
        pingclientDrop(t, l, buf, "downstream packet addressed as carrier traffic is not a valid Echo envelope");
        return;
    }

    if (kind == kPingWireInboundEchoReply)
    {
        if (pingwireOutstandingConsume(state->tracker, state->digest_key, &envelope))
        {
            lineReuseBuffer(l, buf);
            return;
        }

        /* A valid but unmatched reply is unrelated IP traffic, not tunnel data. */
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    assert(kind == kPingWireInboundEchoRequest);
    const ping_wire_replay_result_t replay = pingwireReplayMark(state->tracker, state->digest_key, &envelope);
    if (replay == kPingWireReplayError)
    {
        pingclientDrop(t, l, buf, "could not record the incoming Echo Request");
        return;
    }

    /* Clone before stripping the original; replies must echo every ICMP byte exactly. */
    sbuf_t *reply = sbufDuplicateByPool(lineGetBufferPool(l), buf);
    if (reply == NULL)
    {
        if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPingClientDropLogIntervalMs))
        {
            LOGW("PingClient: could not allocate an Echo Reply clone; delivering the request without an "
                 "acknowledgement");
        }
    }
    else if (! pingwireBuildEchoReply(reply,
                                      &state->wire,
                                      &envelope,
                                      pingwireReplyIdGeneratorNext(&state->reply_ids, getHRTimeUs() / 1000U)))
    {
        lineReuseBuffer(l, reply);
        reply = NULL;
        if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kPingClientDropLogIntervalMs))
        {
            LOGW("PingClient: could not build an Echo Reply clone; delivering the request without an acknowledgement");
        }
    }

    if (reply != NULL)
    {
        lineSetRecalculateChecksum(l, false);
        lineRef(l);
        tunnelNextUpStreamPayload(t, l, reply);
        if (UNLIKELY(! lineIsAlive(l)))
        {
            LOGF("PingClient: worker packet line died during generated Echo Reply callback");
            abortProgramNow(1);
        }
        lineUnref(l);
    }

    if (replay == kPingWireReplayDuplicate)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! pingwireStripEchoRequest(buf, &envelope))
    {
        pingclientDrop(t, l, buf, "validated Echo Request could not be decapsulated");
        return;
    }

    lineSetRecalculateChecksum(l, false);
    tunnelPrevDownStreamPayload(t, l, buf);
}
