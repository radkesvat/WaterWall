#include "structure.h"

#include "loggers/network_logger.h"

static const char *disturberDirectionName(disturber_payload_direction_e direction)
{
    return direction == kDisturberPayloadDirectionUpstream ? "upstream" : "downstream";
}

static bool disturberDirectionIsEnabled(const disturber_tstate_t *ts, disturber_payload_direction_e direction)
{
    return direction == kDisturberPayloadDirectionUpstream ? ts->disturb_upstream : ts->disturb_downstream;
}

static disturber_direction_lstate_t *disturberGetDirectionState(disturber_lstate_t           *ls,
                                                                disturber_payload_direction_e direction)
{
    return direction == kDisturberPayloadDirectionUpstream ? &ls->upstream : &ls->downstream;
}

static void disturberForwardScheduledUpstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    disturber_lstate_t *ls = lineGetState(l, t);
    if (ls->upstream.finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

static void disturberForwardScheduledDownstreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    disturber_lstate_t *ls = lineGetState(l, t);
    if (ls->downstream.finished)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

static LineTaskFnWithBuf disturberGetForwardPayloadFn(disturber_payload_direction_e direction)
{
    return direction == kDisturberPayloadDirectionUpstream ? disturberForwardScheduledUpstreamPayload
                                                           : disturberForwardScheduledDownstreamPayload;
}

static void disturberScheduleForwardPayload(tunnel_t *t, line_t *l, sbuf_t *buf,
                                            disturber_payload_direction_e direction)
{
    discard lineScheduleTaskWithBuf(l, disturberGetForwardPayloadFn(direction), t, buf);
}

bool disturberIsWorkerPacketLine(tunnel_t *t, line_t *l)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || ! chain->finalized)
    {
        return tunnelchainIsWorkerPacketLine(chain, l);
    }

    if (UNLIKELY(chain->packet_lines == NULL))
    {
        LOGF("Disturber: finalized chain is missing its packet-line slots during runtime classification");
        abortProgramNow(1);
    }

    /* Finalization publishes exactly one owner-matched packet line in every
     * worker slot if and only if the chain contains a packet node. Validate the
     * complete geometry before deciding that a callback line is merely normal:
     * a missing or mis-owned slot must not make a real packet line fall through
     * to normal-line teardown. */
    for (wid_t wid = 0; wid < chain->workers_count; ++wid)
    {
        line_t *packet_line = tunnelchainGetWorkerPacketLine(chain, wid);
        if (UNLIKELY(chain->contains_packet_node != (packet_line != NULL)))
        {
            LOGF("Disturber: finalized packet-line topology disagrees with worker slot %d during runtime "
                 "classification",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }

        if (packet_line != NULL &&
            UNLIKELY(lineGetWID(packet_line) != wid || ! tunnelchainIsWorkerPacketLine(chain, packet_line)))
        {
            LOGF("Disturber: finalized chain has a non-owner packet line in worker slot %d during runtime "
                 "classification",
                 workerWIDForLog(wid));
            abortProgramNow(1);
        }
    }

    return tunnelchainIsWorkerPacketLine(chain, l);
}

void disturberPacketLineFinish(tunnel_t *t, line_t *l, disturber_payload_direction_e direction)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    if (UNLIKELY(chain == NULL || ! chain->finalized || ! chain->contains_packet_node || l == NULL ||
                 ! disturberIsWorkerPacketLine(t, l) || ! lineIsOnCurrentEventWorker(l)))
    {
        LOGF("Disturber: packet Finish ran outside the exact owner packet line");
        abortProgramNow(1);
    }

    assert(chain != NULL && chain->contains_packet_node);
    assert(lineIsOnCurrentEventWorker(l));
    assert(disturberIsWorkerPacketLine(t, l));

    disturber_lstate_t *ls = lineGetState(l, t);

    /* A received Finish creates two terminal publication boundaries. Payload
     * already queued in the same direction must not overtake the propagated
     * Finish, and payload queued in the opposite direction must not reflect
     * toward the side that sent it. Normal-line teardown gets both guarantees
     * by destroying all lstate; persistent packet state needs them explicitly. */
    disturber_direction_lstate_t *received = disturberGetDirectionState(ls, direction);
    disturber_direction_lstate_t *opposite = disturberGetDirectionState(ls,
                                                                        direction == kDisturberPayloadDirectionUpstream
                                                                            ? kDisturberPayloadDirectionDownstream
                                                                            : kDisturberPayloadDirectionUpstream);

    received->finished = true;
    if (received->held_payload != NULL)
    {
        lineReuseBuffer(l, received->held_payload);
        received->held_payload = NULL;
    }

    opposite->finished = true;
    if (opposite->held_payload != NULL)
    {
        lineReuseBuffer(l, opposite->held_payload);
        opposite->held_payload = NULL;
    }
}

static void disturberCloseNormalLine(tunnel_t *t, line_t *l)
{
    disturber_lstate_t *ls = lineGetState(l, t);

    disturberLinestateDestroy(l, ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}

void disturberTunnelPayload(tunnel_t *t, line_t *l, sbuf_t *buf, disturber_payload_direction_e direction)
{
    disturber_tstate_t           *ts       = tunnelGetState(t);
    disturber_lstate_t           *ls       = lineGetState(l, t);
    disturber_direction_lstate_t *dir_ls   = disturberGetDirectionState(ls, direction);
    LineTaskFnWithBuf             forward  = disturberGetForwardPayloadFn(direction);
    const char                   *dir_name = disturberDirectionName(direction);

    if (! disturberDirectionIsEnabled(ts, direction))
    {
        forward(t, l, buf);
        return;
    }

    if (dir_ls->finished || dir_ls->is_deadhang)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (roll100(ts->chance_middle_close))
    {
        LOGD("Disturber: Closing %s direction in the middle of transmission", dir_name);
        lineReuseBuffer(l, buf);
        if (disturberIsWorkerPacketLine(t, l))
        {
            dir_ls->is_deadhang = true;
            return;
        }
        disturberCloseNormalLine(t, l);
        return;
    }

    if (roll100(ts->chance_payload_loss))
    {
        LOGD("Disturber: Dropping %s payload (chance: %d%%)", dir_name, ts->chance_payload_loss);
        lineReuseBuffer(l, buf);
        return;
    }

    sbuf_t *dup_buf = NULL;
    if (roll100(ts->chance_payload_duplication))
    {
        LOGD("Disturber: Duplicating %s payload (chance: %d%%)", dir_name, ts->chance_payload_duplication);
        dup_buf = sbufDuplicate(buf);
    }

    if (roll100(ts->chance_payload_corruption))
    {
        uint8_t *data = sbufGetMutablePtr(buf);
        uint32_t size = sbufGetLength(buf);

        if (size > 0)
        {
            // Corrupt up to 10% of the payload, at least 1 byte.
            uint32_t corrupt_bytes = (size > 10) ? (size / 10) : 1;
            for (uint32_t i = 0; i < corrupt_bytes; i++)
            {
                uint32_t offset = fastRand() % size;
                data[offset] ^= (uint8_t) (fastRand() & 0xFF);
            }
            LOGD("Disturber: Corrupted %s payload (corrupted bytes: %u)", dir_name, corrupt_bytes);
        }
    }

    if (dir_ls->held_payload != NULL)
    {
        LOGD("Disturber: Sending held %s payload before current one (chance: %d%%)",
             dir_name,
             ts->chance_payload_out_of_order);

        sbuf_t *held_buf     = dir_ls->held_payload;
        dir_ls->held_payload = NULL;

        if (dup_buf != NULL)
        {
            disturberScheduleForwardPayload(t, l, dup_buf, direction);
        }
        disturberScheduleForwardPayload(t, l, buf, direction);

        discard lineCallWithRefWithBuf(l, forward, t, held_buf);
        return;
    }

    if (roll100(ts->chance_payload_out_of_order))
    {
        dir_ls->held_payload = buf;
        if (dup_buf != NULL)
        {
            disturberScheduleForwardPayload(t, l, dup_buf, direction);
        }
        return;
    }

    if (roll100(ts->chance_payload_delay))
    {
        int delay_range = ts->delay_max_ms - ts->delay_min_ms + 1;
        if (delay_range <= 0)
        {
            // Fallback safety for malformed runtime config.
            delay_range = 1;
        }
        int delay_ms = ts->delay_min_ms + ((int) fastRand() % delay_range);
        LOGD("Disturber: Delaying %s payload by %d ms (chance: %d%%)", dir_name, delay_ms, ts->chance_payload_delay);
        /* Fault-injection delay traffic is intentionally lossy on refusal. */
        discard lineScheduleDelayedTaskWithBuf(l, forward, delay_ms, t, buf);
        if (dup_buf != NULL)
        {
            disturberScheduleForwardPayload(t, l, dup_buf, direction);
        }
        return;
    }

    if (roll100(ts->chance_connection_deadhang))
    {
        LOGD("Disturber: Putting %s direction into deadhang (chance: %d%%)", dir_name, ts->chance_connection_deadhang);
        dir_ls->is_deadhang = true;
        lineReuseBuffer(l, buf);
        if (dup_buf != NULL)
        {
            disturberScheduleForwardPayload(t, l, dup_buf, direction);
        }
        return;
    }

    if (dup_buf != NULL)
    {
        disturberScheduleForwardPayload(t, l, dup_buf, direction);
    }

    forward(t, l, buf);
}
