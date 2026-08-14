#include "structure.h"

#include "devices/device_frag_settlement.h"

#include "loggers/network_logger.h"

#include "loggers/log_rate_limiter.h"

/*
 * Return-fragment association.
 *
 * The flow registry is keyed on transport ports, and only fragment offset zero
 * carries them. This table remembers what fragment zero resolved to so the rest
 * of the datagram reaches the same worker, and therefore the same netif: lwIP
 * reassembles the fragments into one pbuf and delivers it on whichever netif
 * completed it, so a datagram split across per-worker netifs would surface on
 * the wrong flow's stack.
 *
 * An association lives while its datagram is in flight and through the final
 * owner-worker purge barrier. Received byte ranges identify completion, but the
 * entry is retired only after every queued injection has settled and the exact
 * lwIP reassembly key has been purged. This keeps reuse safe without holding
 * completed entries until their timeout.
 *
 * Coverage is tracked the way lwIP tracks it, not the way a set-union tracker
 * would: overlaps and duplicates are rejected rather than merged, because lwIP
 * discards them and a merging tracker would call a datagram complete that the
 * real reassembler still has a hole in. The same reasoning drives the two
 * defensive states in ctp_frag_state_t - lwIP's reassembly list is keyed on
 * ingress netif, source, destination, protocol and identification, so this table
 * must never hand one netif two datagrams that share the remaining identity at
 * once.
 *
 * Everything here runs under `flows_lock` held for writing. That is the same
 * lock the registry uses, which is deliberate - resolving fragment zero needs a
 * registry lookup in the middle of a table mutation, and one lock removes any
 * question of ordering between them. Nothing in this file calls lwIP or a
 * neighboring tunnel: the packet-line caller may already be inside a foreign
 * LOCK_TCPIP_CORE() frame, so publishing is deferred until the lock is released.
 */

enum
{
    kCtpFragDropLogIntervalMs = 5U * 1000U
};

/* Shared by every worker, so each gate has to be atomic. */
static atomic_log_rate_limiter_t g_frag_association_cap_log;
static atomic_log_rate_limiter_t g_frag_pending_cap_log;
static atomic_log_rate_limiter_t g_frag_range_cap_log;
static atomic_log_rate_limiter_t g_frag_malformed_log;
static atomic_log_rate_limiter_t g_frag_inconsistent_log;
static atomic_log_rate_limiter_t g_frag_overlap_log;
static atomic_log_rate_limiter_t g_frag_quarantine_log;
static atomic_log_rate_limiter_t g_frag_expiry_log;

typedef struct ctp_frag_publish_batch_s
{
    ctp_frag_pending_t items[kCtpFragMaxPendingPerDatagram + 1];
    ctp_flow_key_t     flow_key;
    uint64_t           generation;
    uint64_t           serial;
    wid_t              wid;
    uint8_t            count;
    /* Set when this batch completed the datagram, so the caller queues its purge barrier. */
    bool completed;
} ctp_frag_publish_batch_t;

typedef struct ctp_frag_purge_request_s
{
    ctp_frag_key_t key;
    uint64_t       serial;
    wid_t          wid;
} ctp_frag_purge_request_t;

typedef struct ctp_frag_purge_batch_s
{
    ctp_frag_purge_request_t items[kCtpFragMaxAssociations];
    uint16_t                 count;
} ctp_frag_purge_batch_t;

static void ctpFragSchedulePurgeBatch(tunnel_t *t, const ctp_frag_purge_batch_t *purges,
                                      ctp_frag_purge_schedule_fn schedule_purge, uint64_t now_ms);

bool ctpFragTableInitialize(ctp_tstate_t *ts)
{
    ts->frags               = ctp_frag_map_t_with_capacity(kCtpFragMaxAssociations);
    ts->frag_pending_bytes  = 0;
    ts->frag_next_expiry_ms = 0;
    ts->frag_next_serial    = 0;
    return ctp_frag_map_t_capacity(&ts->frags) >= (isize_t) kCtpFragMaxAssociations;
}

static uint64_t ctpFragNextSerialLocked(ctp_tstate_t *ts)
{
    ts->frag_next_serial += 1;
    if (UNLIKELY(ts->frag_next_serial == 0))
    {
        ts->frag_next_serial = 1;
    }
    return ts->frag_next_serial;
}

/*
 * Records that this association owes a purge barrier, and queues one when that
 * is actually safe.
 *
 * Two things can hold it back, and both resolve later rather than never:
 *
 *   - a publish batch is still on its way to the owner worker's queue. The
 *     barrier has to arrive behind it, so it waits for the count to reach zero.
 *   - the caller's batch is full, or a previous enqueue was refused.
 *
 * Either way the entry gets a retry deadline, which is what puts it back in
 * front of the sweep. Without one, a poisoned entry contributes no expiry at
 * all, `frag_next_expiry_ms` collapses to zero, and only traffic carrying this
 * exact identification would ever try again - so a handful of transient
 * failures could pin association slots for the life of the process.
 */
static void ctpFragRequestPurgeLocked(ctp_frag_entry_t *entry, const ctp_frag_key_t *key,
                                      ctp_frag_purge_batch_t *purges, uint64_t now_ms)
{
    entry->purge_required = true;

    if (entry->purge_queued)
    {
        return;
    }

    if (entry->outstanding_publishes > 0 || entry->pending_deliveries > 0 ||
        purges->count >= (uint16_t) kCtpFragMaxAssociations)
    {
        entry->expires_at_ms = now_ms + (uint64_t) kCtpFragPurgeRetryMs;
        return;
    }

    purges->items[purges->count++] =
        (ctp_frag_purge_request_t) {.key = *key, .serial = entry->serial, .wid = entry->wid};
    entry->purge_queued = true;
}

size_t ctpFragAssociationCount(ctp_tstate_t *ts)
{
    rwlockReadLock(&ts->flows_lock);
    const size_t count = (size_t) ctp_frag_map_t_size(&ts->frags);
    rwlockReadUnlock(&ts->flows_lock);
    return count;
}

static void ctpFragReleaseEntryLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry, ctp_frag_discard_fn release,
                                      device_frag_settlement_t refused_settlement)
{
    for (uint8_t i = 0; i < entry->pending_count; ++i)
    {
        ts->frag_pending_bytes -= entry->pending[i].len;
        release(entry->pending[i].payload);
    }
    entry->pending_count = 0;

    for (uint8_t i = 0; i < entry->refused_receipt_count; ++i)
    {
        deviceFragClaimResolve(entry->refused_receipts[i], refused_settlement);
        entry->refused_receipts[i] = NULL;
    }
    entry->refused_receipt_count = 0;
}

void ctpFragClearLocked(ctp_tstate_t *ts, ctp_frag_discard_fn release)
{
    c_foreach(i, ctp_frag_map_t, ts->frags)
    {
        ctpFragReleaseEntryLocked(ts, &i.ref->second, release, kDeviceFragSettlementUnknown);
    }
    ctp_frag_map_t_clear(&ts->frags);
    ts->frag_next_expiry_ms = 0;
}

void ctpFragClearAfterNetifPurgeLocked(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    c_foreach(i, ctp_frag_map_t, ts->frags)
    {
        ctp_frag_entry_t *entry = &i.ref->second;
        ctp_netif_ctx_t  *ctx   = (ts->netifs != NULL && entry->wid < ts->netifs_count) ? ts->netifs[entry->wid] : NULL;
        const bool        exact_netif = ctx != NULL && ctx->added && ctx->tunnel == t && ctx->wid == entry->wid;

        ctpFragReleaseEntryLocked(ts,
                                  entry,
                                  exact_netif ? ctpInjectMessageResolveNoResidue : ctpInjectMessageDestroy,
                                  exact_netif ? kDeviceFragSettlementNoResidue : kDeviceFragSettlementUnknown);
    }
    ctp_frag_map_t_clear(&ts->frags);
    ts->frag_next_expiry_ms = 0;
}

void ctpFragTableDestroy(ctp_tstate_t *ts, ctp_frag_discard_fn release)
{
    /*
     * Stop is supposed to have released every staged payload under the write
     * lock, and the classifier's own gate is what keeps a late packet from
     * staging one behind it. Sweeping again anyway costs a walk of an empty map
     * and turns any future ordering mistake into a released payload rather than a
     * leak. ctpFragReleaseEntryLocked() clears each slot as it goes, so a payload
     * that was already released cannot be released twice.
     */
    ctpFragClearLocked(ts, release);
    ctp_frag_map_t_drop(&ts->frags);
}

/*
 * One completed or poisoned entry, seen by the sweep.
 *
 * These wait for a barrier rather than for a timeout: one already in the owner
 * worker's queue needs nothing further. Returns the instant this entry has to be
 * looked at again, or zero when it does not - the sweep needs that value in its
 * next-wakeup calculation, because an entry that contributes no deadline at all
 * is one the sweep will never revisit.
 */
static uint64_t ctpFragSweepAwaitingBarrierLocked(ctp_frag_entry_t *entry, const ctp_frag_key_t *key,
                                                  ctp_frag_purge_batch_t *purges, uint64_t now_ms)
{
    if (entry->purge_queued)
    {
        return 0;
    }

    if (now_ms >= entry->expires_at_ms)
    {
        ctpFragRequestPurgeLocked(entry, key, purges, now_ms);
    }

    return entry->purge_queued ? 0 : entry->expires_at_ms;
}

/*
 * Lazy expiry, and only when something can actually be due.
 *
 * There is deliberately no timer: an association is swept by later traffic,
 * while completed and poisoned entries wait for their queued purge barrier.
 * `frag_next_expiry_ms` keeps the common case - nothing is due - from scanning
 * the map on every fragment.
 */
static void ctpFragSweepExpiredLocked(ctp_tstate_t *ts, uint64_t now_ms, ctp_frag_discard_fn release,
                                      ctp_frag_purge_batch_t *purges)
{
    if (ts->frag_next_expiry_ms == 0 || now_ms < ts->frag_next_expiry_ms)
    {
        return;
    }

    uint64_t            earliest = 0;
    uint32_t            swept    = 0;
    ctp_frag_map_t_iter it       = ctp_frag_map_t_begin(&ts->frags);

    while (it.ref != NULL)
    {
        ctp_frag_entry_t *entry = &it.ref->second;

        if (entry->state == (uint8_t) kCtpFragStatePublishing || entry->state == (uint8_t) kCtpFragStatePoisoned)
        {
            const uint64_t retry_at = ctpFragSweepAwaitingBarrierLocked(entry, &it.ref->first, purges, now_ms);

            if (retry_at != 0 && (earliest == 0 || retry_at < earliest))
            {
                earliest = retry_at;
            }

            ctp_frag_map_t_next(&it);
            continue;
        }

        if (now_ms < entry->expires_at_ms)
        {
            if (earliest == 0 || entry->expires_at_ms < earliest)
            {
                earliest = entry->expires_at_ms;
            }
            ctp_frag_map_t_next(&it);
            continue;
        }

        /*
         * Queue admission is not delivery. A paused owner may keep an accepted
         * injection past the classification deadline, and retiring the route
         * here would make that packet enter lwIP without a matching association.
         * Revisit it periodically until the exact delivery token settles.
         */
        if (entry->pending_deliveries > 0)
        {
            const uint64_t retry_at = now_ms + (uint64_t) kCtpFragPurgeRetryMs;
            if (earliest == 0 || retry_at < earliest)
            {
                earliest = retry_at;
            }
            ctp_frag_map_t_next(&it);
            continue;
        }

        swept += entry->pending_count;
        ctpFragReleaseEntryLocked(ts, entry, release, kDeviceFragSettlementUnknown);

        if (entry->state == (uint8_t) kCtpFragStateUnresolved)
        {
            /* No fragment from an unresolved entry ever reached lwIP. */
            it = ctp_frag_map_t_erase_at(&ts->frags, it);
            continue;
        }

        entry->state         = (uint8_t) kCtpFragStatePoisoned;
        entry->range_count   = 0;
        entry->final_end     = 0;
        entry->expires_at_ms = 0;
        ctpFragRequestPurgeLocked(entry, &it.ref->first, purges, now_ms);
        ctp_frag_map_t_next(&it);
    }

    ts->frag_next_expiry_ms = earliest;

    if (swept > 0 && atomicLogRateLimiterShouldLog(&g_frag_expiry_log, kCtpFragDropLogIntervalMs))
    {
        LOGW("ConnectionToPackets: dropped %u staged return fragments of datagrams that never completed",
             (unsigned int) swept);
    }
}

static void ctpFragNoteExpiryLocked(ctp_tstate_t *ts, const ctp_frag_entry_t *entry)
{
    if (ts->frag_next_expiry_ms == 0 || entry->expires_at_ms < ts->frag_next_expiry_ms)
    {
        ts->frag_next_expiry_ms = entry->expires_at_ms;
    }
}

// ---------------------------------------------------------------------------
// received-range tracking
// ---------------------------------------------------------------------------

typedef enum ctp_frag_range_result_e
{
    kCtpFragRangeAdded = 0,
    kCtpFragRangeOverlap,
    kCtpFragRangeCapReached
} ctp_frag_range_result_t;

/*
 * Inserts [begin, end) into the entry's sorted, disjoint, non-adjacent range
 * list.
 *
 * Only adjacency is merged. An actual overlap - which includes an exact
 * duplicate - is rejected rather than absorbed, because lwIP is built with
 * IP_REASS_CHECK_OVERLAP and throws such a fragment away. Absorbing it here
 * would credit coverage lwIP never received: [0,1024), [512,1536), [1536,2048)
 * looks like a whole 2048-byte datagram to a merging tracker while lwIP still
 * has the hole at [1024,1536).
 */
static ctp_frag_range_result_t ctpFragRangeAddLocked(ctp_frag_entry_t *entry, uint32_t begin, uint32_t end)
{
    uint8_t first = 0;

    // Ranges are kept non-adjacent, so this lands on the only entry that can
    // touch [begin, end) from the left.
    while (first < entry->range_count && entry->ranges[first].end < begin)
    {
        ++first;
    }

    uint8_t last = first; /* exclusive end of the run being replaced */

    if (last < entry->range_count && entry->ranges[last].end == begin)
    {
        begin = entry->ranges[last].begin;
        ++last;
    }

    if (last < entry->range_count && entry->ranges[last].begin < end)
    {
        return kCtpFragRangeOverlap;
    }

    if (last < entry->range_count && entry->ranges[last].begin == end)
    {
        end = entry->ranges[last].end;
        ++last;
    }

    const uint8_t replaced = (uint8_t) (last - first);

    if (replaced == 0)
    {
        // Touches nothing, so this needs a slot of its own.
        if (entry->range_count >= (uint8_t) kCtpFragMaxRanges)
        {
            return kCtpFragRangeCapReached;
        }

        for (uint8_t k = entry->range_count; k > first; --k)
        {
            entry->ranges[k] = entry->ranges[k - 1];
        }
        ++entry->range_count;
    }
    else if (replaced > 1)
    {
        const uint8_t removed = (uint8_t) (replaced - 1);
        for (uint8_t k = (uint8_t) (first + 1); (uint8_t) (k + removed) < entry->range_count; ++k)
        {
            entry->ranges[k] = entry->ranges[k + removed];
        }
        entry->range_count = (uint8_t) (entry->range_count - removed);
    }

    entry->ranges[first].begin = begin;
    entry->ranges[first].end   = end;
    return kCtpFragRangeAdded;
}

static bool ctpFragIsComplete(const ctp_frag_entry_t *entry)
{
    return entry->final_end != 0 && entry->range_count == 1 && entry->ranges[0].begin == 0 &&
           entry->ranges[0].end == entry->final_end;
}

/*
 * Structural checks that must run before a fragment is staged or routed. A
 * fragment that cannot be part of a well-formed datagram would otherwise occupy
 * an association slot and pull the received ranges apart.
 */
static bool ctpFragSpanIsWellFormed(const ctp_frag_span_t *span)
{
    if (span->payload_len == 0)
    {
        // Only a lone unfragmented packet may be empty, and that never gets here.
        return false;
    }

    if (! span->is_last && (span->payload_len % 8U) != 0)
    {
        // RFC 791: every fragment but the last carries a multiple of eight bytes.
        return false;
    }

    return (uint64_t) span->offset + span->payload_len <= (uint64_t) kCtpFragMaxDatagramLen;
}

/*
 * Checks the fragment against what this datagram is already known to be.
 *
 * The last fragment fixes the datagram's total length, and everything else has
 * to fit inside it. A peer that contradicts that is describing two different
 * datagrams under one identification, which is precisely the shape that must not
 * be allowed to accumulate coverage.
 */
static bool ctpFragSpanAgreesWithEntry(const ctp_frag_entry_t *entry, const ctp_frag_span_t *span)
{
    const uint32_t span_end = span->offset + span->payload_len;

    if (entry->final_end != 0)
    {
        if (span_end > entry->final_end)
        {
            // Data past a known end, or a second last-fragment claiming a longer
            // datagram than the first one did.
            return false;
        }

        if (span->is_last && span_end != entry->final_end)
        {
            return false;
        }

        return true;
    }

    if (span->is_last && entry->range_count > 0 && entry->ranges[entry->range_count - 1].end > span_end)
    {
        // A last fragment that ends before bytes this datagram already carries.
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// staging
// ---------------------------------------------------------------------------

/*
 * Moves everything the entry was holding, plus the fragment that resolved it,
 * into the batch the caller publishes once the lock is released.
 */
static void ctpFragDrainIntoBatchLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry, void *payload, uint32_t len,
                                        ctp_frag_publish_batch_t *batch)
{
    for (uint8_t i = 0; i < entry->pending_count; ++i)
    {
        ts->frag_pending_bytes -= entry->pending[i].len;
        batch->items[batch->count++] = entry->pending[i];
    }
    entry->pending_count = 0;

    batch->items[batch->count++] = (ctp_frag_pending_t) {.payload = payload, .len = len};
    batch->flow_key              = entry->flow_key;
    batch->generation            = entry->generation;
    batch->serial                = entry->serial;
    batch->wid                   = entry->wid;
}

static bool ctpFragHasStagingRoomLocked(const ctp_tstate_t *ts, const ctp_frag_entry_t *entry, uint32_t len)
{
    return entry->pending_count < (uint8_t) kCtpFragMaxPendingPerDatagram &&
           ts->frag_pending_bytes + len <= (uint32_t) kCtpFragMaxPendingBytesTotal;
}

/* Caller has already confirmed there is room. */
static void ctpFragHoldLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry, void *payload, uint32_t len)
{
    entry->pending[entry->pending_count++] = (ctp_frag_pending_t) {.payload = payload, .len = len};
    ts->frag_pending_bytes += len;
}

/*
 * Refuses an identification a different flow has tried to take over while the
 * previous datagram still had fragments inside lwIP.
 *
 * This used to adopt the identity for the new flow, which is safe in this table
 * but not in the stack behind it: lwIP keys its reassembly list on source,
 * destination, protocol and identification alone, so the new datagram's
 * fragments would be appended to the old one's half-built pbuf chain. Quarantine
 * is the conservative half of that trade - the new datagram is lost, rather than
 * spliced into a stranger's.
 */
static void ctpFragPoisonLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry, const ctp_frag_key_t *frag_key,
                                ctp_frag_discard_fn release, ctp_frag_purge_batch_t *purges, uint64_t now_ms)
{
    ctpFragReleaseEntryLocked(ts, entry, release, kDeviceFragSettlementUnknown);

    entry->state         = (uint8_t) kCtpFragStatePoisoned;
    entry->range_count   = 0;
    entry->final_end     = 0;
    entry->expires_at_ms = 0;
    ctpFragRequestPurgeLocked(entry, frag_key, purges, now_ms);
}

/*
 * Binds a not-yet-resolved association to the flow fragment zero names. The
 * staged fragments and the coverage they contributed belong to this same
 * datagram - they were simply waiting for the ports - so neither is discarded.
 *
 * The deadline restarts here because this is when those staged fragments first
 * enter lwIP, and lwIP's interval starts from that moment rather than from when
 * this node first saw them. Without the reset, a datagram whose fragment zero
 * arrived 14.9 seconds late would have its route expire almost immediately after
 * the stack began reassembling it. It is a one-time reset on binding, not a
 * refresh per fragment: lwIP's timer does not refresh either.
 */
static void ctpFragBindLocked(ctp_frag_entry_t *entry, const ctp_flow_key_t *flow_key, uint64_t generation, wid_t wid,
                              uint64_t now_ms)
{
    entry->flow_key      = *flow_key;
    entry->generation    = generation;
    entry->wid           = wid;
    entry->state         = (uint8_t) kCtpFragStateResolved;
    entry->expires_at_ms = now_ms + (uint64_t) kCtpFragTimeoutMs;
}

void ctpFragHandlePacket(tunnel_t *t, const ctp_frag_key_t *frag_key, const ctp_flow_key_t *zero_flow_key,
                         const ctp_frag_span_t *span, void *payload, uint32_t len, ctp_frag_publish_fn publish,
                         ctp_frag_discard_fn release, ctp_frag_purge_schedule_fn schedule_purge)
{
    ctpFragHandlePacketAt(t, ctpNowMs(), frag_key, zero_flow_key, span, payload, len, publish, release, schedule_purge);
}

/*
 * A dropped fragment must not leave a slot behind it. An entry that was created
 * for this fragment alone has nothing left to route once it is dropped, so it is
 * removed again; one that already holds something stays.
 */
static void ctpFragDropEmptyEntryLocked(ctp_tstate_t *ts, const ctp_frag_entry_t *entry, const ctp_frag_key_t *frag_key)
{
    if (entry->pending_count == 0 && entry->range_count == 0 && entry->state == (uint8_t) kCtpFragStateUnresolved)
    {
        ctp_frag_map_t_erase(&ts->frags, *frag_key);
    }
}

/* Existing association, or a fresh one if the table has room. */
static ctp_frag_entry_t *ctpFragFindOrCreateLocked(ctp_tstate_t *ts, const ctp_frag_key_t *frag_key, uint64_t now_ms)
{
    ctp_frag_map_t_iter it = ctp_frag_map_t_find(&ts->frags, *frag_key);

    if (it.ref != NULL)
    {
        return &it.ref->second;
    }

    /*
     * A fragment that is not fragment zero of a datagram this node already
     * tracks would have to be staged on speculation, so the association cap
     * applies before anything is retained for it.
     */
    if (ctp_frag_map_t_size(&ts->frags) >= (isize_t) kCtpFragMaxAssociations)
    {
        return NULL;
    }

    ctp_frag_entry_t fresh = {
        .serial        = ctpFragNextSerialLocked(ts),
        .expires_at_ms = now_ms + (uint64_t) kCtpFragTimeoutMs,
    };
    ctp_frag_map_t_result result = ctp_frag_map_t_insert(&ts->frags, *frag_key, fresh);

    return result.ref != NULL ? &result.ref->second : NULL;
}

typedef enum ctp_frag_zero_result_e
{
    kCtpFragZeroReady = 0,
    kCtpFragZeroNoFlow,
    kCtpFragZeroPoisoned
} ctp_frag_zero_result_t;

/*
 * Binds fragment zero's datagram to the flow it names. The lookup runs for every
 * fragment zero, not only an unresolved one: an identification is reused as soon
 * as the previous datagram finishes, so an entry that is still here may belong
 * to a datagram that stalled, and whichever flow this fragment zero resolves to
 * now is asking for the identity.
 */
static ctp_frag_zero_result_t ctpFragResolveZeroLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry,
                                                       const ctp_frag_key_t *frag_key,
                                                       const ctp_flow_key_t *zero_flow_key, uint64_t now_ms,
                                                       ctp_frag_discard_fn release, ctp_frag_purge_batch_t *purges,
                                                       wid_t *out_wid, uint64_t *out_generation)
{
    /*
     * A second fragment zero is ambiguous even when its transport tuple no
     * longer resolves. The first datagram may already have fragments inside
     * lwIP, so erasing its association on a failed flow lookup would release
     * the identification without first purging that partial reassembly.
     */
    if (entry->state != (uint8_t) kCtpFragStateUnresolved)
    {
        ctpFragPoisonLocked(ts, entry, frag_key, release, purges, now_ms);
        return kCtpFragZeroPoisoned;
    }

    if (! ctpFlowLookupWithLockHeld(ts, zero_flow_key, now_ms, out_wid, out_generation))
    {
        return kCtpFragZeroNoFlow;
    }

    /*
     * This is deliberately only a lookup. The staged ranges still have to be
     * checked against fragment zero, and committing the route before those
     * checks would leave a resolved association behind when the zero is
     * rejected. Nothing has reached lwIP while the entry is unresolved, so the
     * caller can discard it transactionally until ctpFragBindLocked().
     */
    return kCtpFragZeroReady;
}

/*
 * Records the fragment against its datagram and collects everything that becomes
 * publishable.
 *
 * Coverage is recorded for a staged fragment too, not only a routed one: those
 * fragments are part of the same datagram and are what completes it once
 * fragment zero supplies the ports.
 */
static void ctpFragAcceptLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry, const ctp_frag_span_t *span, void *payload,
                                uint32_t len, ctp_frag_publish_batch_t *batch)
{
    if (span->is_last)
    {
        entry->final_end = span->offset + span->payload_len;
    }

    if (entry->state == (uint8_t) kCtpFragStateUnresolved)
    {
        ctpFragHoldLocked(ts, entry, payload, len);
        ctpFragNoteExpiryLocked(ts, entry);
        return;
    }

    ctpFragDrainIntoBatchLocked(ts, entry, payload, len, batch);

    /*
     * This batch is leaving the lock. Until it has been enqueued, no purge
     * barrier for this association may be queued behind it.
     */
    assert(entry->outstanding_publishes < UINT16_MAX);
    ++entry->outstanding_publishes;
    assert((uint32_t) entry->pending_deliveries + batch->count <= UINT16_MAX);
    entry->pending_deliveries = (uint16_t) (entry->pending_deliveries + batch->count);

    if (ctpFragIsComplete(entry))
    {
        /*
         * The entry deliberately stays in the map until the batch has actually
         * been enqueued. Erasing it here instead would free the identification
         * while these messages were still in this thread's hands, letting
         * another worker resolve the same identification for a newer datagram
         * and enqueue its fragments ahead of the ones that finish this one.
         * Matching traffic is dropped for that window - see kCtpFragStatePublishing.
         */
        entry->state          = (uint8_t) kCtpFragStatePublishing;
        entry->purge_required = true;
        batch->completed      = true;
    }

    ctpFragNoteExpiryLocked(ts, entry);
}

/*
 * Final half of a completed or poisoned datagram: the owner-worker FIFO reached
 * its exact purge barrier, so the identification can be released. The serial
 * check keeps this from erasing an entry Stop cleared and something else
 * recreated.
 */
void ctpFragRetirePurged(tunnel_t *t, const ctp_frag_key_t *frag_key, uint64_t serial, bool exact_absence)
{
    ctp_tstate_t *ts = tunnelGetState(t);
    void         *receipts[kCtpFragMaxPendingPerDatagram + 1];
    uint8_t       receipt_count = 0;

    rwlockWriteLock(&ts->flows_lock);
    ctp_frag_map_t_iter it = ctp_frag_map_t_find(&ts->frags, *frag_key);

    if (it.ref != NULL && it.ref->second.serial == serial &&
        (it.ref->second.state == (uint8_t) kCtpFragStatePublishing ||
         it.ref->second.state == (uint8_t) kCtpFragStatePoisoned))
    {
        receipt_count = it.ref->second.refused_receipt_count;
        memcpy(receipts, it.ref->second.refused_receipts, sizeof(it.ref->second.refused_receipts[0]) * receipt_count);
        it.ref->second.refused_receipt_count = 0;
        ctp_frag_map_t_erase_at(&ts->frags, it);
    }
    rwlockWriteUnlock(&ts->flows_lock);

    for (uint8_t i = 0; i < receipt_count; ++i)
    {
        deviceFragClaimResolve(receipts[i],
                               exact_absence ? kDeviceFragSettlementNoResidue : kDeviceFragSettlementUnknown);
    }
}

void ctpFragSettleDeliveryAt(tunnel_t *t, const ctp_frag_key_t *frag_key, uint64_t serial, bool delivered,
                             uint64_t now_ms, ctp_frag_purge_schedule_fn schedule_purge)
{
    ctp_tstate_t          *ts     = tunnelGetState(t);
    ctp_frag_purge_batch_t purges = {0};

    rwlockWriteLock(&ts->flows_lock);
    ctp_frag_map_t_iter it = ctp_frag_map_t_find(&ts->frags, *frag_key);

    if (it.ref != NULL && it.ref->second.serial == serial)
    {
        ctp_frag_entry_t *entry    = &it.ref->second;
        const bool        stopping = atomicLoadRelaxed(&ts->stopping);

        assert(entry->pending_deliveries > 0);
        --entry->pending_deliveries;

        if (stopping)
        {
            /* Stop owns the netif-wide purge and table sweep from this point. */
        }
        else if (delivered)
        {
            /*
             * Only an incomplete, healthy association needs a new lifetime.
             * Completed/poisoned identities already owe a FIFO purge barrier.
             */
            if (entry->state == (uint8_t) kCtpFragStateResolved)
            {
                const uint64_t delivered_expiry = now_ms + (uint64_t) kCtpFragTimeoutMs;
                if (entry->expires_at_ms < delivered_expiry)
                {
                    entry->expires_at_ms = delivered_expiry;
                }
                ctpFragNoteExpiryLocked(ts, entry);
            }
        }
        else
        {
            /* A missing injected fragment leaves any lwIP residue unusable. */
            entry->state          = (uint8_t) kCtpFragStatePoisoned;
            entry->range_count    = 0;
            entry->final_end      = 0;
            entry->expires_at_ms  = 0;
            entry->purge_required = true;
        }

        if (! stopping && entry->purge_required)
        {
            ctpFragRequestPurgeLocked(entry, frag_key, &purges, now_ms);
        }
    }
    rwlockWriteUnlock(&ts->flows_lock);

    ctpFragSchedulePurgeBatch(t, &purges, schedule_purge, now_ms);
}

void ctpFragSettleDelivery(tunnel_t *t, const ctp_frag_key_t *frag_key, uint64_t serial, bool delivered,
                           ctp_frag_purge_schedule_fn schedule_purge)
{
    ctpFragSettleDeliveryAt(t, frag_key, serial, delivered, ctpNowMs(), schedule_purge);
}

typedef enum ctp_frag_drop_reason_e
{
    kCtpFragKept = 0,
    kCtpFragDropMalformed,
    kCtpFragDropInconsistent,
    kCtpFragDropOverlap,
    kCtpFragDropQuarantined,
    kCtpFragDropAssociationCap,
    kCtpFragDropStagingCap,
    kCtpFragDropRangeCap,
    kCtpFragDropNoFlow
} ctp_frag_drop_reason_t;

static void ctpFragReportDrop(ctp_frag_drop_reason_t reason, const ctp_frag_span_t *span)
{
    switch (reason)
    {
    case kCtpFragDropMalformed:
        if (atomicLogRateLimiterShouldLog(&g_frag_malformed_log, kCtpFragDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: dropping a malformed return fragment (offset %u, payload %u, last %u)",
                 (unsigned int) span->offset,
                 (unsigned int) span->payload_len,
                 (unsigned int) span->is_last);
        }
        break;
    case kCtpFragDropInconsistent:
        if (atomicLogRateLimiterShouldLog(&g_frag_inconsistent_log, kCtpFragDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: dropping a return fragment that contradicts its datagram's known length "
                 "(offset %u, payload %u, last %u)",
                 (unsigned int) span->offset,
                 (unsigned int) span->payload_len,
                 (unsigned int) span->is_last);
        }
        break;
    case kCtpFragDropOverlap:
        if (atomicLogRateLimiterShouldLog(&g_frag_overlap_log, kCtpFragDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: dropping a duplicate or overlapping return fragment "
                 "(offset %u, payload %u); lwIP discards these too",
                 (unsigned int) span->offset,
                 (unsigned int) span->payload_len);
        }
        break;
    case kCtpFragDropQuarantined:
        if (atomicLogRateLimiterShouldLog(&g_frag_quarantine_log, kCtpFragDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: dropping a return fragment whose IPv4 identification is still held by "
                 "another datagram inside lwIP");
        }
        break;
    case kCtpFragDropAssociationCap:
        if (atomicLogRateLimiterShouldLog(&g_frag_association_cap_log, kCtpFragDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: dropping a return fragment, all %d datagram associations are in use",
                 (int) kCtpFragMaxAssociations);
        }
        break;
    case kCtpFragDropStagingCap:
        if (atomicLogRateLimiterShouldLog(&g_frag_pending_cap_log, kCtpFragDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: dropping a return fragment, the staging bound for one datagram "
                 "(%d fragments) or the shared staging bound (%d bytes) is full",
                 (int) kCtpFragMaxPendingPerDatagram,
                 (int) kCtpFragMaxPendingBytesTotal);
        }
        break;
    case kCtpFragDropRangeCap:
        if (atomicLogRateLimiterShouldLog(&g_frag_range_cap_log, kCtpFragDropLogIntervalMs))
        {
            LOGW("ConnectionToPackets: dropping a return fragment, one datagram is split across more than %d ranges",
                 (int) kCtpFragMaxRanges);
        }
        break;
    case kCtpFragDropNoFlow:
        LOGD("ConnectionToPackets: dropping a return fragment that matches no registered flow");
        break;
    case kCtpFragKept:
    default:
        break;
    }
}

/*
 * Resolves fragment zero, if this is one. Returns a drop reason, or kCtpFragKept
 * when the entry may go on to record the fragment.
 */
static ctp_frag_drop_reason_t ctpFragBindZeroLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry,
                                                    const ctp_frag_key_t *frag_key, const ctp_flow_key_t *zero_flow_key,
                                                    uint64_t now_ms, ctp_frag_discard_fn release,
                                                    ctp_frag_purge_batch_t *purges, wid_t *out_wid,
                                                    uint64_t *out_generation)
{
    switch (
        ctpFragResolveZeroLocked(ts, entry, frag_key, zero_flow_key, now_ms, release, purges, out_wid, out_generation))
    {
    case kCtpFragZeroReady:
        return kCtpFragKept;

    case kCtpFragZeroPoisoned:
        // The entry stays, quarantining the identification; this fragment goes.
        return kCtpFragDropQuarantined;

    case kCtpFragZeroNoFlow:
    default:
        // No flow owns this datagram, so nothing staged for it could ever be
        // delivered either.
        ctpFragReleaseEntryLocked(ts, entry, release, kDeviceFragSettlementUnknown);
        ctp_frag_map_t_erase(&ts->frags, *frag_key);
        return kCtpFragDropNoFlow;
    }
}

/*
 * Fragment zero resolved a flow, but failed before the association was
 * committed. No payload in an unresolved entry has reached lwIP, so rollback is
 * a plain release-and-erase: scheduling a purge here would target state the
 * stack never owned.
 */
static void ctpFragRollbackUnresolvedZeroLocked(ctp_tstate_t *ts, ctp_frag_entry_t *entry,
                                                const ctp_frag_key_t *frag_key, ctp_frag_discard_fn release)
{
    assert(entry->state == (uint8_t) kCtpFragStateUnresolved);
    ctpFragReleaseEntryLocked(ts, entry, release, kDeviceFragSettlementUnknown);
    ctp_frag_map_t_erase(&ts->frags, *frag_key);
}

/* Runs under the write lock. Publishing and reporting happen after it is released. */
static ctp_frag_drop_reason_t ctpFragClassifyLocked(ctp_tstate_t *ts, const ctp_frag_key_t *frag_key,
                                                    const ctp_flow_key_t *zero_flow_key, const ctp_frag_span_t *span,
                                                    void *payload, uint32_t len, uint64_t now_ms,
                                                    ctp_frag_publish_batch_t *batch, ctp_frag_discard_fn release,
                                                    ctp_frag_purge_batch_t *purges)
{
    ctpFragSweepExpiredLocked(ts, now_ms, release, purges);

    ctp_frag_entry_t *entry = ctpFragFindOrCreateLocked(ts, frag_key, now_ms);

    if (entry == NULL)
    {
        return kCtpFragDropAssociationCap;
    }

    if (entry->state == (uint8_t) kCtpFragStatePoisoned || entry->state == (uint8_t) kCtpFragStatePublishing)
    {
        // Either lwIP still holds a different datagram under this identification,
        // or the batch that finishes the current one has not been enqueued yet.
        // Both windows must not admit new fragments, and neither may be adopted.
        ctpFragRequestPurgeLocked(entry, frag_key, purges, now_ms);
        return kCtpFragDropQuarantined;
    }

    wid_t    zero_wid              = 0;
    uint64_t zero_generation       = 0;
    bool     unresolved_zero_ready = false;

    if (span->is_first)
    {
        const ctp_frag_drop_reason_t bound = ctpFragBindZeroLocked(
            ts, entry, frag_key, zero_flow_key, now_ms, release, purges, &zero_wid, &zero_generation);

        if (bound != kCtpFragKept)
        {
            return bound;
        }

        unresolved_zero_ready = true;
    }

    if (UNLIKELY(! ctpFragSpanAgreesWithEntry(entry, span)))
    {
        if (unresolved_zero_ready)
        {
            ctpFragRollbackUnresolvedZeroLocked(ts, entry, frag_key, release);
        }
        else
        {
            ctpFragDropEmptyEntryLocked(ts, entry, frag_key);
        }
        return kCtpFragDropInconsistent;
    }

    /*
     * Every bound is checked before anything is recorded. A fragment that is
     * about to be dropped must not contribute coverage, or the datagram could
     * look complete while a fragment never reached lwIP.
     */
    if (entry->state == (uint8_t) kCtpFragStateUnresolved && ! unresolved_zero_ready &&
        ! ctpFragHasStagingRoomLocked(ts, entry, len))
    {
        ctpFragDropEmptyEntryLocked(ts, entry, frag_key);
        return kCtpFragDropStagingCap;
    }

    switch (ctpFragRangeAddLocked(entry, span->offset, span->offset + span->payload_len))
    {
    case kCtpFragRangeAdded:
        break;

    case kCtpFragRangeOverlap:
        if (unresolved_zero_ready)
        {
            ctpFragRollbackUnresolvedZeroLocked(ts, entry, frag_key, release);
        }
        else
        {
            ctpFragDropEmptyEntryLocked(ts, entry, frag_key);
        }
        return kCtpFragDropOverlap;

    case kCtpFragRangeCapReached:
    default:
        if (unresolved_zero_ready)
        {
            ctpFragRollbackUnresolvedZeroLocked(ts, entry, frag_key, release);
        }
        else
        {
            ctpFragDropEmptyEntryLocked(ts, entry, frag_key);
        }
        return kCtpFragDropRangeCap;
    }

    if (unresolved_zero_ready)
    {
        /*
         * Every rejecting operation is now behind us. From this commit through
         * ctpFragAcceptLocked() there is no fallible step, so a resolved entry
         * can never exist without fragment zero entering its publish batch.
         */
        ctpFragBindLocked(entry, zero_flow_key, zero_generation, zero_wid, now_ms);
    }

    ctpFragAcceptLocked(ts, entry, span, payload, len, batch);
    return kCtpFragKept;
}

static void ctpFragPurgeQueueFailed(tunnel_t *t, const ctp_frag_purge_request_t *request, uint64_t now_ms)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    rwlockWriteLock(&ts->flows_lock);
    ctp_frag_map_t_iter it = ctp_frag_map_t_find(&ts->frags, request->key);
    if (it.ref != NULL && it.ref->second.serial == request->serial)
    {
        /*
         * Still owed, just not queued. The retry deadline is what gets the sweep
         * to look at this entry again: a poisoned association contributes no
         * ordinary expiry, so without one only traffic carrying this exact
         * identification would ever retry - and the slot would be pinned until
         * that happened to arrive.
         */
        it.ref->second.purge_queued  = false;
        it.ref->second.expires_at_ms = now_ms + (uint64_t) kCtpFragPurgeRetryMs;
        ctpFragNoteExpiryLocked(ts, &it.ref->second);
    }
    rwlockWriteUnlock(&ts->flows_lock);
}

static void ctpFragSchedulePurgeBatch(tunnel_t *t, const ctp_frag_purge_batch_t *purges,
                                      ctp_frag_purge_schedule_fn schedule_purge, uint64_t now_ms)
{
    for (uint16_t i = 0; i < purges->count; ++i)
    {
        const ctp_frag_purge_request_t *request = &purges->items[i];

        if (! schedule_purge(t, &request->key, request->serial, request->wid))
        {
            /* Keep the identity poisoned and let later traffic retry the barrier. */
            ctpFragPurgeQueueFailed(t, request, now_ms);
        }
    }
}

/*
 * One publish batch has finished enqueueing.
 *
 * This is the other half of the count taken during classification, and it is
 * where a barrier finally becomes queueable. Doing it here rather than at the
 * end of classification is the whole point: another worker may have completed or
 * poisoned this same datagram while this batch was still in flight, and its
 * barrier must not reach the owner worker before these fragments do.
 *
 * The serial is what makes that safe across reuse - an entry Stop cleared and
 * something else recreated carries a different one, so this settles nothing.
 */
static void ctpFragSettlePublishBatch(tunnel_t *t, const ctp_frag_key_t *frag_key,
                                      const ctp_frag_publish_batch_t *batch, const ctp_frag_publish_result_t *results,
                                      uint64_t now_ms, ctp_frag_purge_batch_t *purges)
{
    ctp_tstate_t *ts        = tunnelGetState(t);
    bool          published = true;
    void         *unknown_receipts[kCtpFragMaxPendingPerDatagram + 1];
    uint8_t       unknown_receipt_count = 0;

    rwlockWriteLock(&ts->flows_lock);

    ctp_frag_map_t_iter it = ctp_frag_map_t_find(&ts->frags, *frag_key);

    if (it.ref != NULL && it.ref->second.serial == batch->serial)
    {
        ctp_frag_entry_t *entry = &it.ref->second;

        assert(entry->outstanding_publishes > 0);
        --entry->outstanding_publishes;

        for (uint8_t i = 0; i < batch->count; ++i)
        {
            if (! results[i].accepted)
            {
                assert(entry->pending_deliveries > 0);
                --entry->pending_deliveries;
                published = false;
                if (results[i].refused_receipt != NULL)
                {
                    if (entry->refused_receipt_count < ARRAY_SIZE(entry->refused_receipts))
                    {
                        entry->refused_receipts[entry->refused_receipt_count++] = results[i].refused_receipt;
                    }
                    else
                    {
                        /*
                         * Concurrent refused batches can outnumber the per-datagram
                         * retention bound. Conservatively quarantine any overflow;
                         * never turn a bounded ownership table into an overwrite.
                         */
                        unknown_receipts[unknown_receipt_count++] = results[i].refused_receipt;
                    }
                }
            }
        }

        if (! published)
        {
            /*
             * Some fragment of this datagram never reached the owner worker, so
             * lwIP holds a reassembly that can never complete. The identity is
             * poisoned and purged rather than left to time out.
             */
            entry->state          = (uint8_t) kCtpFragStatePoisoned;
            entry->range_count    = 0;
            entry->final_end      = 0;
            entry->expires_at_ms  = 0;
            entry->purge_required = true;
        }

        if (entry->purge_required)
        {
            ctpFragRequestPurgeLocked(entry, frag_key, purges, now_ms);
        }
    }
    else
    {
        for (uint8_t i = 0; i < batch->count; ++i)
        {
            if (results[i].refused_receipt != NULL)
            {
                unknown_receipts[unknown_receipt_count++] = results[i].refused_receipt;
            }
        }
    }

    rwlockWriteUnlock(&ts->flows_lock);

    for (uint8_t i = 0; i < unknown_receipt_count; ++i)
    {
        deviceFragClaimResolve(unknown_receipts[i], kDeviceFragSettlementUnknown);
    }
}

void ctpFragHandlePacketAt(tunnel_t *t, uint64_t now_ms, const ctp_frag_key_t *frag_key,
                           const ctp_flow_key_t *zero_flow_key, const ctp_frag_span_t *span, void *payload,
                           uint32_t len, ctp_frag_publish_fn publish, ctp_frag_discard_fn release,
                           ctp_frag_purge_schedule_fn schedule_purge)
{
    ctp_tstate_t            *ts     = tunnelGetState(t);
    ctp_frag_publish_batch_t batch  = {0};
    ctp_frag_purge_batch_t   purges = {0};
    ctp_frag_drop_reason_t   reason;

    if (UNLIKELY(! ctpFragSpanIsWellFormed(span)))
    {
        ctpFragReportDrop(kCtpFragDropMalformed, span);
        release(payload);
        return;
    }

    rwlockWriteLock(&ts->flows_lock);

    /*
     * The downstream handler checked this gate too, but that was before the
     * packet was copied and before this lock was taken, and Stop clears the whole
     * table while holding it. A classifier that got here first is cleared by
     * Stop's own sweep; one that arrives afterwards would stage an association
     * into a table nobody will ever release, and schedule publication or purge
     * work against a netif that no longer exists.
     *
     * Rechecking here closes that window, and the ordering is what makes it a
     * barrier rather than a narrowing: Stop publishes the atomic before it waits
     * for this same lock, so every classifier either precedes the sweep or
     * observes the gate.
     */
    if (UNLIKELY(atomicLoadRelaxed(&ts->stopping)))
    {
        rwlockWriteUnlock(&ts->flows_lock);
        release(payload);
        return;
    }

    reason = ctpFragClassifyLocked(ts, frag_key, zero_flow_key, span, payload, len, now_ms, &batch, release, &purges);
    rwlockWriteUnlock(&ts->flows_lock);

    if (reason != kCtpFragKept)
    {
        ctpFragSchedulePurgeBatch(t, &purges, schedule_purge, now_ms);
        ctpFragReportDrop(reason, span);
        release(payload);
        return;
    }

    ctp_frag_publish_result_t results[kCtpFragMaxPendingPerDatagram + 1] = {0};
    for (uint8_t i = 0; i < batch.count; ++i)
    {
        results[i] =
            publish(t, &batch.flow_key, batch.generation, batch.wid, frag_key, batch.serial, batch.items[i].payload);
    }

    /*
     * Every fragment of this batch is now in the owner worker's FIFO, so this
     * batch can no longer be overtaken by a barrier. Whether one is owed - by
     * this batch completing the datagram, by another worker poisoning it while
     * this batch was in flight, or by a publish failure above - is decided
     * inside, under the lock.
     */
    if (batch.count > 0)
    {
        ctpFragSettlePublishBatch(t, frag_key, &batch, results, now_ms, &purges);
    }

    ctpFragSchedulePurgeBatch(t, &purges, schedule_purge, now_ms);
}
