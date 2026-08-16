#include "structure.h"

#include "loggers/network_logger.h"

#include "loggers/log_rate_limiter.h"

/*
 * The tuple registry.
 *
 * It is guarded by its own reader/writer lock rather than by LOCK_TCPIP_CORE(),
 * because the hottest reader - the return-packet lookup in the packet line's
 * downstream callback - must not depend on a neighboring packet node's lock
 * context. PacketsToConnection now defers its publication outside the lwIP core
 * lock, but other packet neighbors are not required to share that
 * implementation detail. Keeping lookup on this independent lock preserves
 * composition and avoids a non-recursive core-lock dependency.
 *
 * Lock order where both are needed: LOCK_TCPIP_CORE() first, flows_lock second.
 * Every mutating caller here already holds the core lock for the pcb work that
 * accompanies the registry change; the lookup path holds neither and calls into
 * nothing.
 */

enum
{
    kCtpTombstoneLogIntervalMs = 5U * 1000U
};

/* Shared by every worker, so the gate has to be atomic. */
static atomic_log_rate_limiter_t g_tombstone_evict_log;

static bool ctpFlowRegisterAt(tunnel_t *t, ctp_lstate_t *ls, void *pcb, uint8_t protocol, uint64_t now_ms);
static void ctpFlowRetireAt(tunnel_t *t, ctp_lstate_t *ls, bool graceful, uint64_t now_ms);

bool ctpFlowRegistryInitialize(ctp_tstate_t *ts)
{
    if (UNLIKELY(! rwlockTryInit(&ts->flows_lock)))
    {
        return false;
    }
    ts->flows           = ctp_flow_map_t_with_capacity(128);
    ts->next_generation = 0;
    ts->tombstones      = memoryAllocateZero(sizeof(ctp_tombstone_ref_t) * (size_t) kCtpMaxTombstones);
    ts->tomb_head       = 0;
    ts->tomb_count      = 0;

    if (UNLIKELY(ctp_flow_map_t_capacity(&ts->flows) < 128 || ! ctpFragTableInitialize(ts) || ts->tombstones == NULL))
    {
        ctp_frag_map_t_drop(&ts->frags);
        ctp_flow_map_t_drop(&ts->flows);
        memoryFree(ts->tombstones);
        ts->tombstones = NULL;
        rwlockDestroy(&ts->flows_lock);
        return false;
    }

    ts->flow_registry_initialized = true;
    return true;
}

void ctpFlowRegistryDestroy(ctp_tstate_t *ts)
{
    if (! ts->flow_registry_initialized)
    {
        return;
    }

    ctpFragTableDestroy(ts, ctpInjectMessageDestroy);
    ctp_flow_map_t_drop(&ts->flows);
    memoryFree(ts->tombstones);
    ts->tombstones = NULL;
    rwlockDestroy(&ts->flows_lock);
    ts->flow_registry_initialized = false;
}

static uint64_t ctpNextGenerationLocked(ctp_tstate_t *ts)
{
    ts->next_generation += 1;
    if (UNLIKELY(ts->next_generation == 0))
    {
        // Zero is reserved for "no generation", so it can never be handed out.
        ts->next_generation = 1;
    }
    return ts->next_generation;
}

// ---------------------------------------------------------------------------
// tombstone ring
// ---------------------------------------------------------------------------

/*
 * Drops the map entry a ring record names, but only if that entry is still the
 * one the record was written for.
 *
 * A tuple can be unregistered, or taken over by a new flow, while its record is
 * still queued. The generation is what separates those cases from the ordinary
 * one, and it is why an active or draining entry can never be evicted by ring
 * pressure: it either carries a newer generation or is not detached at all.
 */
static void ctpTombstoneReleaseRecordLocked(ctp_tstate_t *ts, const ctp_tombstone_ref_t *record)
{
    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, record->key);

    if (it.ref != NULL && it.ref->second.detached && it.ref->second.generation == record->generation)
    {
        ctp_flow_map_t_erase_at(&ts->flows, it);
    }
}

static void ctpTombstonePopFrontLocked(ctp_tstate_t *ts)
{
    ctpTombstoneReleaseRecordLocked(ts, &ts->tombstones[ts->tomb_head]);

    ts->tomb_head = (ts->tomb_head + 1U) % (uint32_t) kCtpMaxTombstones;
    --ts->tomb_count;
}

/*
 * Retires every tombstone whose grace period has elapsed.
 *
 * The ring is ordered by deadline, so this stops at the first record that is
 * still young instead of scanning the map. That matters because the callers hold
 * the global lwIP core lock: the old age-based map scan grew with the number of
 * live tombstones and ran on every registration.
 */
static void ctpTombstoneDrainExpiredLocked(ctp_tstate_t *ts, uint64_t now_ms)
{
    while (ts->tomb_count > 0 && now_ms >= ts->tombstones[ts->tomb_head].expires_at_ms)
    {
        ctpTombstonePopFrontLocked(ts);
    }
}

/* Called with flows_lock held for writing, from the graceful-close path. */
static void ctpTombstonePushLocked(ctp_tstate_t *ts, const ctp_flow_key_t *key, uint64_t generation,
                                   uint64_t expires_at_ms, uint64_t now_ms)
{
    ctpTombstoneDrainExpiredLocked(ts, now_ms);

    if (ts->tomb_count == (uint32_t) kCtpMaxTombstones)
    {
        /*
         * Every tombstone is still inside its grace period and one more has to
         * fit, so the oldest gives up its place. This is the case an age-based
         * sweep could not handle at all: more than kCtpMaxTombstones flows can
         * close inside one grace period, and without this the map would simply
         * keep growing.
         */
        ctpTombstonePopFrontLocked(ts);

        if (atomicLogRateLimiterShouldLog(&g_tombstone_evict_log, kCtpTombstoneLogIntervalMs))
        {
            LOGD("ConnectionToPackets: evicting the oldest closing-flow tuple, all %d grace-period slots are in use; "
                 "late close traffic for it will not be routed",
                 (int) kCtpMaxTombstones);
        }
    }

    const uint32_t slot = (ts->tomb_head + ts->tomb_count) % (uint32_t) kCtpMaxTombstones;

    ts->tombstones[slot] =
        (ctp_tombstone_ref_t) {.key = *key, .generation = generation, .expires_at_ms = expires_at_ms};
    ++ts->tomb_count;
}

bool ctpFlowRegister(tunnel_t *t, ctp_lstate_t *ls, void *pcb, uint8_t protocol)
{
    return ctpFlowRegisterAt(t, ls, pcb, protocol, ctpNowMs());
}

static bool ctpFlowRegisterAt(tunnel_t *t, ctp_lstate_t *ls, void *pcb, uint8_t protocol, uint64_t now_ms)
{
    ctp_tstate_t *ts    = tunnelGetState(t);
    bool          taken = false;

    assert(! ls->flow_registered);

    rwlockWriteLock(&ts->flows_lock);

    ctpTombstoneDrainExpiredLocked(ts, now_ms);

    ctp_flow_entry_t entry = {
        .pcb        = pcb,
        .lstate     = ls,
        .generation = ctpNextGenerationLocked(ts),
        .wid        = lineGetWID(ls->line),
        .protocol   = protocol,
        .detached   = false,
    };

    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, ls->flow_key);

    if (it.ref == NULL)
    {
        taken = ctp_flow_map_t_insert(&ts->flows, ls->flow_key, entry).inserted;
    }
    else if (it.ref->second.detached)
    {
        /*
         * lwIP has already handed out this exact local port, so the tombstone is
         * stale by definition and the new flow takes the tuple over. Refusing
         * here would turn an accepted late-packet ambiguity into a visible
         * connection failure.
         *
         * The old ring record stays where it is. Its generation no longer matches
         * the entry, so when it reaches the front it will decline to erase this
         * live flow and simply free its slot.
         */
        it.ref->second = entry;
        taken          = true;
    }

    rwlockWriteUnlock(&ts->flows_lock);

    if (! taken)
    {
        // An *active* entry on the same tuple. lwIP does not reissue a port it
        // still owns, so this means the registry and the stack disagree.
        LOGW("ConnectionToPackets: refusing a flow whose tuple is still owned by a live flow");
        return false;
    }

    ls->generation      = entry.generation;
    ls->flow_registered = true;
    return true;
}

void ctpFlowUnregister(tunnel_t *t, ctp_lstate_t *ls)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    if (! ls->flow_registered)
    {
        return;
    }

    rwlockWriteLock(&ts->flows_lock);
    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, ls->flow_key);
    if (it.ref != NULL && it.ref->second.generation == ls->generation)
    {
        // Any ring record naming this entry is left to expire on its own; the
        // generation check makes it a no-op when it reaches the front.
        ctp_flow_map_t_erase_at(&ts->flows, it);
    }
    rwlockWriteUnlock(&ts->flows_lock);

    ls->flow_registered = false;
    ls->generation      = 0;
}

/*
 * Marks the entry as a tombstone: the borrowed line is gone but lwIP still owns
 * a closing pcb, so the tuple must keep resolving to the same worker and netif
 * until the close completes or the grace period expires.
 *
 * There is no timer. One worker timer per graceful close made both the timer
 * queue and shutdown cost grow with connection churn. The deadline goes into the
 * entry and into the retirement ring, which is what actually bounds how many
 * tombstones can exist at once.
 */
void ctpFlowRetire(tunnel_t *t, ctp_lstate_t *ls, bool graceful)
{
    ctpFlowRetireAt(t, ls, graceful, ctpNowMs());
}

static void ctpFlowRetireAt(tunnel_t *t, ctp_lstate_t *ls, bool graceful, uint64_t now_ms)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    if (! ls->flow_registered)
    {
        return;
    }

    if (! graceful)
    {
        ctpFlowUnregister(t, ls);
        return;
    }

    const uint64_t expires_at = now_ms + (uint64_t) kCtpFlowCloseGraceMs;

    rwlockWriteLock(&ts->flows_lock);

    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, ls->flow_key);
    if (it.ref != NULL && it.ref->second.generation == ls->generation)
    {
        // lwIP owns the pcb from here on, so this node must never touch it again.
        it.ref->second.pcb           = NULL;
        it.ref->second.lstate        = NULL;
        it.ref->second.detached      = true;
        it.ref->second.expires_at_ms = expires_at;

        ctpTombstonePushLocked(ts, &ls->flow_key, ls->generation, expires_at, now_ms);
    }

    rwlockWriteUnlock(&ts->flows_lock);

    ls->flow_registered = false;
    ls->generation      = 0;
}

/*
 * The line is finishing but its pcb is not: a drain has taken it over and is
 * still writing bytes the application handed this node before it closed.
 *
 * The entry stays active - not detached - for the whole drain. That is what
 * keeps tombstone pressure and the expiry drain from evicting a tuple whose pcb
 * this node still owns, and it is why `draining` is a separate flag rather than
 * a variety of tombstone.
 */
void ctpFlowMarkDrainingLocked(tunnel_t *t, ctp_lstate_t *ls)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    rwlockWriteLock(&ts->flows_lock);

    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, ls->flow_key);
    if (it.ref != NULL && it.ref->second.generation == ls->generation)
    {
        // The line state is about to be destroyed, so nothing may point at it.
        it.ref->second.lstate   = NULL;
        it.ref->second.draining = true;
    }

    rwlockWriteUnlock(&ts->flows_lock);

    ls->flow_registered = false;
    ls->generation      = 0;
}

/*
 * The drain is over. A graceful end means lwIP now owns a closing pcb, so the
 * tuple becomes an ordinary tombstone; anything else means the pcb is gone and
 * there is nothing left to route to.
 */
void ctpFlowRetireDrainLocked(tunnel_t *t, const ctp_flow_key_t *key, uint64_t generation, bool graceful)
{
    ctp_tstate_t  *ts         = tunnelGetState(t);
    const uint64_t now_ms     = ctpNowMs();
    const uint64_t expires_at = now_ms + (uint64_t) kCtpFlowCloseGraceMs;

    rwlockWriteLock(&ts->flows_lock);

    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, *key);

    if (it.ref != NULL && it.ref->second.generation == generation && it.ref->second.draining)
    {
        it.ref->second.pcb      = NULL;
        it.ref->second.draining = false;

        if (graceful)
        {
            it.ref->second.detached      = true;
            it.ref->second.expires_at_ms = expires_at;
            ctpTombstonePushLocked(ts, key, generation, expires_at, now_ms);
        }
        else
        {
            ctp_flow_map_t_erase_at(&ts->flows, it);
        }
    }

    rwlockWriteUnlock(&ts->flows_lock);
}

/*
 * A detached entry past its deadline is not a route any more.
 *
 * The ring retires these in bulk, but only when a flow registers or retires. A
 * node that has gone quiet does neither, so expiry is enforced at the point of
 * use as well: without this a tombstone could keep answering for its tuple
 * indefinitely just because no later flow ever came along to trigger a drain.
 */
static bool ctpFlowEntryIsRoutable(const ctp_flow_entry_t *entry, uint64_t now_ms)
{
    return ! entry->detached || now_ms < entry->expires_at_ms;
}

bool ctpFlowLookupWithLockHeld(ctp_tstate_t *ts, const ctp_flow_key_t *key, uint64_t now_ms, wid_t *out_wid,
                               uint64_t *out_generation)
{
    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, *key);
    if (it.ref == NULL || ! ctpFlowEntryIsRoutable(&it.ref->second, now_ms))
    {
        return false;
    }

    *out_wid        = it.ref->second.wid;
    *out_generation = it.ref->second.generation;
    return true;
}

bool ctpFlowLookup(tunnel_t *t, const ctp_flow_key_t *key, wid_t *out_wid, uint64_t *out_generation)
{
    ctp_tstate_t  *ts     = tunnelGetState(t);
    const uint64_t now_ms = ctpNowMs();

    rwlockReadLock(&ts->flows_lock);
    const bool found = ctpFlowLookupWithLockHeld(ts, key, now_ms, out_wid, out_generation);
    rwlockReadUnlock(&ts->flows_lock);

    return found;
}

bool ctpFlowStillOwns(tunnel_t *t, const ctp_flow_key_t *key, uint64_t generation, wid_t wid)
{
    ctp_tstate_t  *ts     = tunnelGetState(t);
    const uint64_t now_ms = ctpNowMs();
    bool           valid  = false;

    rwlockReadLock(&ts->flows_lock);
    ctp_flow_map_t_iter it = ctp_flow_map_t_find(&ts->flows, *key);
    if (it.ref != NULL && ctpFlowEntryIsRoutable(&it.ref->second, now_ms))
    {
        valid = it.ref->second.generation == generation && it.ref->second.wid == wid;
    }
    rwlockReadUnlock(&ts->flows_lock);

    return valid;
}

/*
 * Stop-time teardown, called with LOCK_TCPIP_CORE() held. Detaching the
 * callbacks here is what makes a borrowed line's later Finish safe: it rechecks
 * the stopping gate under the same core lock, finds it set, and skips every pcb
 * operation.
 */
void ctpFlowDropAllLocked(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    /*
     * The constructor can fail before the registry exists, and
     * ctpFlowRegistryInitialize() destroys the lock again when its own later
     * allocation fails. Both unwind through ctpTunnelDestroy(), so this sweep -
     * the lowest helper that touches flows_lock - is what has to decide there is
     * nothing to sweep. Locking a lock that was never created, or one that was
     * already destroyed, is undefined behavior, not a recoverable error.
     */
    if (! ts->flow_registry_initialized)
    {
        return;
    }

    rwlockWriteLock(&ts->flows_lock);

    c_foreach(i, ctp_flow_map_t, ts->flows)
    {
        ctp_flow_entry_t *entry = &i.ref->second;

        /*
         * The owning line is still alive - its worker has not drained yet - and
         * its own copy of this pointer is about to become a freed address. Clear
         * it here, while the registry still knows which line state that is, so a
         * queued Payload/Est/Resume task cannot dereference it afterwards. This
         * is safe under the core lock for the same reason every other pcb access
         * is: the line state outlives the worker message that reaches it, and the
         * stopping gate keeps anything from re-registering behind us.
         */
        if (entry->lstate != NULL)
        {
            entry->lstate->tcp_pcb         = NULL;
            entry->lstate->flow_registered = false;
            entry->lstate->generation      = 0;
            entry->lstate                  = NULL;
        }

        if (entry->pcb == NULL)
        {
            continue;
        }

        if (entry->protocol == IP_PROTO_TCP)
        {
            struct tcp_pcb *pcb = entry->pcb;

            tcp_arg(pcb, NULL);
            tcp_recv(pcb, NULL);
            tcp_sent(pcb, NULL);
            tcp_poll(pcb, NULL, 0);
            tcp_err(pcb, NULL);
            pcb->connected = NULL;

            /*
             * Aborted, not closed. Stop is terminal: the stopping gate is already
             * published, so this node's netif output refuses the FIN, and there is
             * no packet side left to complete a graceful exchange over. A
             * successful tcp_close() would still have left an established pcb
             * sitting in FIN_WAIT on lwIP's process-global active list - outliving
             * the netif this loop's caller is about to remove, and able to observe
             * whatever future interface inherits that one-byte netif index.
             */
            tcp_abort(pcb);
        }
        else
        {
            struct udp_pcb *pcb = entry->pcb;

            udp_recv(pcb, NULL, NULL);
            udp_remove(pcb);
        }

        entry->pcb = NULL;
    }

    ctp_flow_map_t_clear(&ts->flows);
    ts->tomb_head  = 0;
    ts->tomb_count = 0;
    rwlockWriteUnlock(&ts->flows_lock);
}
