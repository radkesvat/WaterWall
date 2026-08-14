#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Active-source ownership for StreamToPackets.
 *
 * One concrete source IP owns the whole tunnel instance at a time. Any number of
 * validated stream lines from that IP may be active together, and return packets
 * are spread across them by per-flow rendezvous hashing. A validated line from a
 * different IP takes ownership and closes every old-source line.
 *
 * Two pieces of state express that:
 *
 *   - the registry, a doubly linked list of heap nodes protected by lines_lock.
 *     Nodes are owned by tunnel state, never by a line, so a takeover running on
 *     one worker never writes another worker's line state;
 *   - published_generation, the release-published epoch token. Publishing it is
 *     the linearization point of a takeover: work that already entered its final
 *     callback may finish, queued work from the old epoch may not start.
 *
 * No inter-tunnel callback ever runs while lines_lock is held.
 */

static uint64_t streamtopacketsMix64(uint64_t value)
{
    value ^= value >> 30U;
    value *= UINT64_C(0xBF58476D1CE4E5B9);
    value ^= value >> 27U;
    value *= UINT64_C(0x94D049BB133111EB);
    value ^= value >> 31U;
    return value;
}

/*
 * Rendezvous ("highest random weight") score of one flow against one line.
 *
 * The identity is line_id, which is unique for the lifetime of the tunnel
 * instance. Pointers, WIDs, list positions, ports and queue depths are all
 * deliberately excluded: they either repeat after a reuse or make the winner
 * depend on something other than the flow.
 */
uint64_t streamtopacketsRendezvousScore(uint64_t flow_hash, uint64_t line_id)
{
    return streamtopacketsMix64(flow_hash ^ streamtopacketsMix64(line_id));
}

static void streamtopacketsSourceKeyFromLine(line_t *l, streamtopackets_source_key_t *out)
{
    address_context_t *source_context = lineGetSourceAddressContext(l);

    memoryZero(out, sizeof(*out));

    if (addresscontextIsIp(source_context))
    {
        out->identified = true;
        out->ip         = source_context->ip_address;
        return;
    }

    /*
     * No concrete peer address, which is normal for a directly composed
     * in-process bridge. Every such line shares one anonymous identity, so those
     * compositions keep working - at the cost of not being able to tell two
     * anonymous peers apart.
     */
    LOGD("StreamToPackets: line has no concrete source IP, using the shared anonymous source identity");
}

// ipAddrCmp compares the address family too, so two families never alias.
static bool streamtopacketsSourceKeyEquals(const streamtopackets_source_key_t *a, const streamtopackets_source_key_t *b)
{
    if (a->identified != b->identified)
    {
        return false;
    }

    if (! a->identified)
    {
        return true;
    }

    return ipAddrCmp(&a->ip, &b->ip) != 0;
}

// Allocates a non-zero token; zero is reserved for "none".
static uint64_t streamtopacketsNextToken(uint64_t *counter)
{
    uint64_t value = *counter + 1U;

    if (UNLIKELY(value == 0))
    {
        value = 1;
    }

    *counter = value;
    return value;
}

static streamtopackets_line_entry_t *streamtopacketsFindEntryLocked(streamtopackets_tstate_t *ts, const line_t *l,
                                                                    uint64_t line_id)
{
    if (line_id == 0)
    {
        return NULL;
    }

    for (streamtopackets_line_entry_t *entry = ts->lines_head; entry != NULL; entry = entry->next)
    {
        if (entry->line == l && entry->line_id == line_id)
        {
            return entry;
        }
    }

    return NULL;
}

static void streamtopacketsUnlinkEntryLocked(streamtopackets_tstate_t *ts, streamtopackets_line_entry_t *entry)
{
    if (entry->prev != NULL)
    {
        entry->prev->next = entry->next;
    }
    else
    {
        ts->lines_head = entry->next;
    }

    if (entry->next != NULL)
    {
        entry->next->prev = entry->prev;
    }

    entry->prev = NULL;
    entry->next = NULL;
}

static bool streamtopacketsHasActiveEntryLocked(const streamtopackets_tstate_t *ts)
{
    for (const streamtopackets_line_entry_t *entry = ts->lines_head; entry != NULL; entry = entry->next)
    {
        if (entry->status == kStreamToPacketsLineActive && entry->source_generation == ts->active_generation)
        {
            return true;
        }
    }

    return false;
}

/*
 * The release store of an ownership change, and always its final state mutation:
 * the registry, the promoted entry and the owner-worker local state are all
 * written first, so a reader that observes the new token also observes the epoch
 * it belongs to.
 */
static void streamtopacketsPublishGenerationLocked(streamtopackets_tstate_t *ts)
{
    atomicStoreU64Explicit(&ts->published_generation, ts->active_generation, memory_order_release);
}

static void streamtopacketsClearOwnerLocked(streamtopackets_tstate_t *ts)
{
    memoryZero(&ts->active_source, sizeof(ts->active_source));
    ts->active_source_set = false;
    ts->active_generation = 0;
    streamtopacketsPublishGenerationLocked(ts);
}

uint64_t streamtopacketsPublishedGeneration(streamtopackets_tstate_t *ts)
{
    return atomicLoadU64Explicit(&ts->published_generation, memory_order_acquire);
}

bool streamtopacketsOwnershipInitialize(streamtopackets_tstate_t *ts)
{
    if (UNLIKELY(! rwlockTryInit(&ts->lines_lock)))
    {
        return false;
    }

    ts->lines_head        = NULL;
    ts->active_source_set = false;
    ts->stopping          = false;
    ts->active_generation = 0;
    ts->next_line_id      = 0;
    ts->next_generation   = 0;
    memoryZero(&ts->active_source, sizeof(ts->active_source));
    atomicStoreU64Explicit(&ts->published_generation, 0, memory_order_release);
    return true;
}

void streamtopacketsOwnershipStop(tunnel_t *t)
{
    streamtopackets_tstate_t *ts = tunnelGetState(t);

    rwlockWriteLock(&ts->lines_lock);
    ts->stopping = true;
    rwlockWriteUnlock(&ts->lines_lock);
}

/*
 * Releases whatever the registry still holds. Called from tunnel destruction,
 * after the workers are quiesced, so this only detaches and frees nodes: the
 * lines themselves are borrowed and belong to their own owners.
 */
void streamtopacketsOwnershipDestroy(tunnel_t *t)
{
    streamtopackets_tstate_t     *ts        = tunnelGetState(t);
    streamtopackets_line_entry_t *remaining = NULL;

    rwlockWriteLock(&ts->lines_lock);
    remaining      = ts->lines_head;
    ts->lines_head = NULL;
    streamtopacketsClearOwnerLocked(ts);
    rwlockWriteUnlock(&ts->lines_lock);

    while (remaining != NULL)
    {
        streamtopackets_line_entry_t *node = remaining;
        remaining                          = node->next;

        // Expected during shutdown: the peers' lines are still open and their own
        // owners tear them down. Only this node's registry storage is released.
        LOGD("StreamToPackets: releasing the registry entry of stream line %p during tunnel destruction",
             (void *) node->line);
        memoryFree(node);
    }

    rwlockDestroy(&ts->lines_lock);
}

/*
 * Publishes one candidate entry for a freshly initialized stream line. A
 * candidate is tracked but never selectable, so registration alone can neither
 * change the active source nor carry return traffic.
 */
bool streamtopacketsRegisterCandidateLine(tunnel_t *t, line_t *l)
{
    streamtopackets_tstate_t     *ts    = tunnelGetState(t);
    streamtopackets_lstate_t     *ls    = lineGetState(l, t);
    streamtopackets_line_entry_t *entry = memoryAllocate(sizeof(*entry));

    if (UNLIKELY(entry == NULL))
    {
        LOGE("StreamToPackets: failed to allocate a line registry entry");
        return false;
    }

    streamtopackets_source_key_t source;
    streamtopacketsSourceKeyFromLine(l, &source);

    rwlockWriteLock(&ts->lines_lock);

    if (UNLIKELY(ts->stopping))
    {
        rwlockWriteUnlock(&ts->lines_lock);
        memoryFree(entry);
        LOGD("StreamToPackets: refusing to track a new stream line while stopping");
        return false;
    }

    *entry = (streamtopackets_line_entry_t) {.prev              = NULL,
                                             .next              = ts->lines_head,
                                             .line              = l,
                                             .source            = source,
                                             .line_id           = streamtopacketsNextToken(&ts->next_line_id),
                                             .source_generation = 0,
                                             .wid               = lineGetWID(l),
                                             .status            = kStreamToPacketsLineCandidate,
                                             .paused            = false};

    if (ts->lines_head != NULL)
    {
        ts->lines_head->prev = entry;
    }
    ts->lines_head = entry;

    // This line's state belongs to this worker, so it is safe to publish here.
    ls->line_id           = entry->line_id;
    ls->source_generation = 0;
    ls->tracked           = true;
    ls->active            = false;
    ls->write_paused      = false;

    rwlockWriteUnlock(&ts->lines_lock);
    return true;
}

/*
 * Collects every tracked line whose source differs from @p source, detaching its
 * registry node and taking one temporary reference per line. The caller queues a
 * close task per node after releasing the registry lock, and that task (or its
 * cleanup) releases the reference.
 */
static streamtopackets_line_entry_t *streamtopacketsDetachForeignSourceLocked(
    streamtopackets_tstate_t *ts, const streamtopackets_source_key_t *source)
{
    streamtopackets_line_entry_t *evicted = NULL;
    streamtopackets_line_entry_t *entry   = ts->lines_head;

    while (entry != NULL)
    {
        streamtopackets_line_entry_t *following = entry->next;

        if (! streamtopacketsSourceKeyEquals(&entry->source, source))
        {
            streamtopacketsUnlinkEntryLocked(ts, entry);

            /*
             * The line is still alive here: a line only leaves the registry
             * through its own worker's Finish handler, and that handler takes
             * this same write lock before its owner may destroy the line.
             */
            lineLock(entry->line);

            entry->next = evicted;
            evicted     = entry;
        }

        entry = following;
    }

    return evicted;
}

// Releases an evicted line's local state and asks its owner to close it. Must
// run on that line's own worker, holding a reference to it.
static void streamtopacketsCloseEvictedLineNow(tunnel_t *t, line_t *l)
{
    assert(lineIsOnCurrentEventWorker(l));

    streamtopackets_lstate_t *ls = lineIsAlive(l) ? lineGetState(l, t) : NULL;

    /*
     * A natural Finish for this line may already have run on this same worker
     * between the takeover and this task. It unregisters and releases everything
     * this task would, so there is nothing left to close and no second Finish to
     * send toward the previous side.
     */
    if (ls == NULL || ! ls->tracked)
    {
        return;
    }

    ls->tracked           = false;
    ls->active            = false;
    ls->write_paused      = false;
    ls->line_id           = 0;
    ls->source_generation = 0;

    if (ls->read_stream.pool != NULL)
    {
        streamtopacketsLinestateDestroy(ls);
    }

    // The line is borrowed: ask its owner to close it, and never destroy it
    // here. Nothing is sent toward the packet side.
    tunnelPrevDownStreamFinish(t, l);
}

static void streamtopacketsCloseEvictedLineOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    tunnel_t *t = arg1;
    line_t   *l = arg2;
    discard   arg3;

    assert(worker != NULL);
    assert(worker->wid == lineGetWID(l));
    discard worker;

    streamtopacketsCloseEvictedLineNow(t, l);
    lineUnlock(l);
}

static void streamtopacketsCleanupEvictedLine(void *arg1, void *arg2, void *arg3)
{
    discard arg1;
    discard arg3;

    line_t *l = arg2;

    lineUnlock(l);
}

/*
 * "Every old-source line is closed" is an invariant, so a rejected close is not
 * something to discard silently. The caller keeps its own reference across the
 * post so the line is still safe to touch after the message's own reference has
 * been released by the cleanup callback.
 */
static void streamtopacketsRecoverFailedEvictionClose(tunnel_t *t, line_t *l, wid_t wid)
{
    if (isApplicationTerminating())
    {
        // Shutdown drops queued work by design, and every line is being torn down
        // by its own owner anyway.
        LOGD("StreamToPackets: evicted stream line %p was not closed because the program is terminating", (void *) l);
        return;
    }

    if (lineIsOnCurrentEventWorker(l))
    {
        // The takeover is running on this line's own worker, so the close this
        // could not queue can simply be performed here instead.
        LOGW("StreamToPackets: could not queue the close of evicted stream line %p; closing it on this worker instead",
             (void *) l);
        streamtopacketsCloseEvictedLineNow(t, l);
        return;
    }

    /*
     * Only that line's own worker may touch its state, and the single way to
     * reach it just failed for a reason that is not shutdown: an exhausted
     * message pool, or a loop that will not accept a wakeup. Retrying would use
     * the same queue and hit the same failure, and there is no second channel.
     *
     * Leaving the line open would break "every previous-source line is closed":
     * the connection and its parser would live on for as long as the peer holds
     * them, and repeated failures would accumulate them. Fail closed instead.
     */
    LOGF("StreamToPackets: could not queue the close of evicted stream line %p on worker %u; an old-source line "
         "cannot be left open, requesting an orderly shutdown",
         (void *) l,
         (unsigned int) wid);

    if (! requestProgramShutdown(1))
    {
        // Worker 0 refused the handoff, so no orderly teardown will run.
        abortProgramNow(1);
    }
}

static void streamtopacketsQueueEvictedCloses(tunnel_t *t, streamtopackets_line_entry_t *evicted)
{
    while (evicted != NULL)
    {
        streamtopackets_line_entry_t *node = evicted;
        line_t                       *l    = node->line;
        const wid_t                   wid  = node->wid;

        evicted = node->next;
        memoryFree(node);

        LOGD("StreamToPackets: closing evicted stream line %p on worker %u", (void *) l, (unsigned int) wid);

        // Held across the post so the recovery below still has a live line after
        // a rejected message has already run its cleanup.
        lineLock(l);

        if (UNLIKELY(! sendWorkerMessageForceQueueWithCleanup(
                wid,
                (WorkerMessageCallback) streamtopacketsCloseEvictedLineOnWorker,
                streamtopacketsCleanupEvictedLine,
                t,
                l,
                NULL)))
        {
            streamtopacketsRecoverFailedEvictionClose(t, l, wid);
        }

        lineUnlock(l);
    }
}

static void streamtopacketsActivateEntryLocked(streamtopackets_tstate_t *ts, streamtopackets_line_entry_t *entry,
                                               streamtopackets_lstate_t *ls)
{
    entry->status            = kStreamToPacketsLineActive;
    entry->source_generation = ts->active_generation;

    ls->active            = true;
    ls->source_generation = ts->active_generation;
}

// Whether an already-active entry still belongs to the current source epoch.
static bool streamtopacketsEntryStillOwnsLocked(const streamtopackets_tstate_t     *ts,
                                                const streamtopackets_line_entry_t *entry)
{
    return entry != NULL && entry->status == kStreamToPacketsLineActive && ts->active_source_set &&
           ts->active_generation != 0 && entry->source_generation == ts->active_generation &&
           streamtopacketsSourceKeyEquals(&entry->source, &ts->active_source);
}

/*
 * The single authorization point for traffic that proves a peer speaks the
 * protocol: a complete, validated IPv4 packet or a valid sensitive-mode ping.
 *
 * Returns the current non-zero source generation when this line may proceed, and
 * zero otherwise. Every normal packet goes through here, not only the first one
 * on a candidate: that is what stops a line whose entry was detached during a
 * takeover from injecting traffic while its close task is still queued.
 *
 * Once onStop has run, promotion is refused entirely; active lines may still
 * drain.
 *
 * Runs on @p l's own worker.
 */
uint64_t streamtopacketsAuthorizeLine(tunnel_t *t, line_t *l)
{
    streamtopackets_tstate_t     *ts      = tunnelGetState(t);
    streamtopackets_lstate_t     *ls      = lineGetState(l, t);
    streamtopackets_line_entry_t *evicted = NULL;
    uint64_t                      generation;

    if (! ls->tracked)
    {
        return 0;
    }

    /*
     * Steady state: an already-active line mutates nothing, so every worker can
     * authorize its packets under a shared lock instead of serializing the whole
     * instance on one exclusive lock per decoded packet. Only promotion and
     * takeover, which really do mutate the registry, take the write lock below.
     */
    if (ls->active)
    {
        rwlockReadLock(&ts->lines_lock);

        streamtopackets_line_entry_t *active_entry = streamtopacketsFindEntryLocked(ts, l, ls->line_id);

        // A detached or superseded entry means this line lost ownership, and an
        // evicted line may never reclaim it.
        generation = streamtopacketsEntryStillOwnsLocked(ts, active_entry) ? ts->active_generation : 0;

        rwlockReadUnlock(&ts->lines_lock);
        return generation;
    }

    rwlockWriteLock(&ts->lines_lock);

    streamtopackets_line_entry_t *entry = streamtopacketsFindEntryLocked(ts, l, ls->line_id);

    if (entry == NULL)
    {
        // Detached by a takeover, so this line lost ownership and may never
        // reclaim it. Its close task is already queued.
        rwlockWriteUnlock(&ts->lines_lock);
        return 0;
    }

    if (entry->status == kStreamToPacketsLineActive)
    {
        generation = streamtopacketsEntryStillOwnsLocked(ts, entry) ? ts->active_generation : 0;
        rwlockWriteUnlock(&ts->lines_lock);
        return generation;
    }

    if (UNLIKELY(ts->stopping))
    {
        /*
         * onStop has begun tearing the instance down. An already-active line may
         * keep draining through the branch above, but a candidate must not become
         * an owner now: that would publish a new epoch and queue eviction work
         * onto workers that are already shutting down.
         */
        rwlockWriteUnlock(&ts->lines_lock);
        LOGD("StreamToPackets: refusing to promote a stream line while stopping");
        return 0;
    }

    if (! ts->active_source_set)
    {
        // No owner: this validated candidate establishes a fresh epoch.
        ts->active_source     = entry->source;
        ts->active_source_set = true;
        ts->active_generation = streamtopacketsNextToken(&ts->next_generation);
        streamtopacketsActivateEntryLocked(ts, entry, ls);
        streamtopacketsPublishGenerationLocked(ts);

        generation = ts->active_generation;
        rwlockWriteUnlock(&ts->lines_lock);

        LOGD("StreamToPackets: stream line %p established source generation %llu",
             (void *) l,
             (unsigned long long) generation);
        return generation;
    }

    if (streamtopacketsSourceKeyEquals(&entry->source, &ts->active_source))
    {
        // The normal multi-line join: same source, same epoch, nothing evicted.
        streamtopacketsActivateEntryLocked(ts, entry, ls);

        generation = ts->active_generation;
        rwlockWriteUnlock(&ts->lines_lock);
        return generation;
    }

    /*
     * Validated newest source wins. Detach every old-source line (including idle
     * candidates), publish the new generation as the takeover linearization
     * point, and only then - outside the lock - queue their closes.
     */
    evicted               = streamtopacketsDetachForeignSourceLocked(ts, &entry->source);
    ts->active_source     = entry->source;
    ts->active_source_set = true;
    ts->active_generation = streamtopacketsNextToken(&ts->next_generation);
    streamtopacketsActivateEntryLocked(ts, entry, ls);
    streamtopacketsPublishGenerationLocked(ts);

    generation = ts->active_generation;
    rwlockWriteUnlock(&ts->lines_lock);

    LOGI("StreamToPackets: a validated new source took ownership, generation %llu", (unsigned long long) generation);
    streamtopacketsQueueEvictedCloses(t, evicted);

    return generation;
}

/*
 * Natural upstream Finish: the previous side is the sender, so nothing is sent
 * back toward it. Runs on @p l's own worker.
 */
void streamtopacketsUnregisterLine(tunnel_t *t, line_t *l)
{
    streamtopackets_tstate_t *ts = tunnelGetState(t);
    streamtopackets_lstate_t *ls = lineGetState(l, t);

    if (! ls->tracked)
    {
        return;
    }

    rwlockWriteLock(&ts->lines_lock);

    streamtopackets_line_entry_t *entry = streamtopacketsFindEntryLocked(ts, l, ls->line_id);

    if (entry != NULL)
    {
        streamtopacketsUnlinkEntryLocked(ts, entry);
        memoryFree(entry);
    }

    if (ts->active_source_set && ! streamtopacketsHasActiveEntryLocked(ts))
    {
        // The last active line of this epoch is gone. Publishing zero makes every
        // queued write stale rather than letting it reach an ownerless pool.
        LOGD("StreamToPackets: the final active line of generation %llu finished, clearing the active source",
             (unsigned long long) ts->active_generation);
        streamtopacketsClearOwnerLocked(ts);
    }

    rwlockWriteUnlock(&ts->lines_lock);

    ls->tracked           = false;
    ls->active            = false;
    ls->write_paused      = false;
    ls->line_id           = 0;
    ls->source_generation = 0;
}

/*
 * Pause is per stream line, never global.
 *
 * The restrictive view is always installed first and the permissive one last, so
 * the two views never disagree in the direction that would deliver to a paused
 * line or drop a packet on a resumed one:
 *
 *   - on pause the owner-worker local flag goes up first, so a write that was
 *     already selected against the older registry value still fails its local
 *     check; the registry flag then stops new selections;
 *   - on resume the local flag comes down first, so by the time the registry
 *     makes the line selectable again its own worker already accepts writes.
 *
 * Both flags are only ever written by this line's own worker, so no other worker
 * can observe them in the opposite order.
 */
void streamtopacketsSetLinePaused(tunnel_t *t, line_t *l, bool paused)
{
    streamtopackets_tstate_t *ts = tunnelGetState(t);
    streamtopackets_lstate_t *ls = lineGetState(l, t);

    if (! ls->tracked)
    {
        return;
    }

    ls->write_paused = paused;

    rwlockWriteLock(&ts->lines_lock);

    streamtopackets_line_entry_t *entry = streamtopacketsFindEntryLocked(ts, l, ls->line_id);

    if (entry != NULL)
    {
        entry->paused = paused;
    }

    rwlockWriteUnlock(&ts->lines_lock);
}

/*
 * Rendezvous-selects one return line for @p flow_hash among the active, unpaused
 * lines of the current source generation.
 *
 * On success the caller owns one temporary reference on out->line and must
 * release it exactly once. The winner is decided by score alone, with line_id as
 * a deterministic tie-break, so it never depends on list order.
 */
bool streamtopacketsSelectReturnLine(tunnel_t *t, uint64_t flow_hash, streamtopackets_selected_line_t *out)
{
    streamtopackets_tstate_t     *ts         = tunnelGetState(t);
    streamtopackets_line_entry_t *best       = NULL;
    uint64_t                      best_score = 0;

    rwlockReadLock(&ts->lines_lock);

    if (! ts->active_source_set || ts->active_generation == 0)
    {
        rwlockReadUnlock(&ts->lines_lock);
        return false;
    }

    for (streamtopackets_line_entry_t *entry = ts->lines_head; entry != NULL; entry = entry->next)
    {
        if (entry->status != kStreamToPacketsLineActive || entry->paused ||
            entry->source_generation != ts->active_generation ||
            ! streamtopacketsSourceKeyEquals(&entry->source, &ts->active_source))
        {
            continue;
        }

        const uint64_t score = streamtopacketsRendezvousScore(flow_hash, entry->line_id);

        if (best == NULL || score > best_score || (score == best_score && entry->line_id > best->line_id))
        {
            best       = entry;
            best_score = score;
        }
    }

    if (best == NULL)
    {
        rwlockReadUnlock(&ts->lines_lock);
        return false;
    }

    // Taken before the registry protection is released, so the winner cannot die
    // between selection and delivery.
    lineLock(best->line);

    *out = (streamtopackets_selected_line_t) {
        .line = best->line, .line_id = best->line_id, .generation = best->source_generation, .wid = best->wid};

    rwlockReadUnlock(&ts->lines_lock);
    return true;
}

/*
 * Cross-worker return write.
 *
 * lineScheduleTaskWithBuf() cannot carry the generation and line ID this needs,
 * so the message is its own allocation. It owns the buffer and the caller's
 * temporary line reference, and releases both on every path.
 */
typedef struct streamtopackets_line_write_msg_s
{
    tunnel_t *tunnel;
    line_t   *line;
    sbuf_t   *buf;
    uint64_t  line_id;
    uint64_t  generation;
} streamtopackets_line_write_msg_t;

static void streamtopacketsWriteSelectedLineOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    streamtopackets_line_write_msg_t *msg = arg1;
    discard                           arg2;
    discard                           arg3;

    assert(worker != NULL);
    assert(worker->wid == lineGetWID(msg->line));
    discard worker;

    // The payload callback may close this line re-entrantly, so nothing below
    // reads line or registry state again.
    streamtopacketsDeliverSelectedWrite(msg->tunnel, msg->line, msg->line_id, msg->generation, msg->buf);

    lineUnlock(msg->line);
    memoryFree(msg);
}

static void streamtopacketsCleanupSelectedWrite(void *arg1, void *arg2, void *arg3)
{
    streamtopackets_line_write_msg_t *msg = arg1;
    discard                           arg2;
    discard                           arg3;

    // A pooled buffer may only go back to a pool this thread owns.
    if (lineIsOnCurrentEventWorker(msg->line))
    {
        lineReuseBuffer(msg->line, msg->buf);
    }
    else
    {
        sbufDestroy(msg->buf);
    }

    lineUnlock(msg->line);
    memoryFree(msg);
}

/*
 * Hands one return packet to the selected line's own worker. Takes ownership of
 * @p buf and of the temporary reference streamtopacketsSelectReturnLine() left
 * on the selected line.
 */
void streamtopacketsQueueSelectedWrite(tunnel_t *t, streamtopackets_selected_line_t *selected, sbuf_t *buf)
{
    streamtopackets_line_write_msg_t *msg = memoryAllocate(sizeof(*msg));

    if (UNLIKELY(msg == NULL))
    {
        LOGE("StreamToPackets: failed to allocate a cross-worker return-write message");
        bufferpoolReuseBuffer(getCurrentEventWorkerBufferPool(), buf);
        lineUnlock(selected->line);
        return;
    }

    *msg = (streamtopackets_line_write_msg_t) {.tunnel     = t,
                                               .line       = selected->line,
                                               .buf        = buf,
                                               .line_id    = selected->line_id,
                                               .generation = selected->generation};

    sendWorkerMessageForceQueueBestEffortWithCleanup(selected->wid,
                                                     (WorkerMessageCallback) streamtopacketsWriteSelectedLineOnWorker,
                                                     streamtopacketsCleanupSelectedWrite,
                                                     msg,
                                                     NULL,
                                                     NULL);
}

/*
 * Final validated delivery of one return packet, always on @p l's own worker and
 * always holding a temporary reference to it. Takes ownership of @p buf.
 *
 * The payload callback may close the line re-entrantly, so the caller must not
 * read line or registry state after this returns - only release its reference.
 */
void streamtopacketsDeliverSelectedWrite(tunnel_t *t, line_t *l, uint64_t line_id, uint64_t generation, sbuf_t *buf)
{
    streamtopackets_tstate_t *ts = tunnelGetState(t);

    assert(lineIsOnCurrentEventWorker(l));

    if (! lineIsAlive(l))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (streamtopacketsPublishedGeneration(ts) != generation)
    {
        // A takeover linearized after this write was selected.
        lineReuseBuffer(l, buf);
        return;
    }

    streamtopackets_lstate_t *ls = lineGetState(l, t);

    if (! ls->tracked || ! ls->active || ls->write_paused || ls->line_id != line_id ||
        ls->source_generation != generation)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
