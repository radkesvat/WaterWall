#include "internal.h"

#include "loggers/network_logger.h"

static int authenticationclientCompareEntries(const void *left, const void *right);

static authenticationclient_accounting_entry_t *authenticationclientCatchupEntry(authenticationclient_tstate_t *ts,
                                                                                 uint64_t                       id);

static bool authenticationclientEntryOwed(const authenticationclient_accounting_entry_t *entry);

static user_ud_t authenticationclientOwedTraffic(authenticationclient_tstate_t    *ts,
                                                 const user_accounting_snapshot_t *snapshot);

static bool authenticationclientCreateUsageBatch(tunnel_t *t);

uint64_t authenticationclientCounterDelta(uint64_t current, uint64_t baseline)
{
    return current > baseline ? current - baseline : 0;
}

static int authenticationclientCompareEntries(const void *left, const void *right)
{
    const authenticationclient_accounting_entry_t *a = left, *b = right;
    return (a->id > b->id) - (a->id < b->id);
}

static authenticationclient_accounting_entry_t *authenticationclientCatchupEntry(authenticationclient_tstate_t *ts,
                                                                                 uint64_t                       id)
{
    const authenticationclient_accounting_entry_t key = {.id = id};
    return ts->catchup_entries_count == 0 ? NULL
                                          : bsearch(&key,
                                                    ts->catchup_entries,
                                                    ts->catchup_entries_count,
                                                    sizeof(key),
                                                    authenticationclientCompareEntries);
}

static bool authenticationclientEntryOwed(const authenticationclient_accounting_entry_t *entry)
{
    return entry->delta.u != 0 || entry->delta.d != 0 || entry->first_usage_at_ms != 0;
}

bool authenticationclientHasCatchup(const authenticationclient_tstate_t *ts)
{
    for (size_t i = 0; i < ts->catchup_entries_count; ++i)
        if (authenticationclientEntryOwed(&ts->catchup_entries[i]))
            return true;
    return false;
}

static user_ud_t authenticationclientOwedTraffic(authenticationclient_tstate_t    *ts,
                                                 const user_accounting_snapshot_t *snapshot)
{
    user_stat_t previous = {0};
    user_t     *base     = usersLookupByIdentifier(ts->sync_baseline_users, snapshot->id);
    if (base != NULL)
        userGetStats(base, &previous);
    return (user_ud_t) {.u = authenticationclientCounterDelta(snapshot->traffic.u, previous.traffic.u),
                        .d = authenticationclientCounterDelta(snapshot->traffic.d, previous.traffic.d)};
}

bool authenticationclientCaptureCatchup(tunnel_t *t)
{
    authenticationclient_tstate_t *ts       = tunnelGetState(t);
    user_accounting_snapshot_t    *snapshot = NULL;
    size_t                         count    = 0, bytes;
    rwlockReadLock(&ts->users_lock);
    if (! usersSnapshotAccounting(ts->users, &snapshot, &count) ||
        ! memoryTryComputeArraySize(count, sizeof(*ts->catchup_entries), &bytes))
    {
        rwlockReadUnlock(&ts->users_lock);
        memoryFree(snapshot);
        return false;
    }
    authenticationclient_accounting_entry_t *entries = memoryAllocate(bytes);
    size_t                                   owed    = 0;
    for (size_t i = 0; i < count; ++i)
    {
        const user_accounting_snapshot_t       *current = &snapshot[i];
        authenticationclient_accounting_entry_t entry   = {
              .id                = current->id,
              .delta             = authenticationclientOwedTraffic(ts, current),
              .first_usage_at_ms = current->observation_pending ? current->first_usage_at_ms : 0};
        const authenticationclient_accounting_entry_t *retained = authenticationclientCatchupEntry(ts, current->id);
        if (retained != NULL)
        {
            /* Reconnect must preserve debt hidden by a saturated rebase.
             * Visible A - B overlaps that debt, so merge without adding it twice. */
            entry.delta.u = max(entry.delta.u, retained->delta.u);
            entry.delta.d = max(entry.delta.d, retained->delta.d);
        }
        if (authenticationclientEntryOwed(&entry))
            entries[owed++] = entry;
    }
    rwlockReadUnlock(&ts->users_lock);
    memoryFree(snapshot);
    qsort(entries, owed, sizeof(*entries), authenticationclientCompareEntries);
    memoryFree(ts->catchup_entries);
    ts->catchup_entries        = entries;
    ts->catchup_entries_count  = owed;
    ts->catchup_capture_needed = false;
    return true;
}

static bool authenticationclientCreateUsageBatch(tunnel_t *t)
{
    authenticationclient_tstate_t *ts       = tunnelGetState(t);
    user_accounting_snapshot_t    *snapshot = NULL;
    size_t                         total    = 0;
    rwlockReadLock(&ts->users_lock);
    if (! ts->users_loaded || ! usersSnapshotAccounting(ts->users, &snapshot, &total))
    {
        rwlockReadUnlock(&ts->users_lock);
        return false;
    }
    /* Fixed maximum geometry; ordinary allocation is fatal on heap OOM. */
    authenticationclient_accounting_entry_t *entries =
        memoryAllocate(kAuthenticationClientMaxBatchEntries * sizeof(*entries));
    cJSON     *root = cJSON_CreateObject(), *array = cJSON_CreateArray();
    discard    cJSON_AddStringToObject(root, "epoch", ts->accounting_epoch);
    discard    jsonAddUint64ToObject(root, "sequence", ts->next_batch_sequence);
    discard    cJSON_AddItemToObject(root, "users", array);
    size_t     count        = 0;
    const bool catchup      = authenticationclientHasCatchup(ts);
    bool       more_entries = false;
    for (size_t i = 0; i < total; ++i)
    {
        const user_accounting_snapshot_t              *current = &snapshot[i];
        const authenticationclient_accounting_entry_t *owed    = NULL;
        if (catchup)
        {
            owed = authenticationclientCatchupEntry(ts, current->id);
            if (owed == NULL || ! authenticationclientEntryOwed(owed))
                continue;
        }
        user_ud_t delta = authenticationclientOwedTraffic(ts, current);
        if (owed != NULL)
        {
            /* A saturating aggregate rebase can hide A - B. Relative debt at
             * the cut remains known production until this batch's ACK. */
            delta.u = max(delta.u, owed->delta.u);
            delta.d = max(delta.d, owed->delta.d);
        }
        if (delta.u == 0 && delta.d == 0 && ! current->observation_pending)
            continue;
        /* Rebased/imported bytes are never observations. All local production
         * must pass through accounting with a valid installed clock. */
        assert(current->first_usage_at_ms != 0);
        if (count == kAuthenticationClientMaxBatchEntries)
        {
            more_entries = ! catchup;
            break;
        }
        entries[count++] = (authenticationclient_accounting_entry_t) {.id                = current->id,
                                                                      .totals            = current->traffic,
                                                                      .delta             = delta,
                                                                      .first_usage_at_ms = current->first_usage_at_ms};
        cJSON  *entry    = cJSON_CreateObject();
        discard jsonAddUint64ToObject(entry, "id", current->id);
        discard jsonAddUint64ToObject(entry, "up", delta.u);
        discard jsonAddUint64ToObject(entry, "down", delta.d);
        discard jsonAddUint64ToObject(entry, "first-usage-at-ms", current->first_usage_at_ms);
        discard cJSON_AddItemToArray(array, entry);
    }
    rwlockReadUnlock(&ts->users_lock);
    memoryFree(snapshot);
    if (more_entries)
    {
        mutexLock(&ts->control_mutex);
        ts->push_requested = true;
        mutexUnlock(&ts->control_mutex);
    }
    char *text = count != 0 ? cJSON_PrintUnformatted(root) : NULL;
    cJSON_Delete(root);
    if (text == NULL ||
        stringLength(text) > kAuthenticationClientMaxMessagePayload - kAuthenticationClientRequestHeaderSize)
    {
        cJSON_free(text);
        memoryFree(entries);
        return false;
    }
    /* Publish both immutable owners before any transport callback. */
    ts->pending_entries       = entries;
    ts->pending_entries_count = count;
    ts->pending_batch         = text;
    ts->pending_batch_length  = (uint32_t) stringLength(text);
    return true;
}

bool authenticationclientSendPushUserStats(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    ts->push_requested = true;
    const bool allowed = authenticationclientRequestMayBeSentLocked(ts, kAuthenticationClientRequestTypePushUserStats);
    if (allowed)
        ts->push_requested = false;
    mutexUnlock(&ts->control_mutex);
    if (! allowed)
        return false;
    if (ts->pending_batch == NULL && ! authenticationclientCreateUsageBatch(t))
    {
        authenticationclientScheduleSyncProgress(t);
        return false; /* Empty batch, or refusal: baseline and traffic stay intact. */
    }
    const bool sent = authenticationclientSendRequest(t,
                                                      kAuthenticationClientRequestTypePushUserStats,
                                                      (const uint8_t *) ts->pending_batch,
                                                      ts->pending_batch_length);
    if (! sent)
    {
        mutexLock(&ts->control_mutex);
        ts->push_requested = true;
        mutexUnlock(&ts->control_mutex);
        authenticationclientScheduleSyncProgress(t);
    }
    return sent;
}

bool authenticationclientAcknowledgeUsageBatch(tunnel_t *t, const uint8_t *data, uint32_t length)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (ts->pending_batch == NULL)
        return false;
    cJSON        *json     = cJSON_ParseWithLength((const char *) data, length);
    const cJSON  *epoch    = cJSON_GetObjectItemCaseSensitive(json, "epoch");
    const cJSON  *digest   = cJSON_GetObjectItemCaseSensitive(json, "digest");
    const cJSON  *pull     = cJSON_GetObjectItemCaseSensitive(json, "needs-pull");
    uint64_t      sequence = 0;
    uint8_t       decoded[32];
    sha256_hash_t expected = {0};
    const bool    valid =
        cJSON_IsObject(json) && cJSON_IsString(epoch) && epoch->valuestring != NULL &&
        stringCompare(epoch->valuestring, ts->accounting_epoch) == 0 &&
        getUint64FromJson(&sequence, cJSON_GetObjectItemCaseSensitive(json, "sequence")) &&
        sequence == ts->next_batch_sequence && cJSON_IsString(digest) && digest->valuestring != NULL &&
        stringLength(digest->valuestring) == 64 &&
        asciiHexDecodeBytes((const uint8_t *) digest->valuestring, 64, decoded, sizeof(decoded)) &&
        wCryptoSHA256(&expected, (const uint8_t *) ts->pending_batch, ts->pending_batch_length) == kWCryptoOk &&
        memoryEqual(decoded, expected.bytes, sizeof(decoded)) && cJSON_IsTrue(pull);
    cJSON_Delete(json);
    if (! valid)
        return false;
    rwlockWriteLock(&ts->users_lock);
    for (size_t i = 0; i < ts->pending_entries_count; ++i)
    {
        const authenticationclient_accounting_entry_t *sent = &ts->pending_entries[i];
        user_t *base = usersLookupByIdentifier(ts->sync_baseline_users, sent->id);
        assert(base != NULL); /* Pull replacement is forbidden while unresolved. */
        rwlockWriteLock(&base->stats_lock);
        base->stats.traffic = sent->totals;
        rwlockWriteUnlock(&base->stats_lock);
        user_t *active = usersLookupByIdentifier(ts->users, sent->id);
        if (active != NULL)
            userAcknowledgeObservation(active, sent->first_usage_at_ms);
        authenticationclient_accounting_entry_t *owed = authenticationclientCatchupEntry(ts, sent->id);
        if (owed != NULL)
        {
            owed->delta.u = authenticationclientCounterDelta(owed->delta.u, sent->delta.u);
            owed->delta.d = authenticationclientCounterDelta(owed->delta.d, sent->delta.d);
            if (owed->first_usage_at_ms == sent->first_usage_at_ms)
                owed->first_usage_at_ms = 0;
        }
    }
    rwlockWriteUnlock(&ts->users_lock);
    memoryFree(ts->pending_entries);
    ts->pending_entries       = NULL;
    ts->pending_entries_count = 0;
    if (! authenticationclientHasCatchup(ts))
    {
        memoryFree(ts->catchup_entries);
        ts->catchup_entries       = NULL;
        ts->catchup_entries_count = 0;
    }
    cJSON_free(ts->pending_batch);
    ts->pending_batch        = NULL;
    ts->pending_batch_length = 0;
    mutexLock(&ts->control_mutex);
    ts->last_ack_sequence = sequence;
    memoryCopy(ts->last_ack_digest, expected.bytes, sizeof(ts->last_ack_digest));
    if (ts->next_batch_sequence == UINT64_MAX)
        ts->continuity_error = true;
    else
        ++ts->next_batch_sequence;
    ts->pull_requested            = true;
    ts->pull_required             = true;
    ts->stats_push_refused        = false;
    ts->stats_retry_not_before_ms = 0;
    ts->last_ack_success_ms       = authenticationclientLocalTimeMS();
    ts->last_ack_success_valid    = true;
    const bool exhausted          = ts->continuity_error;
    mutexUnlock(&ts->control_mutex);
    if (exhausted)
        authenticationclientRecordFailure(
            t, kAuthenticationClientFailureContinuity, kAuthenticationClientRequestTypePushUserStats);
    return true;
}
