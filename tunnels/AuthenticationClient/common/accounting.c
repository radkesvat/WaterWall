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

bool authenticationclientIdDetachedLocked(authenticationclient_tstate_t *ts, uint64_t id)
{
    const authenticationclient_accounting_entry_t *entry = authenticationclientCatchupEntry(ts, id);
    return entry != NULL && entry->detached;
}

bool authenticationclientHasCatchup(const authenticationclient_tstate_t *ts)
{
    for (size_t i = 0; i < ts->catchup_entries_count; ++i)
        if (! ts->catchup_entries[i].detached && authenticationclientEntryOwed(&ts->catchup_entries[i]))
            return true;
    return false;
}

static uint64_t earliestObservation(uint64_t a, uint64_t b)
{
    return a == 0 ? b : b == 0 ? a : min(a, b);
}

static uint64_t advanceRetainedAge(uint64_t age, uint64_t elapsed)
{
    return elapsed > UINT64_MAX - age ? UINT64_MAX : age + elapsed;
}

static void mergeObservation(authenticationclient_accounting_entry_t *entry, const user_accounting_snapshot_t *current,
                             bool retain_report)
{
    const uint64_t report = retain_report || current->observation_pending ? current->first_usage_at_ms : 0;
    if (report != 0)
    {
        if (entry->first_usage_at_ms == 0 || current->first_local_at_ms < entry->first_local_at_ms)
            entry->first_local_at_ms = current->first_local_at_ms;
        entry->first_usage_at_ms = earliestObservation(entry->first_usage_at_ms, report);
    }
    const uint64_t sample = max(entry->age_sample_ms, current->age_sample_ms);
    const uint64_t retained =
        entry->age_valid ? advanceRetainedAge(entry->first_usage_age_ms, sample - entry->age_sample_ms) : 0;
    const uint64_t observed =
        current->age_valid ? advanceRetainedAge(current->first_usage_age_ms, sample - current->age_sample_ms) : 0;
    entry->first_usage_age_ms = max(retained, observed);
    entry->age_sample_ms      = sample;
    entry->age_valid |= current->age_valid;
}

static bool debtPreparationFits(const authenticationclient_tstate_t *ts, size_t active, bool snapshot,
                                size_t *candidate_bytes)
{
    size_t old_bytes, snapshot_bytes = 0;
    if (active > SIZE_MAX - ts->catchup_entries_count ||
        ! memoryTryComputeArraySize(ts->catchup_entries_count, sizeof(*ts->catchup_entries), &old_bytes) ||
        ! memoryTryComputeArraySize(
            active + ts->catchup_entries_count, sizeof(*ts->catchup_entries), candidate_bytes) ||
        (snapshot && ! memoryTryComputeArraySize(active, sizeof(user_accounting_snapshot_t), &snapshot_bytes)) ||
        old_bytes > SIZE_MAX - snapshot_bytes || *candidate_bytes > (SIZE_MAX - old_bytes - snapshot_bytes) / 2)
        return false;
    /* Shrinking may allocate a replacement before freeing the candidate. */
    return old_bytes + snapshot_bytes + 2 * *candidate_bytes <= ts->sync_max_bytes;
}

void authenticationclientInstallDebt(authenticationclient_tstate_t           *ts,
                                     authenticationclient_accounting_entry_t *entries, size_t count)
{
    memoryFree(ts->catchup_entries);
    ts->catchup_entries       = entries;
    ts->catchup_entries_count = count;
    ts->orphan_debt_count     = 0;
    for (size_t i = 0; i < count; ++i)
        ts->orphan_debt_count += entries[i].detached;
}

/* users_lock pins the old active table. Prepare all retained obligations before
 * publication; failure leaves its table and debt ledger unchanged. */
bool authenticationclientPrepareTableDebt(authenticationclient_tstate_t *ts, users_t *dest,
                                          authenticationclient_accounting_entry_t **entries_out, size_t *count_out)
{
    const size_t active = usersCount(ts->users);
    size_t       bytes;
    if (! debtPreparationFits(ts, active, false, &bytes))
        return false;
    authenticationclient_accounting_entry_t *entries = memoryAllocate(bytes);
    size_t                                   count   = ts->catchup_entries_count;
    if (count != 0)
        memoryCopy(entries, ts->catchup_entries, count * sizeof(*entries));
    for (size_t i = 0; i < active; ++i)
    {
        user_accounting_snapshot_t current;
        userGetAccountingSnapshot(usersGetAt(ts->users, i), &current);
        const user_ud_t delta = authenticationclientOwedTraffic(ts, &current);
        if (usersLookupByIdentifier(dest, current.id) != NULL)
        {
            if (usersAddTrafficByIdentifier(dest, current.id, delta.u, delta.d) != kUsersUpdateResultOk)
                goto failed;
            continue;
        }
        authenticationclient_accounting_entry_t *previous = authenticationclientCatchupEntry(ts, current.id);
        if (delta.u == 0 && delta.d == 0 && ! current.observation_pending &&
            (previous == NULL || ! authenticationclientEntryOwed(previous)))
            continue;
        authenticationclient_accounting_entry_t *entry =
            previous == NULL ? &entries[count++] : &entries[(size_t) (previous - ts->catchup_entries)];
        if (previous == NULL)
            *entry = (authenticationclient_accounting_entry_t) {.id = current.id};
        entry->delta.u = max(entry->delta.u, delta.u);
        entry->delta.d = max(entry->delta.d, delta.d);
        mergeObservation(entry, &current, true);
    }
    for (size_t i = 0; i < count; ++i)
    {
        authenticationclient_accounting_entry_t *entry   = &entries[i];
        const bool                               present = usersLookupByIdentifier(dest, entry->id) != NULL;
        if (entry->detached && present)
        {
            user_ud_t visible = {0};
            user_t   *old     = usersLookupByIdentifier(ts->users, entry->id);
            if (old != NULL)
            {
                user_accounting_snapshot_t current;
                userGetAccountingSnapshot(old, &current);
                visible = authenticationclientOwedTraffic(ts, &current);
            }
            if (usersAddTrafficByIdentifier(dest,
                                            entry->id,
                                            authenticationclientCounterDelta(entry->delta.u, visible.u),
                                            authenticationclientCounterDelta(entry->delta.d, visible.d)) !=
                kUsersUpdateResultOk)
                goto failed;
        }
        entry->detached = ! present;
    }
    qsort(entries, count, sizeof(*entries), authenticationclientCompareEntries);
    if (count == 0)
    {
        memoryFree(entries);
        entries = NULL;
    }
    else
        entries = memoryReAllocate(entries, count * sizeof(*entries));
    *entries_out = entries;
    *count_out   = count;
    return true;
failed:
    memoryFree(entries);
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
    authenticationclient_tstate_t *ts  = tunnelGetState(t);
    const uint64_t                 now = authenticationclientLocalTimeMS();
    if (now < ts->catchup_retry_not_before_ms)
        return false;
    user_accounting_snapshot_t *snapshot = NULL;
    size_t                      count    = 0, bytes;
    rwlockWriteLock(&ts->users_lock);
    if (! debtPreparationFits(ts, usersCount(ts->users), true, &bytes))
    {
        rwlockWriteUnlock(&ts->users_lock);
        ts->catchup_retry_not_before_ms = now + min(UINT64_MAX - now, UINT64_C(1000));
        mutexLock(&ts->control_mutex);
        ts->last_failure           = kAuthenticationClientFailureSyncLimit;
        ts->last_failure_operation = kAuthenticationClientRequestTypePushUserStats;
        ts->last_failure_ms        = now;
        mutexUnlock(&ts->control_mutex);
        return false;
    }
    if (! usersSnapshotAccounting(ts->users, &snapshot, &count))
    {
        rwlockWriteUnlock(&ts->users_lock);
        memoryFree(snapshot);
        return false;
    }
    authenticationclient_accounting_entry_t *entries = memoryAllocate(bytes);
    size_t                                   owed    = 0;
    for (size_t i = 0; i < count; ++i)
    {
        const user_accounting_snapshot_t              *current  = &snapshot[i];
        authenticationclient_accounting_entry_t        entry    = {.id    = current->id,
                                                                   .delta = authenticationclientOwedTraffic(ts, current)};
        const authenticationclient_accounting_entry_t *retained = authenticationclientCatchupEntry(ts, current->id);
        if (retained != NULL)
        {
            /* Reconnect must preserve debt hidden by a saturated rebase.
             * Visible A - B overlaps that debt, so merge without adding it twice. */
            entry.delta.u            = max(entry.delta.u, retained->delta.u);
            entry.delta.d            = max(entry.delta.d, retained->delta.d);
            entry.first_usage_at_ms  = retained->first_usage_at_ms;
            entry.first_local_at_ms  = retained->first_local_at_ms;
            entry.first_usage_age_ms = retained->first_usage_age_ms;
            entry.age_sample_ms      = retained->age_sample_ms;
            entry.age_valid          = retained->age_valid;
            entry.detached           = retained->detached;
        }
        mergeObservation(&entry, current, entry.detached);
        if (authenticationclientEntryOwed(&entry))
            entries[owed++] = entry;
    }
    for (size_t i = 0; i < ts->catchup_entries_count; ++i)
        if (usersLookupByIdentifier(ts->users, ts->catchup_entries[i].id) == NULL &&
            authenticationclientEntryOwed(&ts->catchup_entries[i]))
        {
            entries[owed]            = ts->catchup_entries[i];
            entries[owed++].detached = true;
        }
    memoryFree(snapshot);
    qsort(entries, owed, sizeof(*entries), authenticationclientCompareEntries);
    if (owed == 0)
    {
        memoryFree(entries);
        entries = NULL;
    }
    else
        entries = memoryReAllocate(entries, owed * sizeof(*entries));
    authenticationclientInstallDebt(ts, entries, owed);
    rwlockWriteUnlock(&ts->users_lock);
    ts->catchup_capture_needed      = false;
    ts->catchup_retry_not_before_ms = 0;
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
        const authenticationclient_accounting_entry_t *owed    = authenticationclientCatchupEntry(ts, current->id);
        if (owed != NULL && owed->detached)
            continue;
        if (catchup)
        {
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
        const uint64_t observation =
            earliestObservation(current->first_usage_at_ms, owed != NULL ? owed->first_usage_at_ms : 0);
        if (delta.u == 0 && delta.d == 0 && ! current->observation_pending &&
            (owed == NULL || owed->first_usage_at_ms == 0))
            continue;
        /* Rebased/imported bytes are never observations. All local production
         * must pass through accounting with a valid installed clock. */
        assert(observation != 0);
        if (count == kAuthenticationClientMaxBatchEntries)
        {
            more_entries = ! catchup;
            break;
        }
        entries[count++] = (authenticationclient_accounting_entry_t) {
            .id = current->id, .totals = current->traffic, .delta = delta, .first_usage_at_ms = observation};
        cJSON  *entry = cJSON_CreateObject();
        discard jsonAddUint64ToObject(entry, "id", current->id);
        discard jsonAddUint64ToObject(entry, "up", delta.u);
        discard jsonAddUint64ToObject(entry, "down", delta.d);
        discard jsonAddUint64ToObject(entry, "first-usage-at-ms", observation);
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
    /* One flat ACK object, four keys and four scalar values. Validate the whole
     * document before any receipt can settle the retained accounting batch. */
    cJSON        *json     = configLexicalParseBoundedQuiet((const char *) data, length, 1, 9);
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
    memoryFree(ts->pending_entries);
    ts->pending_entries       = NULL;
    ts->pending_entries_count = 0;
    size_t retained           = 0;
    for (size_t i = 0; i < ts->catchup_entries_count; ++i)
        if (authenticationclientEntryOwed(&ts->catchup_entries[i]))
            ts->catchup_entries[retained++] = ts->catchup_entries[i];
    ts->catchup_entries_count = retained;
    ts->orphan_debt_count     = 0;
    for (size_t i = 0; i < retained; ++i)
        ts->orphan_debt_count += ts->catchup_entries[i].detached;
    if (retained == 0)
    {
        memoryFree(ts->catchup_entries);
        ts->catchup_entries       = NULL;
        ts->catchup_entries_count = 0;
    }
    else
        ts->catchup_entries = memoryReAllocate(ts->catchup_entries, retained * sizeof(*ts->catchup_entries));
    rwlockWriteUnlock(&ts->users_lock);
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
    ts->pull_required             = ! ts->pull_deferred;
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

bool authenticationclientRejectMissingBatch(tunnel_t *t, const uint8_t *data, uint32_t length)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (ts->pending_batch == NULL)
        return false;
    cJSON *json =
        configLexicalParseBoundedQuiet((const char *) data, length, 2, kAuthenticationClientMaxBatchEntries + 16);
    static const char *const keys[] = {
        "error", "epoch", "sequence", "digest", "checkpoint-sequence", "checkpoint-digest", "missing-ids"};
    size_t fields = 0;
    if (! cJSON_IsObject(json))
        goto invalid;
    for (const cJSON *field = json->child; field != NULL; field = field->next)
    {
        bool known = false;
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
            known |= strcmp(field->string, keys[i]) == 0;
        if (! known)
            goto invalid;
        ++fields;
    }
    if (fields != sizeof(keys) / sizeof(keys[0]))
        goto invalid;
#define FIELD(key) cJSON_GetObjectItemCaseSensitive(json, key)
    const cJSON *error = FIELD("error"), *epoch = FIELD("epoch"), *digest = FIELD("digest"),
                *checkpoint = FIELD("checkpoint-digest"), *missing = FIELD("missing-ids");
    uint64_t      sequence, previous;
    sha256_hash_t hash;
    char          expected[65] = {0}, prior[65] = {0};
    if (! cJSON_IsString(error) || strcmp(error->valuestring, "usage-accounts-missing") != 0 ||
        ! cJSON_IsString(epoch) || strcmp(epoch->valuestring, ts->accounting_epoch) != 0 ||
        ! cJSON_IsString(FIELD("sequence")) || ! getUint64FromJson(&sequence, FIELD("sequence")) ||
        sequence != ts->next_batch_sequence || ! cJSON_IsString(FIELD("checkpoint-sequence")) ||
        ! getUint64FromJson(&previous, FIELD("checkpoint-sequence")) || previous != ts->last_ack_sequence ||
        sequence == 0 || previous != sequence - 1 || ! cJSON_IsString(digest) || ! cJSON_IsString(checkpoint) ||
        ! cJSON_IsArray(missing) || cJSON_GetArraySize(missing) == 0 ||
        (size_t) cJSON_GetArraySize(missing) > ts->pending_entries_count ||
        wCryptoSHA256(&hash, (const uint8_t *) ts->pending_batch, ts->pending_batch_length) != kWCryptoOk)
        goto invalid;
    asciiHexEncodeBytesLower(hash.bytes, sizeof(hash.bytes), (uint8_t *) expected);
    asciiHexEncodeBytesLower(ts->last_ack_digest, sizeof(ts->last_ack_digest), (uint8_t *) prior);
    if (strcmp(digest->valuestring, expected) != 0 || strcmp(checkpoint->valuestring, prior) != 0)
        goto invalid;
    for (const cJSON *id = missing->child; id != NULL; id = id->next)
    {
        uint64_t value;
        if (! cJSON_IsString(id) || ! getUint64FromJson(&value, id) || value == 0)
            goto invalid;
        bool found = false;
        for (size_t i = 0; i < ts->pending_entries_count; ++i)
            found |= ts->pending_entries[i].id == value;
        if (! found)
            goto invalid;
        for (const cJSON *prior_id = missing->child; prior_id != id; prior_id = prior_id->next)
        {
            uint64_t prior_value;
            if (getUint64FromJson(&prior_value, prior_id) && prior_value == value)
                goto invalid;
        }
    }
    if (! authenticationclientCaptureCatchup(t))
        goto invalid;
    rwlockWriteLock(&ts->users_lock);
    for (const cJSON *id = missing->child; id != NULL; id = id->next)
    {
        uint64_t                                 value;
        discard                                  getUint64FromJson(&value, id);
        authenticationclient_accounting_entry_t *entry = authenticationclientCatchupEntry(ts, value);
        assert(entry != NULL);
        user_accounting_snapshot_t current;
        user_t                    *active = usersLookupByIdentifier(ts->users, value);
        assert(active != NULL);
        userGetAccountingSnapshot(active, &current);
        mergeObservation(entry, &current, true);
        if (! entry->detached)
        {
            entry->detached = true;
            ++ts->orphan_debt_count;
        }
    }
    rwlockWriteUnlock(&ts->users_lock);
    /* This proof states that the current sequence did not commit. Its debt,
     * baseline and checkpoint remain unchanged; the same sequence is reusable. */
    memoryFree(ts->pending_entries);
    ts->pending_entries       = NULL;
    ts->pending_entries_count = 0;
    cJSON_free(ts->pending_batch);
    ts->pending_batch        = NULL;
    ts->pending_batch_length = 0;
    mutexLock(&ts->control_mutex);
    ts->pull_requested = ts->pull_required = true;
    ts->pull_retry_not_before_ms           = 0;
    ts->stats_push_refused                 = false;
    ts->stats_retry_not_before_ms          = 0;
    mutexUnlock(&ts->control_mutex);
    cJSON_Delete(json);
    return true;
invalid:
    cJSON_Delete(json);
    return false;
#undef FIELD
}
