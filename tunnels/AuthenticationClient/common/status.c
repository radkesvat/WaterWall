#include "structure.h"

typedef struct status_entry_s
{
    uint64_t  id;
    user_ud_t active, visible, pending, pending_totals, retained;
    bool      has_active, has_pending, observation, lower_bound;
} status_entry_t;

static uint64_t elapsed(uint64_t now, uint64_t then)
{
    return now > then ? now - then : 0;
}

static uint64_t addLowerBound(uint64_t a, uint64_t b, bool *lower_bound)
{
    if (b > UINT64_MAX - a)
    {
        *lower_bound = true;
        return UINT64_MAX;
    }
    return a + b;
}

static bool deadlineExpired(uint64_t deadline_ms)
{
    return deadline_ms != 0 && authenticationclientLocalTimeMS() >= deadline_ms;
}

/* control_mutex and users_lock pin tables, and worker 0 owns all collection
 * membership changes. Traffic workers mutate user values, never membership.
 * Therefore count, preflight and copy cannot race a collection resize. */
static bool accountingCopy(authenticationclient_tstate_t *ts, size_t allowance, uint64_t deadline_ms,
                           status_entry_t **entries_out, size_t *count_out)
{
    const size_t active_count = usersCount(ts->users);
    size_t       count        = active_count, bytes;
    if (ts->pending_entries_count > SIZE_MAX - count)
        return false;
    count += ts->pending_entries_count;
    if (ts->catchup_entries_count > SIZE_MAX - count)
        return false;
    count += ts->catchup_entries_count;
    /* A second equally sized array supports a fixed eight-pass radix sort:
     * accounting work and storage both grow linearly with represented users. */
    if (! memoryTryComputeArraySize(count, 2 * sizeof(status_entry_t), &bytes) || bytes > allowance ||
        deadlineExpired(deadline_ms))
        return false;
    status_entry_t *entries = count != 0 ? memoryAllocate(bytes) : NULL;
    size_t          at      = 0;
    for (size_t i = 0; i < active_count; ++i)
    {
        if ((i & 127U) == 0 && deadlineExpired(deadline_ms))
            goto refused;
        user_accounting_snapshot_t current;
        userGetAccountingSnapshot(usersGetAt(ts->users, i), &current);
        user_stat_t baseline = {0};
        user_t     *base     = usersLookupByIdentifier(ts->sync_baseline_users, current.id);
        if (base != NULL)
            userGetStats(base, &baseline);
        entries[at++] =
            (status_entry_t) {.id          = current.id,
                              .active      = current.traffic,
                              .has_active  = true,
                              .visible     = {.u = elapsed(current.traffic.u, baseline.traffic.u),
                                              .d = elapsed(current.traffic.d, baseline.traffic.d)},
                              .observation = current.observation_pending,
                              .lower_bound = current.traffic.u == UINT64_MAX || current.traffic.d == UINT64_MAX};
    }
    for (size_t i = 0; i < ts->pending_entries_count; ++i)
    {
        if ((i & 127U) == 0 && deadlineExpired(deadline_ms))
            goto refused;
        const authenticationclient_accounting_entry_t *pending = &ts->pending_entries[i];
        entries[at++] =
            (status_entry_t) {.id             = pending->id,
                              .pending        = pending->delta,
                              .pending_totals = pending->totals,
                              .has_pending    = true,
                              .lower_bound    = pending->delta.u == UINT64_MAX || pending->delta.d == UINT64_MAX};
        /* A batch's timestamp is also present on already-acknowledged later
         * traffic; only explicit active/retained evidence counts observations. */
    }
    for (size_t i = 0; i < ts->catchup_entries_count; ++i)
    {
        if ((i & 127U) == 0 && deadlineExpired(deadline_ms))
            goto refused;
        const authenticationclient_accounting_entry_t *retained = &ts->catchup_entries[i];
        entries[at++] =
            (status_entry_t) {.id          = retained->id,
                              .retained    = retained->delta,
                              .observation = retained->first_usage_at_ms != 0,
                              .lower_bound = retained->delta.u == UINT64_MAX || retained->delta.d == UINT64_MAX};
    }
    *entries_out = entries;
    *count_out   = count;
    return true;
refused:
    memoryFree(entries);
    return false;
}

static bool accountingAggregate(status_entry_t *entries, size_t count, uint64_t deadline_ms,
                                authenticationclient_status_t *out)
{
    if (count > 1)
    {
        status_entry_t *source = entries, *dest = entries + count;
        for (unsigned shift = 0; shift < 64; shift += 8)
        {
            size_t offsets[256] = {0};
            for (size_t i = 0; i < count; ++i)
            {
                if ((i & 127U) == 0 && deadlineExpired(deadline_ms))
                    return false;
                ++offsets[(source[i].id >> shift) & 255U];
            }
            size_t prefix = 0;
            for (size_t i = 0; i < 256; ++i)
            {
                const size_t bucket = offsets[i];
                offsets[i]          = prefix;
                prefix += bucket;
            }
            for (size_t i = 0; i < count; ++i)
            {
                if ((i & 127U) == 0 && deadlineExpired(deadline_ms))
                    return false;
                dest[offsets[(source[i].id >> shift) & 255U]++] = source[i];
            }
            status_entry_t *swap = source;
            source               = dest;
            dest                 = swap;
        }
        assert(source == entries);
    }
    uint64_t upload = 0, download = 0, users = 0, observations = 0;
    bool     lower_bound = false;
    for (size_t at = 0; at < count;)
    {
        if (deadlineExpired(deadline_ms))
            return false;
        status_entry_t merged = {.id = entries[at].id};
        do
        {
            const status_entry_t *entry = &entries[at++];
            if (entry->has_active)
            {
                merged.active     = entry->active;
                merged.visible    = entry->visible;
                merged.has_active = true;
            }
            if (entry->has_pending)
            {
                merged.pending        = entry->pending;
                merged.pending_totals = entry->pending_totals;
                merged.has_pending    = true;
            }
            merged.retained.u = max(merged.retained.u, entry->retained.u);
            merged.retained.d = max(merged.retained.d, entry->retained.d);
            merged.observation |= entry->observation;
            merged.lower_bound |= entry->lower_bound;
        } while (at < count && entries[at].id == merged.id);
        user_ud_t debt = {.u = max(merged.visible.u, merged.retained.u), .d = max(merged.visible.d, merged.retained.d)};
        if (merged.has_pending)
        {
            const uint64_t later_u = merged.has_active ? elapsed(merged.active.u, merged.pending_totals.u) : 0;
            const uint64_t later_d = merged.has_active ? elapsed(merged.active.d, merged.pending_totals.d) : 0;
            debt.u                 = max(debt.u, addLowerBound(merged.pending.u, later_u, &merged.lower_bound));
            debt.d                 = max(debt.d, addLowerBound(merged.pending.d, later_d, &merged.lower_bound));
        }
        lower_bound |= merged.lower_bound;
        upload   = addLowerBound(upload, debt.u, &lower_bound);
        download = addLowerBound(download, debt.d, &lower_bound);
        users += debt.u != 0 || debt.d != 0;
        observations += merged.observation;
    }
    out->locally_unacknowledged_upload_bytes   = upload;
    out->locally_unacknowledged_download_bytes = download;
    out->usage_user_count                      = users;
    out->first_use_observation_count           = observations;
    out->accounting_lower_bound                = lower_bound;
    return ! deadlineExpired(deadline_ms);
}

void authenticationclientRecordFailure(tunnel_t *t, authenticationclient_failure_t failure, uint8_t operation)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    ts->last_failure           = failure;
    ts->last_failure_operation = operation;
    ts->last_failure_ms        = authenticationclientLocalTimeMS();
    mutexUnlock(&ts->control_mutex);
}

void authenticationclientStatusSnapshot(tunnel_t *t, bool include_accounting, size_t working_allowance,
                                        uint64_t deadline_ms, authenticationclient_status_t *out)
{
    assert(t != NULL && out != NULL && currentThreadIsEventWorkerWID(0));
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    *out                              = (authenticationclient_status_t) {0};
    const uint64_t  now               = authenticationclientLocalTimeMS();
    const uint64_t  loop_now          = wloopNowMonotonicMS(getWorkerLoop(0));
    status_entry_t *entries           = NULL;
    size_t          count             = 0;
    mutexLock(&ts->control_mutex);
    rwlockReadLock(&ts->users_lock);
    out->started                     = ts->started;
    out->stopping                    = ts->stopping;
    out->connected                   = ts->connected;
    out->authenticated               = ts->authenticated;
    out->auth_rejected               = ts->auth_rejected;
    out->continuity_error            = ts->continuity_error;
    out->users_loaded                = ts->users_loaded;
    out->clock_loaded                = ts->clock_loaded;
    out->users_count                 = usersCount(ts->users);
    out->blocking_reason             = ts->stopping           ? kAuthenticationClientBlockStopping
                                       : ! ts->started        ? kAuthenticationClientBlockNotStarted
                                       : ts->continuity_error ? kAuthenticationClientBlockContinuity
                                       : ts->auth_rejected    ? kAuthenticationClientBlockCredentialRejected
                                       : ! ts->users_loaded || ! ts->clock_loaded || ts->users == NULL
                                           ? kAuthenticationClientBlockCacheClock
                                           : kAuthenticationClientBlockNone;
    out->can_authenticate            = out->blocking_reason == kAuthenticationClientBlockNone;
    out->state                       = ts->continuity_error ? kAuthenticationClientStateContinuityError
                                       : ts->authenticated
                                           ? (ts->users_loaded ? kAuthenticationClientStateReady : kAuthenticationClientStateAuthenticating)
                                       : ts->connected                 ? kAuthenticationClientStateAuthenticating
                                       : ts->started && ! ts->stopping ? kAuthenticationClientStateConnecting
                                                                       : kAuthenticationClientStateStopped;
    out->write_paused                = ts->write_paused;
    out->auth_in_flight              = ts->auth_in_flight;
    out->pull_in_flight              = ts->pull_in_flight;
    out->push_in_flight              = ts->push_in_flight;
    out->pull_requested              = ts->pull_requested;
    out->pull_required               = ts->pull_required;
    out->push_requested              = ts->push_requested;
    out->first_usage_push_requested  = ts->first_usage_push_requested;
    out->first_usage_push_deferred   = ts->first_usage_push_deferred;
    out->catchup_capture_needed      = ts->catchup_capture_needed;
    out->retained_catchup_slots      = ts->catchup_entries_count;
    out->reconnect_queued            = ts->reconnect_work_pending;
    out->pending_request_count       = ts->pending_count;
    out->unresolved_batch            = ts->pending_batch != NULL;
    out->batch_sequence              = ts->next_batch_sequence;
    out->batch_entry_count           = ts->pending_entries_count;
    out->batch_size                  = ts->pending_batch_length;
    out->retry_deadline_valid        = ts->reconnect_timer != NULL;
    out->retry_remaining_ms          = elapsed(ts->reconnect_due_ms, loop_now);
    out->request_deadline_valid      = ts->request_timer != NULL;
    out->request_remaining_ms        = elapsed(ts->request_deadline_ms, loop_now);
    out->applied_config_revision     = ts->local_config_revision;
    out->applied_stats_revision      = ts->local_stats_revision;
    out->applied_revision_generation = ts->local_revision_generation;
    out->remote_config_revision      = ts->remote_config_revision;
    out->remote_stats_revision       = ts->remote_stats_revision;
    out->remote_revision_generation  = ts->remote_revision_generation;
    out->auth_success_valid          = ts->last_auth_success_valid;
    out->pull_success_valid          = ts->last_pull_success_valid;
    out->ack_success_valid           = ts->last_ack_success_valid;
    out->auth_success_age_ms         = elapsed(now, ts->last_auth_success_ms);
    out->pull_success_age_ms         = elapsed(now, ts->last_pull_success_ms);
    out->ack_success_age_ms          = elapsed(now, ts->last_ack_success_ms);
    out->last_failure                = ts->last_failure;
    out->last_failure_operation      = ts->last_failure_operation;
    out->last_failure_age_ms         = elapsed(now, ts->last_failure_ms);
    out->accounting_state =
        include_accounting ? kAuthenticationClientAccountingUnavailable : kAuthenticationClientAccountingNotRequested;
    out->sampling_started_ms = authenticationclientLocalTimeMS();
    const bool sampled = include_accounting && accountingCopy(ts, working_allowance, deadline_ms, &entries, &count);
    out->sampling_finished_ms = authenticationclientLocalTimeMS();
    rwlockReadUnlock(&ts->users_lock);
    mutexUnlock(&ts->control_mutex);
    if (sampled && accountingAggregate(entries, count, deadline_ms, out))
        out->accounting_state = kAuthenticationClientAccountingAvailable;
    memoryFree(entries);
}
