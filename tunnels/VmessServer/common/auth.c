#include "auth.h"
#include "internal.h"
#include "loggers/network_logger.h"

enum
{
    kVmessAuthWorkerQuantumUs = 1000,
    kVmessAuthWorkerTrials    = 256,
    kVmessAuthLineTrials      = 32,
    kVmessAuthBuildRows       = 128,
    kVmessAuthBuildRetryMs    = 1000
};

typedef struct vmessserver_auth_entry_s
{
    authenticationclient_uuid_candidate_t candidate;
    vmess_prepared_key_t                  key;
} vmessserver_auth_entry_t;

typedef struct vmessserver_auth_snapshot_s
{
    uint64_t                 generation;
    size_t                   count, capacity, bytes, references;
    vmessserver_auth_entry_t entries[];
} vmessserver_auth_snapshot_t;

typedef struct vmessserver_auth_worker_s
{
    vmessserver_auth_runtime_t *runtime;
    vmessserver_auth_job_t     *head, *tail;
    wtimer_t                   *timer;
    uint64_t                    timer_due_ms;
    size_t                      count;
    wid_t                       wid;
    bool                        stopping;
    bool                        pump_queued; /* runtime mutex; cancellation may be foreign */
} vmessserver_auth_worker_t;

struct vmessserver_auth_job_s
{
    vmessserver_auth_job_t      *prev, *next;
    vmessserver_auth_worker_t   *worker;
    vmessserver_lstate_t        *state;
    vmessserver_auth_snapshot_t *snapshot;
    vmess_auth_id_ctx_t          trial;
    size_t                       position;
    uint64_t                     deadline_ms, cache_event;
    uint8_t                      auth_id[16];
    bool                         ready, waiting_cache;
};

struct vmessserver_auth_runtime_s
{
    tunnel_t                    *tunnel;
    wmutex_t                     mutex;
    vmessserver_auth_snapshot_t *current;
    size_t                       cache_bytes, pending_count, pending_bytes;
    size_t                       worker_count;
    bool                         stopping, builder_queued;
    uint64_t                     retry_at_ms, cache_event;
    /* Construction belongs to worker zero; cancellation only changes shared
     * admission flags. Worker stop settles the unpublished vector. */
    vmessserver_auth_snapshot_t          *building;
    authenticationclient_uuid_source_t    source;
    size_t                                source_position, page_count, page_position;
    authenticationclient_uuid_candidate_t page[kVmessAuthBuildRows];
    wtimer_t                             *retry_timer;
    vmessserver_auth_worker_t             workers[];
};

static void authWorkerTimer(wtimer_t *timer);
static void authRunWorker(vmessserver_auth_worker_t *worker);
static void authRequestBuild(vmessserver_auth_runtime_t *runtime);

bool vmessserverAuthSnapshot(vmessserver_auth_runtime_t *runtime, uint64_t *pending, uint64_t *bytes, uint64_t *cache)
{
    if (! mutexTryLock(&runtime->mutex))
        return false;
    *pending = runtime->pending_count;
    *bytes   = runtime->pending_bytes;
    *cache   = runtime->cache_bytes;
    mutexUnlock(&runtime->mutex);
    return true;
}

static bool authStopping(vmessserver_auth_runtime_t *runtime)
{
    mutexLock(&runtime->mutex);
    const bool stopping = runtime->stopping;
    mutexUnlock(&runtime->mutex);
    return stopping;
}

static void authSnapshotRelease(vmessserver_auth_runtime_t *runtime, vmessserver_auth_snapshot_t *snapshot)
{
    if (snapshot == NULL)
        return;
    mutexLock(&runtime->mutex);
    if (UNLIKELY(snapshot->references == 0))
    {
        LOGF("VmessServer: authentication snapshot reference underflow");
        abortProgramNow(1);
    }
    const bool last = --snapshot->references == 0;
    mutexUnlock(&runtime->mutex);
    if (! last)
        return;
    const size_t bytes = snapshot->bytes;
    memorySecureZero(snapshot, bytes);
    memoryFree(snapshot);
    /* The old reservation remains charged through its actual wipe/free. */
    mutexLock(&runtime->mutex);
    assert(runtime->cache_bytes >= bytes);
    runtime->cache_bytes -= bytes;
    mutexUnlock(&runtime->mutex);
}

static vmessserver_auth_snapshot_t *authSnapshotAllocate(vmessserver_auth_runtime_t *runtime, size_t count,
                                                         uint64_t generation, size_t source_limit,
                                                         bool *capacity_refused)
{
    *capacity_refused        = false;
    vmessserver_tstate_t *ts = tunnelGetState(runtime->tunnel);
    size_t                bytes;
    if (! memoryTryComputeArraySize(count, sizeof(vmessserver_auth_entry_t), &bytes) ||
        bytes > SIZE_MAX - sizeof(vmessserver_auth_snapshot_t))
        return NULL;
    bytes += sizeof(vmessserver_auth_snapshot_t);
    const size_t limit = min(ts->auth_cache_max_bytes, source_limit);
    mutexLock(&runtime->mutex);
    const bool admitted = ! runtime->stopping && runtime->cache_bytes <= limit && bytes <= limit - runtime->cache_bytes;
    if (admitted)
        runtime->cache_bytes += bytes;
    else
        *capacity_refused = ! runtime->stopping;
    mutexUnlock(&runtime->mutex);
    if (! admitted)
        return NULL;
    vmessserver_auth_snapshot_t *snapshot = memoryAllocate(bytes);
    snapshot->bytes                       = bytes;
    snapshot->count                       = 0;
    snapshot->capacity                    = count;
    snapshot->generation                  = generation;
    snapshot->references                  = 1;
    return snapshot;
}

static bool authDropObsoleteCurrent(vmessserver_auth_runtime_t *runtime, uint64_t generation)
{
    mutexLock(&runtime->mutex);
    vmessserver_auth_snapshot_t *obsolete = runtime->current;
    if (obsolete != NULL && obsolete->generation != generation)
        runtime->current = NULL;
    else
        obsolete = NULL;
    mutexUnlock(&runtime->mutex);
    /* Jobs retain independent references. A stale cache cannot serve new jobs,
     * so keeping its cache reference must not prevent all future refreshes. */
    authSnapshotRelease(runtime, obsolete);
    return obsolete != NULL;
}

static bool authArmWorker(vmessserver_auth_worker_t *worker, uint64_t due_ms)
{
    assert(currentThreadOwnsWorker(worker->wid));
    if (worker->stopping || authStopping(worker->runtime))
        return false;
    if (worker->timer != NULL && worker->timer_due_ms <= due_ms)
        return true;
    const uint64_t now   = getHRTimeUs() / 1000U;
    const uint32_t delay = (uint32_t) min(max(due_ms > now ? due_ms - now : 0, UINT64_C(1)), (uint64_t) UINT32_MAX);
    if (worker->timer != NULL)
    {
        if (! wtimerReset(worker->timer, delay))
            return false;
    }
    else
    {
        worker->timer = wtimerAdd(getWorkerLoop(worker->wid), authWorkerTimer, delay, 1);
        if (worker->timer == NULL)
            return false;
        weventSetUserData(worker->timer, worker);
    }
    worker->timer_due_ms = due_ms;
    return true;
}

static void authScheduleFailure(vmessserver_auth_runtime_t *runtime, wid_t wid)
{
    if (authStopping(runtime) || wloopQuiesceRequested(getWorkerLoop(wid)))
        return;
    LOGE("VmessServer: could not schedule required authentication work");
    if (! requestProgramShutdown(1))
        abortProgramNow(1);
}

static void authPumpCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                    arg2;
    discard                    arg3;
    discard                    reason;
    vmessserver_auth_worker_t *worker = arg1;
    mutexLock(&worker->runtime->mutex);
    worker->pump_queued = false;
    mutexUnlock(&worker->runtime->mutex);
}

static void authPumpTask(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t                  *owner  = worker_ptr;
    vmessserver_auth_worker_t *worker = arg1;
    assert(owner->wid == worker->wid);
    discard owner;
    authPumpCancelled(worker, arg2, arg3, kWorkerMessageCancelQuiesced);
    authRunWorker(worker);
}

/* Only immutable worker identity and mutex-protected admission are touched here,
 * so publishers can coalesce a wakeup for any explicit worker. */
static void authQueueWorker(vmessserver_auth_worker_t *worker)
{
    vmessserver_auth_runtime_t *runtime = worker->runtime;
    mutexLock(&runtime->mutex);
    const bool needed = ! runtime->stopping && ! worker->pump_queued;
    if (needed)
        worker->pump_queued = true;
    mutexUnlock(&runtime->mutex);
    if (needed && sendWorkerMessageForceQueueWithCleanup(
                      worker->wid, authPumpTask, authPumpCancelled, worker, NULL, NULL) != kWorkerMessageSubmitAccepted)
        authScheduleFailure(runtime, worker->wid);
}

static void authWakeAll(vmessserver_auth_runtime_t *runtime)
{
    mutexLock(&runtime->mutex);
    ++runtime->cache_event;
    mutexUnlock(&runtime->mutex);
    for (wid_t wid = 0; wid < runtime->worker_count; ++wid)
        authQueueWorker(&runtime->workers[wid]);
}

static void authDiscardBuild(vmessserver_auth_runtime_t *runtime)
{
    vmessserver_auth_snapshot_t *snapshot = runtime->building;
    runtime->building                     = NULL;
    runtime->source                       = (authenticationclient_uuid_source_t) {0};
    runtime->source_position = runtime->page_count = runtime->page_position = 0;
    memorySecureZero(runtime->page, sizeof(runtime->page));
    authSnapshotRelease(runtime, snapshot);
}

static void authBuildRetryTimer(wtimer_t *timer)
{
    vmessserver_auth_runtime_t *runtime = weventGetUserdata(timer);
    if (runtime == NULL)
        return;
    runtime->retry_timer = NULL;
    authRequestBuild(runtime);
}

static void authRetryBuild(vmessserver_auth_runtime_t *runtime)
{
    assert(currentThreadOwnsWorker(0));
    authDiscardBuild(runtime);
    mutexLock(&runtime->mutex);
    runtime->retry_at_ms = getHRTimeUs() / 1000U + kVmessAuthBuildRetryMs;
    const bool stopping  = runtime->stopping;
    mutexUnlock(&runtime->mutex);
    if (! stopping && runtime->retry_timer == NULL)
    {
        runtime->retry_timer = wtimerAdd(getWorkerLoop(0), authBuildRetryTimer, kVmessAuthBuildRetryMs, 1);
        if (runtime->retry_timer != NULL)
            weventSetUserData(runtime->retry_timer, runtime);
        else
            authScheduleFailure(runtime, 0);
    }
    authWakeAll(runtime);
}

static bool authReadSource(vmessserver_auth_runtime_t *runtime, authenticationclient_uuid_source_t *source)
{
    vmessserver_tstate_t *ts = tunnelGetState(runtime->tunnel);
    if (ts->auth_client_tunnel != NULL)
        return authenticationclientGetUUIDSource(ts->auth_client_tunnel, source) == kAuthenticationClientUuidSnapshotOk;
    *source = (authenticationclient_uuid_source_t) {.users_generation = 1,
                                                    .total_users      = ts->user_count,
                                                    .max_users        = ts->user_count,
                                                    .max_bytes        = ts->auth_cache_max_bytes};
    return true;
}

static void authBuildCancelled(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard                     arg2;
    discard                     arg3;
    discard                     reason;
    vmessserver_auth_runtime_t *runtime = arg1;
    mutexLock(&runtime->mutex);
    runtime->builder_queued = false;
    mutexUnlock(&runtime->mutex);
}

static void authBuildTask(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    worker_t *owner = worker_ptr;
    assert(owner->wid == 0);
    discard                     owner;
    vmessserver_auth_runtime_t *runtime = arg1;
    authBuildCancelled(runtime, arg2, arg3, kWorkerMessageCancelQuiesced);
    if (authStopping(runtime))
        return;
    mutexLock(&runtime->mutex);
    const bool deferred = getHRTimeUs() / 1000U < runtime->retry_at_ms;
    mutexUnlock(&runtime->mutex);
    if (deferred)
        return;
    vmessserver_tstate_t *ts = tunnelGetState(runtime->tunnel);
    if (runtime->building == NULL)
    {
        if (! authReadSource(runtime, &runtime->source))
        {
            authWakeAll(runtime);
            return;
        }
        mutexLock(&runtime->mutex);
        const bool current =
            runtime->current != NULL && runtime->current->generation == runtime->source.users_generation;
        mutexUnlock(&runtime->mutex);
        if (current)
        {
            authWakeAll(runtime);
            return;
        }
        bool capacity_refused;
        runtime->building = authSnapshotAllocate(runtime,
                                                 runtime->source.total_users,
                                                 runtime->source.users_generation,
                                                 runtime->source.max_bytes,
                                                 &capacity_refused);
        if (runtime->building == NULL && capacity_refused &&
            authDropObsoleteCurrent(runtime, runtime->source.users_generation))
            runtime->building = authSnapshotAllocate(runtime,
                                                     runtime->source.total_users,
                                                     runtime->source.users_generation,
                                                     runtime->source.max_bytes,
                                                     &capacity_refused);
        if (runtime->building == NULL)
        {
            authRetryBuild(runtime);
            return;
        }
    }
    const uint64_t start   = getHRTimeUs();
    size_t         derived = 0;
    while (derived < kVmessAuthBuildRows && getHRTimeUs() - start < kVmessAuthWorkerQuantumUs)
    {
        if (runtime->page_position == runtime->page_count)
        {
            memorySecureZero(runtime->page, sizeof(runtime->page));
            runtime->page_count = runtime->page_position = 0;
            if (runtime->source_position == runtime->source.total_users)
                break;
            if (ts->auth_client_tunnel != NULL)
            {
                if (authenticationclientCopyUUIDCandidatePage(ts->auth_client_tunnel,
                                                              runtime->source.users_generation,
                                                              runtime->source_position,
                                                              kVmessAuthBuildRows,
                                                              runtime->page,
                                                              &runtime->page_count,
                                                              &runtime->source_position) !=
                    kAuthenticationClientUuidSnapshotOk)
                {
                    authRetryBuild(runtime);
                    return;
                }
            }
            else
            {
                const size_t end = min(runtime->source.total_users, runtime->source_position + kVmessAuthBuildRows);
                while (runtime->source_position < end)
                {
                    const size_t                           index     = runtime->source_position++;
                    authenticationclient_uuid_candidate_t *candidate = &runtime->page[runtime->page_count++];
                    candidate->user_id                               = index + 1U;
                    memoryCopy(candidate->uuid, ts->users[index].uuid, sizeof(candidate->uuid));
                }
            }
            /* Empty pages still consume this construction turn. */
            if (runtime->page_count == 0)
                break;
        }
        assert(runtime->building->count < runtime->building->capacity);
        vmessserver_auth_entry_t *entry = &runtime->building->entries[runtime->building->count];
        entry->candidate                = runtime->page[runtime->page_position++];
        if (vmessPrepareKey(entry->candidate.uuid, &entry->key) != kWCryptoOk)
        {
            authRetryBuild(runtime);
            return;
        }
        ++runtime->building->count;
        ++derived;
    }
    if (runtime->source_position != runtime->source.total_users || runtime->page_position != runtime->page_count)
    {
        authRequestBuild(runtime);
        return;
    }
    authenticationclient_uuid_source_t current_source;
    if (! authReadSource(runtime, &current_source) ||
        current_source.users_generation != runtime->source.users_generation)
    {
        authRetryBuild(runtime);
        return;
    }
    mutexLock(&runtime->mutex);
    vmessserver_auth_snapshot_t *old = runtime->current;
    runtime->current                 = runtime->building;
    runtime->building                = NULL;
    runtime->retry_at_ms             = 0;
    mutexUnlock(&runtime->mutex);
    authSnapshotRelease(runtime, old);
    runtime->source_position = runtime->page_count = runtime->page_position = 0;
    memorySecureZero(runtime->page, sizeof(runtime->page));
    authWakeAll(runtime);
}

static void authRequestBuild(vmessserver_auth_runtime_t *runtime)
{
    mutexLock(&runtime->mutex);
    const bool needed =
        ! runtime->stopping && ! runtime->builder_queued && getHRTimeUs() / 1000U >= runtime->retry_at_ms;
    if (needed)
        runtime->builder_queued = true;
    mutexUnlock(&runtime->mutex);
    if (needed && sendWorkerMessageForceQueueWithCleanup(0, authBuildTask, authBuildCancelled, runtime, NULL, NULL) !=
                      kWorkerMessageSubmitAccepted)
        authScheduleFailure(runtime, 0);
}

static int authPinSnapshot(vmessserver_auth_job_t *job)
{
    vmessserver_auth_runtime_t        *runtime = job->worker->runtime;
    authenticationclient_uuid_source_t source;
    if (! authReadSource(runtime, &source))
        return -1;
    mutexLock(&runtime->mutex);
    vmessserver_auth_snapshot_t *snapshot = runtime->current;
    if (! runtime->stopping && snapshot != NULL && snapshot->generation == source.users_generation)
    {
        if (UNLIKELY(snapshot->references == 0 || snapshot->references == SIZE_MAX))
        {
            LOGF("VmessServer: invalid authentication snapshot reference count");
            abortProgramNow(1);
        }
        ++snapshot->references;
        job->snapshot = snapshot;
    }
    job->cache_event = runtime->cache_event;
    mutexUnlock(&runtime->mutex);
    if (job->snapshot != NULL)
        return 1;
    job->waiting_cache = true;
    authRequestBuild(runtime);
    return 0;
}

static void authRotateJob(vmessserver_auth_worker_t *worker, vmessserver_auth_job_t *job)
{
    assert(worker->head == job);
    if (worker->tail == job)
        return;
    worker->head       = job->next;
    worker->head->prev = NULL;
    job->next          = NULL;
    job->prev          = worker->tail;
    worker->tail->next = job;
    worker->tail       = job;
}

static void authLookupFinished(vmessserver_auth_job_t *job, uint8_t result)
{
    vmessserver_lstate_t *ls   = job->state;
    tunnel_t             *t    = ls->tunnel;
    line_t               *line = ls->line;
    ls->auth_result            = result;
    job->ready                 = false;
    authSnapshotRelease(job->worker->runtime, job->snapshot);
    job->snapshot = NULL;
    vmessAuthIdDestroy(&job->trial);
    lineRef(line);
    vmessserverProcessInput(t, line);
    lineUnref(line);
    /* The callback may detach/free this job or close any sibling job. */
}

static void authLookupMiss(vmessserver_auth_job_t *job)
{
    authenticationclient_uuid_source_t source;
    if (authReadSource(job->worker->runtime, &source) && source.users_generation != job->snapshot->generation)
    {
        /* A user added while this vector was being scanned must get a fresh
         * attempt before the bytes can be classified as unauthenticated. */
        authSnapshotRelease(job->worker->runtime, job->snapshot);
        job->snapshot      = NULL;
        job->position      = 0;
        job->waiting_cache = false;
        return;
    }
    authLookupFinished(job, 2);
}

static void authWorkerTimer(wtimer_t *timer)
{
    vmessserver_auth_worker_t *worker = weventGetUserdata(timer);
    if (worker == NULL)
        return;
    worker->timer = NULL;
    authRunWorker(worker);
}

static void authRunWorker(vmessserver_auth_worker_t *worker)
{
    assert(currentThreadOwnsWorker(worker->wid));
    if (worker->stopping || authStopping(worker->runtime))
        return;
    mutexLock(&worker->runtime->mutex);
    const uint64_t cache_event = worker->runtime->cache_event;
    mutexUnlock(&worker->runtime->mutex);
    const uint64_t start = getHRTimeUs();
    size_t         turns = max(worker->count, (size_t) (kVmessAuthWorkerTrials / kVmessAuthLineTrials)), trials = 0;
    while (worker->head != NULL && turns-- != 0 && trials < kVmessAuthWorkerTrials &&
           getHRTimeUs() - start < kVmessAuthWorkerQuantumUs)
    {
        vmessserver_auth_job_t *job = worker->head;
        authRotateJob(worker, job);
        if (job->waiting_cache && job->cache_event != cache_event)
            job->waiting_cache = false;
        if (getHRTimeUs() / 1000U >= job->deadline_ms)
        {
            tunnel_t *t    = job->state->tunnel;
            line_t   *line = job->state->line;
            lineRef(line);
            vmessserverReason(job->state,
                              job->waiting_cache ? kVmessServerReasonAuthUnavailable : kVmessServerReasonTimeout);
            vmessserverCloseLineBidirectional(t, line);
            lineUnref(line);
            continue;
        }
        if (! job->ready || job->waiting_cache)
            continue;
        if (job->snapshot == NULL)
        {
            const int pinned = authPinSnapshot(job);
            if (pinned < 0)
            {
                vmessserverReason(job->state, kVmessServerReasonAuthUnavailable);
                authLookupFinished(job, 2);
            }
            if (pinned <= 0)
                continue;
        }
        if (job->trial.cipher == NULL && vmessAuthIdInit(&job->trial) != kWCryptoOk)
        {
            authLookupFinished(job, 3);
            continue;
        }
        bool complete = false;
        for (size_t quantum = 0; quantum < kVmessAuthLineTrials && job->position < job->snapshot->count &&
                                 trials < kVmessAuthWorkerTrials && getHRTimeUs() - start < kVmessAuthWorkerQuantumUs;
             ++quantum)
        {
            ++trials;
            const vmessserver_auth_entry_t *entry     = &job->snapshot->entries[job->position++];
            uint64_t                        timestamp = 0;
            const wcrypto_status_t          checked =
                vmessAuthIdCheck(&job->trial, &entry->key, job->auth_id, getTimeOfDayMS() / 1000U, &timestamp);
            if (checked == kWCryptoAuthenticationFailed)
                continue;
            vmessserver_lstate_t *ls = job->state;
            if (checked == kWCryptoOk || checked == kWCryptoRejectedKey)
                ls->auth_recognized = true;
            if (checked == kWCryptoRejectedKey)
                vmessserverReason(ls, kVmessServerReasonExpiredAuthId);
            if (checked == kWCryptoOk)
            {
                ls->candidate            = entry->candidate;
                ls->candidate_generation = job->snapshot->generation;
                ls->auth_key             = entry->key;
                ls->auth_timestamp       = timestamp;
            }
            authLookupFinished(job, checked == kWCryptoOk ? 1 : 3);
            complete = true;
            break;
        }
        if (! complete && job->position == job->snapshot->count)
            authLookupMiss(job);
    }
    uint64_t       due      = UINT64_MAX;
    const uint64_t now      = getHRTimeUs() / 1000U;
    bool           runnable = false;
    for (vmessserver_auth_job_t *job = worker->head; job != NULL; job = job->next)
    {
        due = min(due, job->deadline_ms);
        runnable |=
            job->deadline_ms <= now || (job->ready && (! job->waiting_cache || job->cache_event != cache_event));
    }
    if (due != UINT64_MAX && ! authArmWorker(worker, due))
        authScheduleFailure(worker->runtime, worker->wid);
    if (runnable)
        authQueueWorker(worker);
}

vmessserver_auth_runtime_t *vmessserverAuthCreate(tunnel_t *t)
{
    const size_t workers = getWorkersCount();
    size_t       bytes;
    if (! memoryTryComputeArraySize(workers, sizeof(vmessserver_auth_worker_t), &bytes) ||
        bytes > SIZE_MAX - sizeof(vmessserver_auth_runtime_t))
        return NULL;
    vmessserver_auth_runtime_t *runtime = memoryAllocateZero(sizeof(*runtime) + bytes);
    if (! mutexTryInit(&runtime->mutex))
    {
        memoryFree(runtime);
        return NULL;
    }
    runtime->tunnel       = t;
    runtime->worker_count = workers;
    for (wid_t wid = 0; wid < workers; ++wid)
    {
        runtime->workers[wid].runtime = runtime;
        runtime->workers[wid].wid     = wid;
    }
    return runtime;
}

bool vmessserverAuthLineInit(vmessserver_lstate_t *ls)
{
    assert(ls->line_kind == kVmessServerLineKindClient && ls->auth_job == NULL && lineIsOnCurrentWorker(ls->line));
    vmessserver_tstate_t       *ts      = tunnelGetState(ls->tunnel);
    vmessserver_auth_runtime_t *runtime = ts->auth;
    vmessserver_auth_worker_t  *worker  = &runtime->workers[lineGetWID(ls->line)];
    mutexLock(&runtime->mutex);
    const bool admitted = ! runtime->stopping && runtime->pending_count < ts->auth_max_pending;
    if (admitted)
        ++runtime->pending_count;
    mutexUnlock(&runtime->mutex);
    if (! admitted)
        return false;
    vmessserver_auth_job_t *job = memoryAllocateZero(sizeof(*job));
    lineRef(ls->line);
    job->worker      = worker;
    job->state       = ls;
    job->deadline_ms = getHRTimeUs() / 1000U + ts->handshake_timeout_ms;
    job->prev        = worker->tail;
    if (worker->tail != NULL)
        worker->tail->next = job;
    else
        worker->head = job;
    worker->tail = job;
    ++worker->count;
    ls->auth_job = job;
    if (! authArmWorker(worker, job->deadline_ms))
    {
        vmessserverAuthLineDetach(ls);
        return false;
    }
    return true;
}

bool vmessserverAuthAdmitInput(vmessserver_lstate_t *ls, size_t bytes)
{
    if (ls->auth_job == NULL)
        return true;
    vmessserver_tstate_t       *ts      = tunnelGetState(ls->tunnel);
    vmessserver_auth_runtime_t *runtime = ts->auth;
    mutexLock(&runtime->mutex);
    const bool admitted = ! runtime->stopping && runtime->pending_bytes <= ts->auth_pending_max_bytes &&
                          bytes <= ts->auth_pending_max_bytes - runtime->pending_bytes;
    if (admitted)
        runtime->pending_bytes += bytes;
    mutexUnlock(&runtime->mutex);
    if (admitted)
        ls->unauth_bytes += bytes;
    return admitted;
}

void vmessserverAuthSchedule(vmessserver_lstate_t *ls)
{
    assert(lineIsOnCurrentWorker(ls->line) && ls->header_filled >= 16 && ls->auth_job != NULL);
    vmessserver_auth_job_t *job = ls->auth_job;
    if (job->ready)
        return;
    memoryCopy(job->auth_id, ls->header, sizeof(job->auth_id));
    job->ready = true;
    authQueueWorker(job->worker);
}

void vmessserverAuthLineDetach(vmessserver_lstate_t *ls)
{
    vmessserver_auth_job_t *job = ls->auth_job;
    if (job == NULL)
        return;
    assert(lineIsOnCurrentWorker(ls->line));
    line_t *line                        = ls->line;
    ls->auth_job                        = NULL;
    vmessserver_auth_worker_t  *worker  = job->worker;
    vmessserver_auth_runtime_t *runtime = worker->runtime;
    if (job->prev != NULL)
        job->prev->next = job->next;
    else
        worker->head = job->next;
    if (job->next != NULL)
        job->next->prev = job->prev;
    else
        worker->tail = job->prev;
    assert(worker->count != 0);
    --worker->count;
    mutexLock(&runtime->mutex);
    assert(runtime->pending_count != 0 && runtime->pending_bytes >= ls->unauth_bytes);
    --runtime->pending_count;
    runtime->pending_bytes -= ls->unauth_bytes;
    mutexUnlock(&runtime->mutex);
    ls->unauth_bytes = 0;
    authSnapshotRelease(runtime, job->snapshot);
    vmessAuthIdDestroy(&job->trial);
    memorySecureZero(job, sizeof(*job));
    memoryFree(job);
    lineUnref(line);
}

bool vmessserverAuthResolve(vmessserver_lstate_t *ls)
{
    assert(ls->auth_result == 1 && ls->auth_username == NULL && ls->auth_password == NULL);
    vmessserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ts->auth_client_tunnel != NULL)
    {
        authenticationclient_user_profile_t             profile = {0};
        const authenticationclient_user_lookup_result_t result  = authenticationclientResolveUUIDCandidateWithProfile(
            ts->auth_client_tunnel, ls->candidate_generation, &ls->candidate, &ls->user_handle, &profile);
        if (result != kAuthenticationClientUserLookupOk)
            return false;
        ls->auth_username = profile.name;
        ls->auth_password = profile.password;
        return true;
    }
    assert(ls->candidate.user_id != 0 && ls->candidate.user_id <= ts->user_count);
    const vmessserver_user_t *user = &ts->users[ls->candidate.user_id - 1U];
    assert(memoryEqual(user->uuid, ls->candidate.uuid, sizeof(user->uuid)));
    char password[kWwUuidCanonicalStringLen + 1U];
    wwUuidToCanonicalString(user->uuid, password);
    ls->auth_username = user->username != NULL ? stringDuplicate(user->username) : NULL;
    ls->auth_password = stringDuplicate(password);
    memorySecureZero(password, sizeof(password));
    return true;
}

bool vmessserverLineAuthenticated(const vmessserver_lstate_t *ls)
{
    return userHandleIsValid(&ls->user_handle) || ls->auth_password != NULL;
}

void vmessserverRecordLineUser(line_t *line, vmessserver_lstate_t *ls)
{
    assert(vmessserverLineAuthenticated(ls));
    if (userHandleIsValid(&ls->user_handle))
        lineAddUser(line, &ls->user_handle, ls->auth_username, ls->auth_password);
    else
        lineAddAuthenticatedCredentials(line, ls->auth_username, ls->auth_password);
}

void vmessserverAuthOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard               context;
    vmessserver_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->auth->mutex);
    ts->auth->stopping = true;
    mutexUnlock(&ts->auth->mutex);
}

void vmessserverAuthOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadOwnsWorker(wid));
    vmessserver_tstate_t      *ts     = tunnelGetState(t);
    vmessserver_auth_worker_t *worker = &ts->auth->workers[wid];
    worker->stopping                  = true;
    if (worker->timer != NULL)
    {
        weventSetUserData(worker->timer, NULL);
        wtimerDelete(worker->timer);
        worker->timer = NULL;
    }
    if (wid == 0 && ts->auth->retry_timer != NULL)
    {
        weventSetUserData(ts->auth->retry_timer, NULL);
        wtimerDelete(ts->auth->retry_timer);
        ts->auth->retry_timer = NULL;
    }
}

void vmessserverAuthOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadOwnsWorker(wid));
    vmessserver_tstate_t      *ts     = tunnelGetState(t);
    vmessserver_auth_worker_t *worker = &ts->auth->workers[wid];
    while (ts->owned_backends != NULL && ts->owned_backends[wid] != NULL)
        vmessserverCloseUdpRemoteLineInternal(t, ts->owned_backends[wid]->line, true);
    while (worker->head != NULL)
    {
        line_t *line = worker->head->state->line;
        lineRef(line);
        vmessserverCloseLineBidirectional(t, line);
        lineUnref(line);
    }
    if (wid == 0)
        authDiscardBuild(ts->auth);
}

void vmessserverAuthDestroy(vmessserver_auth_runtime_t *runtime)
{
    if (runtime == NULL)
        return;
    assert(runtime->pending_count == 0 && runtime->pending_bytes == 0 && ! runtime->builder_queued);
    for (size_t i = 0; i < runtime->worker_count; ++i)
        assert(runtime->workers[i].head == NULL && runtime->workers[i].timer == NULL &&
               ! runtime->workers[i].pump_queued);
    assert(runtime->retry_timer == NULL);
    authDiscardBuild(runtime);
    authSnapshotRelease(runtime, runtime->current);
    assert(runtime->cache_bytes == 0);
    mutexDestroy(&runtime->mutex);
    memorySecureZero(runtime, sizeof(*runtime) + runtime->worker_count * sizeof(*runtime->workers));
    memoryFree(runtime);
}
