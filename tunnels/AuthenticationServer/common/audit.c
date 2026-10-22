#include "AuthenticationServer/audit.h"
#include "loggers/network_logger.h"

/* Only the queue lock is shared with submitters. File output, JSON escaping and
 * diagnostics run on the dedicated writer, without any account/worker locks. */
typedef struct authenticationserver_audit_record_s
{
    uint64_t    timestamp_ms, sequence, id, revision, suppressed_rejections;
    uint32_t    fields;
    const char *operation, *error;
    char        actor[kAuthenticationServerAuditLabelCap + 1];
    char        gateway_config[kAuthenticationServerAuditLabelCap + 1];
    char        gateway_node[kAuthenticationServerAuditLabelCap + 1];
    bool        api, server_summary, has_actor, has_gateway_config, has_gateway_node, truncated;
} authenticationserver_audit_record_t;

struct authenticationserver_audit_s
{
    authenticationserver_audit_writer_t *writer;
    wthread_t                            thread;
    wcond_mutex_t                        lock;
    wcondvar_t                           wake;
    bool                                 stopping;
    size_t                               head, count;
    uint64_t                             sequence, pending_suppressed, next_rejection_ms;
    bool                                 rejection_sample_seen, rejection_deadline_exhausted;
    authenticationserver_audit_record_t  records[kAuthenticationServerAuditQueueCap];
    char                                 config[kAuthenticationServerAuditLabelCap + 1];
    char                                 node[kAuthenticationServerAuditLabelCap + 1];
    char                                 instance[33];
    atomic_bool                          writer_failed;
    atomic_ullong                        queued, written, dropped, write_failures, suppressed;
    atomic_int                           last_error;
};

enum
{
    kAuthenticationServerAuditRejectionIntervalMs = 5000,
    kAuthenticationServerAuditRejectionQueueLimit = 16,
    kAuthenticationServerAuditQueueFull           = 100,
    kAuthenticationServerAuditSequenceExhausted
};

static bool authenticationserverAuditCopyLabel(char output[kAuthenticationServerAuditLabelCap + 1], const char *input)
{
    if (input == NULL)
    {
        output[0] = '\0';
        return false;
    }
    size_t length = 0;
    while (length < kAuthenticationServerAuditLabelCap && input[length] != '\0')
        ++length;
    bool truncated = input[length] != '\0';
    /* Configuration labels are UTF-8. Never split the final code point. */
    if (truncated)
        while (length > 0 && ((unsigned char) input[length] & 0xc0U) == 0x80U)
            --length;
    memoryCopy(output, input, length);
    output[length] = '\0';
    return truncated;
}

typedef struct authenticationserver_audit_json_s
{
    char   bytes[kAuthenticationServerAuditRecordCap];
    size_t length;
} authenticationserver_audit_json_t;

static void authenticationserverAuditJsonBytes(authenticationserver_audit_json_t *json, const char *bytes, size_t size)
{
    /* Five bounded labels, each escaping to at most six bytes per input byte,
     * plus fixed field names and scalars fit the fixed 16-KiB record. */
    if (size > sizeof(json->bytes) - json->length)
    {
        LOGF("AuthenticationServer: audit record geometry invariant failed");
        abortProgramNow(1);
    }
    memoryCopy(json->bytes + json->length, bytes, size);
    json->length += size;
}

static void authenticationserverAuditJsonText(authenticationserver_audit_json_t *json, const char *text)
{
    authenticationserverAuditJsonBytes(json, text, strlen(text));
}

static void authenticationserverAuditJsonString(authenticationserver_audit_json_t *json, const char *text)
{
    static const char hex[] = "0123456789abcdef";
    if (text == NULL)
    {
        authenticationserverAuditJsonText(json, "null");
        return;
    }
    authenticationserverAuditJsonText(json, "\"");
    for (const unsigned char *p = (const unsigned char *) text; *p != 0; ++p)
    {
        if (*p == '"' || *p == '\\')
        {
            const char escaped[] = {'\\', (char) *p};
            authenticationserverAuditJsonBytes(json, escaped, sizeof(escaped));
        }
        else if (*p < 0x20U)
        {
            const char escaped[] = {'\\', 'u', '0', '0', hex[*p >> 4U], hex[*p & 15U]};
            authenticationserverAuditJsonBytes(json, escaped, sizeof(escaped));
        }
        else
            authenticationserverAuditJsonBytes(json, (const char *) p, 1);
    }
    authenticationserverAuditJsonText(json, "\"");
}

static void authenticationserverAuditJsonU64(authenticationserver_audit_json_t *json, uint64_t value)
{
    char number[24];
    int  length = snprintf(number, sizeof(number), "\"%" PRIu64 "\"", value);
    assert(length > 0 && (size_t) length < sizeof(number));
    authenticationserverAuditJsonBytes(json, number, (size_t) length);
}

static void authenticationserverAuditRender(const authenticationserver_audit_t        *audit,
                                            const authenticationserver_audit_record_t *record,
                                            authenticationserver_audit_json_t         *json)
{
    static const char *const fields[] = {"name",
                                         "email",
                                         "notes",
                                         "wireguard_allowed_ips",
                                         "gid",
                                         "enabled",
                                         "record_stat_interval_ms",
                                         "limit.traffic.u",
                                         "limit.traffic.d",
                                         "limit.traffic.total",
                                         "limit.bandwidth.u",
                                         "limit.bandwidth.d",
                                         "limit.ips",
                                         "limit.devices",
                                         "limit.cons_in",
                                         "limit.cons_out",
                                         "time.expire_at_ms",
                                         "time.expire_after_first_usage_ms",
                                         "account",
                                         "credentials"};
    json->length                      = 0;
#define AUTH_AUDIT_TEXT(value)   authenticationserverAuditJsonText(json, value)
#define AUTH_AUDIT_STRING(value) authenticationserverAuditJsonString(json, value)
    AUTH_AUDIT_TEXT("{\"timestamp_ms\":");
    authenticationserverAuditJsonU64(json, record->timestamp_ms);
    AUTH_AUDIT_TEXT(",\"server_instance\":");
    AUTH_AUDIT_STRING(audit->instance);
    AUTH_AUDIT_TEXT(",\"sequence\":");
    authenticationserverAuditJsonU64(json, record->sequence);
    AUTH_AUDIT_TEXT(",\"config\":");
    AUTH_AUDIT_STRING(audit->config);
    AUTH_AUDIT_TEXT(",\"node\":");
    AUTH_AUDIT_STRING(audit->node);
    AUTH_AUDIT_TEXT(",\"source\":");
    AUTH_AUDIT_STRING(record->server_summary ? "server" : record->api ? "api" : "producer");
    AUTH_AUDIT_TEXT(",\"actor\":");
    AUTH_AUDIT_STRING(record->has_actor ? record->actor : NULL);
    AUTH_AUDIT_TEXT(",\"gateway_config\":");
    AUTH_AUDIT_STRING(record->has_gateway_config ? record->gateway_config : NULL);
    AUTH_AUDIT_TEXT(",\"gateway_node\":");
    AUTH_AUDIT_STRING(record->has_gateway_node ? record->gateway_node : NULL);
    AUTH_AUDIT_TEXT(",\"operation\":");
    AUTH_AUDIT_STRING(record->operation);
    AUTH_AUDIT_TEXT(",\"user_id\":");
    if (record->id == 0)
        AUTH_AUDIT_TEXT("null");
    else
        authenticationserverAuditJsonU64(json, record->id);
    AUTH_AUDIT_TEXT(",\"outcome\":");
    AUTH_AUDIT_STRING(record->error == NULL ? "committed" : "rejected");
    AUTH_AUDIT_TEXT(",\"error\":");
    AUTH_AUDIT_STRING(record->error);
    AUTH_AUDIT_TEXT(",\"config_revision\":");
    if (record->error == NULL)
        authenticationserverAuditJsonU64(json, record->revision);
    else
        AUTH_AUDIT_TEXT("null");
    AUTH_AUDIT_TEXT(",\"fields\":[");
    bool comma = false;
    for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i)
    {
        if ((record->fields & (1U << i)) == 0)
            continue;
        if (comma)
            AUTH_AUDIT_TEXT(",");
        AUTH_AUDIT_STRING(fields[i]);
        comma = true;
    }
    if (record->error != NULL)
    {
        AUTH_AUDIT_TEXT("],\"node_suppressed_rejections\":");
        authenticationserverAuditJsonU64(json, record->suppressed_rejections);
        AUTH_AUDIT_TEXT(",\"identity_truncated\":");
    }
    else
        AUTH_AUDIT_TEXT("],\"identity_truncated\":");
    AUTH_AUDIT_TEXT(record->truncated ? "true" : "false");
    AUTH_AUDIT_TEXT("}\n");
#undef AUTH_AUDIT_TEXT
#undef AUTH_AUDIT_STRING
}

static const char *authenticationserverAuditLastError(int error)
{
    switch (error)
    {
    case kAuthenticationServerAuditQueueFull:
        return "queue_full";
    case kAuthenticationServerAuditSequenceExhausted:
        return "sequence_exhausted";
    default:
        return error == kAuthenticationServerAuditErrorNone
                   ? NULL
                   : authenticationserverAuditErrorName((authenticationserver_audit_error_code_t) error);
    }
}

void authenticationserverAuditSnapshot(const authenticationserver_audit_t    *audit,
                                       authenticationserver_audit_snapshot_t *snapshot)
{
    assert(snapshot != NULL);
    *snapshot = (authenticationserver_audit_snapshot_t) {.healthy = true};
    if (audit == NULL)
        return;
    snapshot->enabled               = true;
    snapshot->queued_records        = atomicLoadU64Relaxed(&audit->queued);
    snapshot->written_records       = atomicLoadU64Relaxed(&audit->written);
    snapshot->dropped_records       = atomicLoadU64Relaxed(&audit->dropped);
    snapshot->write_failures        = atomicLoadU64Relaxed(&audit->write_failures);
    snapshot->suppressed_rejections = atomicLoadU64Relaxed(&audit->suppressed);
    snapshot->last_error =
        authenticationserverAuditLastError(atomic_load_explicit(&audit->last_error, memory_order_relaxed));
    snapshot->healthy = ! atomic_load_explicit(&audit->writer_failed, memory_order_acquire) &&
                        snapshot->dropped_records == 0 && snapshot->write_failures == 0;
}

static void authenticationserverAuditSuppress(authenticationserver_audit_t *audit)
{
    /* The queue lock serializes writers of both counters. Readers only load the
     * cumulative atomic; intentional omissions never change audit health. */
    uint64_t total = atomicLoadU64Relaxed(&audit->suppressed);
    if (total != UINT64_MAX)
        atomicStoreU64Relaxed(&audit->suppressed, total + 1U);
    if (audit->pending_suppressed != UINT64_MAX)
        ++audit->pending_suppressed;
}

static void authenticationserverAuditDrop(authenticationserver_audit_t *audit, int error)
{
    atomicAddU64Explicit(&audit->dropped, 1, memory_order_relaxed);
    if (! atomic_load_explicit(&audit->writer_failed, memory_order_relaxed))
        atomic_store_explicit(&audit->last_error, error, memory_order_relaxed);
}

static void authenticationserverAuditReport(authenticationserver_audit_t *audit)
{
    authenticationserver_audit_snapshot_t status;
    authenticationserverAuditSnapshot(audit, &status);
    LOGW("AuthenticationServer: administrative audit degraded: error=%s dropped=%" PRIu64 " write-failures=%" PRIu64,
         status.last_error != NULL ? status.last_error : "unknown",
         status.dropped_records,
         status.write_failures);
}

static WTHREAD_ROUTINE(authenticationserverAuditThread)
{
    authenticationserver_audit_t *audit    = userdata;
    bool                          reported = false;
    for (;;)
    {
        condmutexLock(&audit->lock);
        while (audit->count == 0 && ! audit->stopping)
        {
#ifdef OS_WIN
            bool waited = condvarWait(&audit->wake, &audit->lock) != FALSE;
#else
            bool waited = condvarWait(&audit->wake, &audit->lock) == 0;
#endif
            if (! waited)
            {
                LOGF("AuthenticationServer: audit writer condition wait failed");
                abortProgramNow(1);
            }
        }
        authenticationserver_audit_record_t record;
        if (audit->count == 0)
        {
            if (audit->pending_suppressed == 0)
            {
                condmutexUnlock(&audit->lock);
                break;
            }
            if (audit->sequence == UINT64_MAX)
            {
                authenticationserverAuditDrop(audit, kAuthenticationServerAuditSequenceExhausted);
                condmutexUnlock(&audit->lock);
                break;
            }
            /* Submitters have quiesced. One fixed-storage node-wide summary
             * follows all accepted records, without another queue or root. */
            record                    = (authenticationserver_audit_record_t) {.timestamp_ms          = getTimeOfDayMS(),
                                                                               .sequence              = ++audit->sequence,
                                                                               .operation             = "rejection-summary",
                                                                               .error                 = "suppressed-rejections",
                                                                               .server_summary        = true,
                                                                               .suppressed_rejections = audit->pending_suppressed};
            audit->pending_suppressed = 0;
        }
        else
        {
            record      = audit->records[audit->head];
            audit->head = (audit->head + 1) % kAuthenticationServerAuditQueueCap;
            --audit->count;
            atomicSubU64Explicit(&audit->queued, 1, memory_order_relaxed);
        }
        condmutexUnlock(&audit->lock);

        authenticationserver_audit_json_t json;
        authenticationserverAuditRender(audit, &record, &json);
        authenticationserver_audit_error_t error;
        if (! authenticationserverAuditWriterAppend(audit->writer, json.bytes, json.length, &error))
        {
            atomic_store_explicit(&audit->writer_failed, true, memory_order_release);
            atomic_store_explicit(&audit->last_error, error.code, memory_order_relaxed);
            atomicAddU64Explicit(&audit->write_failures, 1, memory_order_relaxed);
            condmutexLock(&audit->lock);
            atomicAddU64Explicit(&audit->dropped, audit->count + 1, memory_order_relaxed);
            audit->count = 0;
            atomicStoreU64Relaxed(&audit->queued, 0);
            condmutexUnlock(&audit->lock);
            LOGE("AuthenticationServer: audit file operation failed: %s (native=%u)",
                 authenticationserverAuditErrorName(error.code),
                 error.native_error);
            authenticationserverAuditReport(audit);
            reported = true;
            break;
        }
        atomicAddU64Explicit(&audit->written, 1, memory_order_relaxed);
        if (! reported && atomicLoadU64Relaxed(&audit->dropped) != 0)
        {
            authenticationserverAuditReport(audit);
            reported = true;
        }
    }
    authenticationserver_audit_error_t error;
    if (! authenticationserverAuditWriterClose(audit->writer, &error))
    {
        atomic_store_explicit(&audit->last_error, error.code, memory_order_relaxed);
        atomicAddU64Explicit(&audit->write_failures, 1, memory_order_relaxed);
        LOGE("AuthenticationServer: audit file close failed (native=%u)", error.native_error);
        authenticationserverAuditReport(audit);
    }
    else if (! reported && atomicLoadU64Relaxed(&audit->dropped) != 0)
        authenticationserverAuditReport(audit);
    audit->writer = NULL;
    return 0;
}

authenticationserver_audit_t *authenticationserverAuditCreate(const char *path, uint64_t max_file_size,
                                                              unsigned max_files, const char *config, const char *node,
                                                              const uint8_t instance_id[16])
{
    assert(path != NULL && config != NULL && node != NULL && instance_id != NULL);
    if (max_file_size < kAuthenticationServerAuditRecordCap || strlen(config) > kAuthenticationServerAuditLabelCap ||
        strlen(node) > kAuthenticationServerAuditLabelCap)
    {
        LOGE("AuthenticationServer: invalid audit record/file configuration");
        return NULL;
    }
    authenticationserver_audit_error_t   error;
    authenticationserver_audit_writer_t *writer =
        authenticationserverAuditWriterOpen(path, max_file_size, max_files, &error);
    if (writer == NULL)
    {
        LOGE("AuthenticationServer: audit startup failed: %s (native=%u)",
             authenticationserverAuditErrorName(error.code),
             error.native_error);
        return NULL;
    }
    authenticationserver_audit_t *audit = memoryAllocate(sizeof(*audit));
    memoryZero(audit, sizeof(*audit));
    audit->writer = writer;
    atomic_init(&audit->writer_failed, false);
    atomic_init(&audit->queued, 0);
    atomic_init(&audit->written, 0);
    atomic_init(&audit->dropped, 0);
    atomic_init(&audit->write_failures, 0);
    atomic_init(&audit->suppressed, 0);
    atomic_init(&audit->last_error, kAuthenticationServerAuditErrorNone);
    authenticationserverAuditCopyLabel(audit->config, config);
    authenticationserverAuditCopyLabel(audit->node, node);
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 16; ++i)
    {
        audit->instance[2 * i]     = hex[instance_id[i] >> 4U];
        audit->instance[2 * i + 1] = hex[instance_id[i] & 15U];
    }
#ifdef OS_WIN
    bool lock_ready = InitializeCriticalSectionEx(&audit->lock, 0, 0) != FALSE;
    bool wake_ready = lock_ready;
    if (wake_ready)
        condvarInit(&audit->wake);
#else
    bool lock_ready = condmutexInit(&audit->lock) == 0;
    bool wake_ready = lock_ready && condvarInit(&audit->wake) == 0;
#endif
    if (! wake_ready || threadCreate(&audit->thread, authenticationserverAuditThread, audit) != kWThreadErrorNone)
    {
        LOGE("AuthenticationServer: audit synchronization/thread startup failed");
        if (wake_ready)
        {
            contvarDestroy(&audit->wake);
        }
        if (lock_ready)
        {
            condmutexDestroy(&audit->lock);
        }
        authenticationserverAuditWriterClose(writer, &error);
        memoryFree(audit);
        return NULL;
    }
    return audit;
}

void authenticationserverAuditDestroy(authenticationserver_audit_t *audit)
{
    if (audit == NULL)
        return;
    condmutexLock(&audit->lock);
    audit->stopping = true;
    condvarSignal(&audit->wake);
    condmutexUnlock(&audit->lock);
    if (! safeThreadJoin(audit->thread))
    {
        LOGF("AuthenticationServer: cannot join audit writer; its storage remains live");
        abortProgramNow(1);
    }
    contvarDestroy(&audit->wake);
    condmutexDestroy(&audit->lock);
    memoryFree(audit);
}

static void authenticationserverAuditSubmit(authenticationserver_audit_t *audit, bool api, const char *actor,
                                            const char *gateway_config, const char *gateway_node, const char *operation,
                                            uint64_t id, uint64_t revision, uint32_t fields, const char *error)
{
    if (audit == NULL)
        return;
    assert(operation != NULL && (fields & ~((1U << 20U) - 1U)) == 0);
    if (atomic_load_explicit(&audit->writer_failed, memory_order_acquire))
    {
        atomicAddU64Explicit(&audit->dropped, 1, memory_order_relaxed);
        return;
    }
    /* A bounded metadata copy shares this short critical section with dequeue.
     * The writer never holds it while formatting, logging, or touching files. */
    condmutexLock(&audit->lock);
    assert(! audit->stopping); /* Submitters quiesce before destruction. */
    if (atomic_load_explicit(&audit->writer_failed, memory_order_acquire))
        atomicAddU64Explicit(&audit->dropped, 1, memory_order_relaxed);
    else if (audit->sequence == UINT64_MAX)
        authenticationserverAuditDrop(audit, kAuthenticationServerAuditSequenceExhausted);
    else if (error != NULL && (audit->count >= kAuthenticationServerAuditRejectionQueueLimit ||
                               (audit->rejection_sample_seen && (audit->rejection_deadline_exhausted ||
                                                                 getHRTimeUs() / 1000U < audit->next_rejection_ms))))
        authenticationserverAuditSuppress(audit);
    else if (audit->count == kAuthenticationServerAuditQueueCap)
        authenticationserverAuditDrop(audit, kAuthenticationServerAuditQueueFull);
    else
    {
        authenticationserver_audit_record_t *record =
            &audit->records[(audit->head + audit->count) % kAuthenticationServerAuditQueueCap];
        *record = (authenticationserver_audit_record_t) {.timestamp_ms       = getTimeOfDayMS(),
                                                         .sequence           = ++audit->sequence,
                                                         .id                 = id,
                                                         .revision           = revision,
                                                         .fields             = fields,
                                                         .operation          = operation,
                                                         .error              = error,
                                                         .api                = api,
                                                         .has_actor          = actor != NULL,
                                                         .has_gateway_config = gateway_config != NULL,
                                                         .has_gateway_node   = gateway_node != NULL};
        if (error != NULL)
        {
            const uint64_t now                  = getHRTimeUs() / 1000U;
            audit->rejection_sample_seen        = true;
            audit->rejection_deadline_exhausted = now > UINT64_MAX - kAuthenticationServerAuditRejectionIntervalMs;
            audit->next_rejection_ms =
                audit->rejection_deadline_exhausted ? UINT64_MAX : now + kAuthenticationServerAuditRejectionIntervalMs;
            record->suppressed_rejections = audit->pending_suppressed;
            audit->pending_suppressed     = 0;
        }
        record->truncated = authenticationserverAuditCopyLabel(record->actor, actor);
        record->truncated |= authenticationserverAuditCopyLabel(record->gateway_config, gateway_config);
        record->truncated |= authenticationserverAuditCopyLabel(record->gateway_node, gateway_node);
        ++audit->count;
        atomicAddU64Explicit(&audit->queued, 1, memory_order_relaxed);
        condvarSignal(&audit->wake);
    }
    condmutexUnlock(&audit->lock);
}

void authenticationserverAuditRecordApi(authenticationserver_audit_t *audit, const node_api_call_context_t *context,
                                        const char *operation, uint64_t id, uint64_t revision, uint32_t fields,
                                        const char *error)
{
    assert(context != NULL);
    authenticationserverAuditSubmit(audit,
                                    true,
                                    context->principal,
                                    context->gateway_config,
                                    context->gateway_node,
                                    operation,
                                    id,
                                    revision,
                                    fields,
                                    error);
}

void authenticationserverAuditRecordProducer(authenticationserver_audit_t *audit, const char *actor,
                                             const char *operation, uint64_t id, uint64_t revision, uint32_t fields,
                                             const char *error)
{
    authenticationserverAuditSubmit(audit, false, actor, NULL, NULL, operation, id, revision, fields, error);
}
