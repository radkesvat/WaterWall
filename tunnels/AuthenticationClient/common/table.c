#include "internal.h"

#include "loggers/network_logger.h"
#include "node_builder/config_lexical.h"

void authenticationclientDestroyUsers(users_t *users)
{
    if (users != NULL)
    {
        usersDestroy(users);
        memoryFreeAligned(users);
    }
}

static users_t *createUsers(void)
{
    users_t *users = memoryAllocateAligned(sizeof(*users), 32);
    if (! usersCreate(users))
    {
        memoryFreeAligned(users);
        return NULL;
    }
    return users;
}

void authenticationclientDiscardStaging(authenticationclient_tstate_t *ts)
{
    authenticationclientDestroyUsers(ts->staging.users);
    memoryFree(ts->staging.clocks);
    ts->staging = (authenticationclient_staging_t) {0};
}

/* Full diagnostic validation remains available separately. These tables were
 * built by the trusted importer; copying preserves its credential values. */
static users_t *createBaseline(const users_t *src)
{
    users_t *copy = createUsers();
    if (copy != NULL && ! usersCopy(copy, src))
    {
        authenticationclientDestroyUsers(copy);
        return NULL;
    }
    return copy;
}

static bool decimal(const cJSON *json, uint64_t *out)
{
    if (! cJSON_IsString(json) || json->valuestring == NULL)
        return false;
    const char *text = json->valuestring;
    if (*text == '\0' || (text[0] == '0' && text[1] != '\0'))
        return false;
    uint64_t value = 0;
    for (; *text != '\0'; ++text)
    {
        if (*text < '0' || *text > '9' || value > (UINT64_MAX - (uint64_t) (*text - '0')) / 10)
            return false;
        value = value * 10 + (uint64_t) (*text - '0');
    }
    *out = value;
    return true;
}

static bool hexText(const cJSON *json, size_t length)
{
    if (! cJSON_IsString(json) || json->valuestring == NULL || strlen(json->valuestring) != length)
        return false;
    for (size_t i = 0; i < length; ++i)
        if (! ((json->valuestring[i] >= '0' && json->valuestring[i] <= '9') ||
               (json->valuestring[i] >= 'a' && json->valuestring[i] <= 'f')))
            return false;
    return true;
}

static uint64_t hex64(const char *text)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 16; ++i)
        value = (value << 4) | (uint64_t) (text[i] <= '9' ? text[i] - '0' : text[i] - 'a' + 10);
    return value;
}

/* The strict parser has checked syntax and the root schema permits only one
 * array, users. Count its exact object spans, including their internal whitespace,
 * before constructing any additional users. Strings cannot affect nesting. */
static bool recordBytes(const uint8_t *data, size_t length, uint64_t expected, uint64_t *bytes)
{
    size_t   depth = 0, start = 0;
    uint64_t count = 0, total = 0;
    for (size_t i = 0; i < length; ++i)
    {
        const uint8_t c = data[i];
        if (c == '"')
        {
            for (++i; i < length && data[i] != '"'; ++i)
                if (data[i] == '\\')
                    ++i;
        }
        else if (c == '{' || c == '[')
        {
            if (c == '{' && depth == 2)
                start = i;
            ++depth;
        }
        else if (c == '}' || c == ']')
        {
            if (c == '}' && depth == 3)
            {
                total += i - start + 1;
                ++count;
            }
            --depth;
        }
    }
    *bytes = total;
    return count == expected;
}

static bool appendClock(authenticationclient_staging_t *stage, size_t position, size_t count, uint64_t server,
                        uint64_t accounting, uint64_t received)
{
    if (stage->clock_count == stage->clock_capacity)
    {
        size_t capacity = stage->clock_capacity == 0 ? 8 : stage->clock_capacity * 2, bytes;
        if (capacity < stage->clock_capacity || ! memoryTryComputeArraySize(capacity, sizeof(*stage->clocks), &bytes))
            return false;
        stage->clocks         = memoryReAllocate(stage->clocks, bytes);
        stage->clock_capacity = capacity;
    }
    stage->clocks[stage->clock_count++] = (authenticationclient_page_clock_t) {.position           = position,
                                                                               .count              = count,
                                                                               .server_time_ms     = server,
                                                                               .accounting_time_ms = accounting,
                                                                               .received_at_ms     = received};
    return true;
}

bool authenticationclientSendUsersPage(tunnel_t *t)
{
    authenticationclient_tstate_t  *ts    = tunnelGetState(t);
    authenticationclient_staging_t *stage = &ts->staging;
    if (! stage->active)
    {
        stage->users = createUsers();
        if (stage->users == NULL)
            return false;
        stage->active = true;
        mutexLock(&ts->control_mutex);
        ts->pull_required = true;
        mutexUnlock(&ts->control_mutex);
    }
    char digest[65] = {0};
    asciiHexEncodeBytesLower(ts->last_ack_digest, sizeof(ts->last_ack_digest), (uint8_t *) digest);
    cJSON  *request = cJSON_CreateObject();
    discard cJSON_AddStringToObject(request, "epoch", ts->accounting_epoch);
    char    sequence[24];
    snprintf(sequence, sizeof(sequence), "%" PRIu64, ts->last_ack_sequence);
    discard cJSON_AddStringToObject(request, "sequence", sequence);
    discard cJSON_AddStringToObject(request, "digest", digest);
    if (stage->cursor[0] != '\0')
    {
        discard cJSON_AddStringToObject(request, "cursor", stage->cursor);
        char    total[24];
        snprintf(total, sizeof(total), "%" PRIu64, stage->total);
        discard cJSON_AddStringToObject(request, "total", total);
        if (stage->complete)
            discard cJSON_AddBoolToObject(request, "validate", true);
    }
    char *text = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    const bool sent = authenticationclientSendRequest(
        t, kAuthenticationClientRequestTypeGetUsersPage, (const uint8_t *) text, (uint32_t) strlen(text));
    cJSON_free(text);
    return sent;
}

/* users_lock pins the current active values throughout preparation and commit.
 * Missing accounts with known debt/observations are a refusal, never a prune. */
static bool mergeCurrentTraffic(authenticationclient_tstate_t *ts, users_t *dest)
{
    for (size_t i = 0; i < usersCount(ts->users); ++i)
    {
        user_accounting_snapshot_t current;
        userGetAccountingSnapshot(usersGetAt(ts->users, i), &current);
        user_stat_t baseline = {0};
        user_t     *base     = usersLookupByIdentifier(ts->sync_baseline_users, current.id);
        if (base != NULL)
            userGetStats(base, &baseline);
        const uint64_t upload   = authenticationclientCounterDelta(current.traffic.u, baseline.traffic.u);
        const uint64_t download = authenticationclientCounterDelta(current.traffic.d, baseline.traffic.d);
        if (upload == 0 && download == 0 && ! current.observation_pending)
            continue;
        if (usersLookupByIdentifier(dest, current.id) == NULL ||
            usersAddTrafficByIdentifier(dest, current.id, upload, download) != kUsersUpdateResultOk)
            return false;
    }
    for (size_t i = 0; i < ts->catchup_entries_count; ++i)
    {
        const authenticationclient_accounting_entry_t *owed = &ts->catchup_entries[i];
        if ((owed->delta.u != 0 || owed->delta.d != 0 || owed->first_usage_at_ms != 0) &&
            usersLookupByIdentifier(dest, owed->id) == NULL)
            return false;
    }
    return true;
}

static bool installStaging(tunnel_t *t, uint64_t generation)
{
    authenticationclient_tstate_t  *ts    = tunnelGetState(t);
    authenticationclient_staging_t *stage = &ts->staging;
    if (usersCount(stage->users) != stage->total || ! usersValidateStructure(stage->users))
        return false;
    size_t covered = 0;
    for (size_t i = 0; i < stage->clock_count; ++i)
    {
        if (stage->clocks[i].position != covered || stage->clocks[i].count > stage->total - covered)
            return false;
        covered += stage->clocks[i].count;
    }
    if (covered != stage->total)
        return false;
    users_t *baseline = createBaseline(stage->users);
    if (baseline == NULL)
        return false;
    rwlockWriteLock(&ts->users_lock);
    if (! mergeCurrentTraffic(ts, stage->users))
    {
        rwlockWriteUnlock(&ts->users_lock);
        authenticationclientDestroyUsers(baseline);
        return false;
    }
    users_t *old = ts->users, *old_baseline = ts->sync_baseline_users;
    /* All fallible work is complete. Migration cannot refuse initialized tables. */
    if (! usersMigrateRuntimeStateByIdentifier(stage->users, old))
    {
        LOGF("AuthenticationClient: invalid runtime migration state");
        abortProgramNow(1);
    }
    /* Migration replaces clocks; reproject with EACH page's original receipt. */
    for (size_t i = 0; i < stage->clock_count; ++i)
    {
        const authenticationclient_page_clock_t *clock = &stage->clocks[i];
        for (size_t j = 0; j < clock->count; ++j)
            userInstallClientClock(usersGetAt(stage->users, clock->position + j),
                                   clock->server_time_ms,
                                   clock->accounting_time_ms,
                                   clock->received_at_ms);
    }
    usersResetFirstUsagePushRequests(stage->users);
    ts->users               = stage->users;
    stage->users            = NULL;
    ts->sync_baseline_users = baseline;
    ++ts->users_generation;
    ts->local_config_revision     = stage->config_revision;
    ts->local_stats_revision      = stage->stats_revision; /* First-page conservative sample. */
    ts->local_revision_generation = generation;
    ts->users_loaded = ts->clock_loaded = true;
    rwlockWriteUnlock(&ts->users_lock);
    const size_t installed_count = stage->total;
    authenticationclientDiscardStaging(ts);
    mutexLock(&ts->control_mutex);
    ts->pull_required              = false;
    ts->first_usage_push_requested = false;
    ts->first_usage_push_deferred  = false;
    ts->last_pull_success_ms       = authenticationclientLocalTimeMS();
    ts->last_pull_success_valid    = true;
    authenticationclientResetSyncRetryLocked(ts);
    mutexUnlock(&ts->control_mutex);
    authenticationclientDestroyUsers(old);
    authenticationclientDestroyUsers(old_baseline);
    if (ts->catchup_capture_needed)
        discard authenticationclientCaptureCatchup(t);
    LOGI("AuthenticationClient: pulled %zu users from server", installed_count);
    return true;
}

authenticationclient_failure_t authenticationclientAcceptUsersPage(tunnel_t *t, const uint8_t *data, uint32_t length,
                                                                   uint64_t config_revision, uint64_t stats_revision,
                                                                   uint64_t generation, uint64_t received_at_ms)
{
    authenticationclient_tstate_t  *ts     = tunnelGetState(t);
    authenticationclient_staging_t *stage  = &ts->staging;
    authenticationclient_failure_t  result = kAuthenticationClientFailureInvalidResponse;
    cJSON                          *json   = configLexicalParseQuiet((const char *) data, length, 10);
    if (! cJSON_IsObject(json) || ! stage->active)
        goto done;
    static const char *const keys[] = {"instance",
                                       "config-revision",
                                       "stats-revision",
                                       "total",
                                       "position",
                                       "count",
                                       "cursor",
                                       "complete",
                                       "validated",
                                       "epoch",
                                       "sequence",
                                       "digest",
                                       "server-time-ms",
                                       "accounting-time-ms",
                                       "users"};
    size_t                   fields = 0;
    for (const cJSON *field = json->child; field != NULL; field = field->next)
    {
        bool known = false;
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
            known |= strcmp(field->string, keys[i]) == 0;
        if (! known)
            goto done;
        ++fields;
    }
    if (fields != sizeof(keys) / sizeof(keys[0]))
        goto done;
#define FIELD(name) cJSON_GetObjectItemCaseSensitive(json, name)
    uint64_t     config, stats, total, position, count, sequence, server_time, accounting_time;
    const cJSON *instance = FIELD("instance"), *cursor = FIELD("cursor"), *epoch = FIELD("epoch"),
                *digest = FIELD("digest"), *users = FIELD("users");
    if (! decimal(FIELD("config-revision"), &config) || config != config_revision ||
        ! decimal(FIELD("stats-revision"), &stats) || stats != stats_revision || ! decimal(FIELD("total"), &total) ||
        ! decimal(FIELD("position"), &position) || ! decimal(FIELD("count"), &count) ||
        ! decimal(FIELD("sequence"), &sequence) || ! decimal(FIELD("server-time-ms"), &server_time) ||
        ! decimal(FIELD("accounting-time-ms"), &accounting_time) || accounting_time == 0 || ! hexText(instance, 32) ||
        ! hexText(cursor, 64) || ! hexText(epoch, 64) || ! hexText(digest, 64) || ! cJSON_IsBool(FIELD("complete")) ||
        ! cJSON_IsBool(FIELD("validated")) || ! cJSON_IsArray(users))
        goto done;
    char expected_digest[65] = {0};
    asciiHexEncodeBytesLower(ts->last_ack_digest, sizeof(ts->last_ack_digest), (uint8_t *) expected_digest);
    if (strcmp(epoch->valuestring, ts->accounting_epoch) != 0 || sequence != ts->last_ack_sequence ||
        strcmp(digest->valuestring, expected_digest) != 0)
    {
        result = kAuthenticationClientFailureContinuity;
        goto done;
    }
    if (total > ts->sync_max_users || total > SIZE_MAX)
    {
        result = kAuthenticationClientFailureSyncLimit;
        goto done;
    }
    const bool first    = stage->cursor[0] == '\0';
    const bool complete = cJSON_IsTrue(FIELD("complete")), validated = cJSON_IsTrue(FIELD("validated"));
    if (position != stage->position || position > total || count > total - position ||
        count > kAuthenticationUsersPageMaxUsers || (uint64_t) cJSON_GetArraySize(users) != count ||
        complete != (position + count == total) || strncmp(cursor->valuestring, instance->valuestring, 32) != 0 ||
        hex64(cursor->valuestring + 32) != config || hex64(cursor->valuestring + 48) != position + count ||
        (! first && (strcmp(instance->valuestring, stage->instance) != 0 || config != stage->config_revision ||
                     total != stage->total)) ||
        validated != stage->complete || (validated && (count != 0 || ! complete)) ||
        (! validated && count == 0 && total != 0))
        goto done;
    uint64_t bytes;
    if (! recordBytes(data, length, count, &bytes))
        goto done;
    if (stage->encoded_bytes > ts->sync_max_bytes || bytes > ts->sync_max_bytes - stage->encoded_bytes)
    {
        result = kAuthenticationClientFailureSyncLimit;
        goto done;
    }
    if (validated)
    {
        if (strcmp(cursor->valuestring, stage->cursor) != 0 || ! installStaging(t, generation))
            goto done;
    }
    else
    {
        if (! usersFeedJsonRequiredIds(stage->users, users) ||
            ! appendClock(stage, (size_t) position, (size_t) count, server_time, accounting_time, received_at_ms))
            goto done;
        if (first)
        {
            stage->total           = total;
            stage->config_revision = config;
            stage->stats_revision  = stats;
            memoryCopy(stage->instance, instance->valuestring, sizeof(stage->instance));
        }
        stage->position += count;
        stage->encoded_bytes += bytes;
        stage->complete = complete;
        memoryCopy(stage->cursor, cursor->valuestring, sizeof(stage->cursor));
    }
    result = kAuthenticationClientFailureNone;
#undef FIELD
done:
    cJSON_Delete(json);
    return result;
}
