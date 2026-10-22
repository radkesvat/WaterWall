#include "modules/get_all_users/get_all_users.h"
#include "AuthenticationServer/api.h"

static void pageNumber(cJSON *json, const char *key, uint64_t number)
{
    char text[24];
    snprintf(text, sizeof(text), "%" PRIu64, number);
    cJSON_DeleteItemFromObjectCaseSensitive(json, key);
    discard cJSON_AddStringToObject(json, key, text);
}

static void pagePosition(cJSON *json, const authenticationserver_page_view_t *view, size_t count, bool validated)
{
    char cursor[65];
    authenticationserverApiCursor(view, count, cursor);
    pageNumber(json, "count", count);
    cJSON_DeleteItemFromObjectCaseSensitive(json, "cursor");
    discard cJSON_AddStringToObject(json, "cursor", cursor);
    cJSON_DeleteItemFromObjectCaseSensitive(json, "complete");
    discard cJSON_AddBoolToObject(json, "complete", view->position + count == view->total);
    cJSON_DeleteItemFromObjectCaseSensitive(json, "validated");
    discard cJSON_AddBoolToObject(json, "validated", validated);
}

static bool pageUnsigned(const cJSON *json, const char *key, uint64_t *number)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    return cJSON_IsString(item) && authenticationserverApiUnsignedDecimal(item->valuestring, number);
}

/* Shared by admission geometry and real responses. Each changing number is
 * represented as an exact decimal string; the synthetic page reserves its
 * maximum width even when a live page currently uses a shorter value. */
static cJSON *createPageMetadata(const char *instance, const char *epoch, const char *digest, uint64_t sequence,
                                 uint64_t config, uint64_t stats, uint64_t wall, uint64_t accounting, uint64_t total,
                                 uint64_t position)
{
    cJSON  *page = cJSON_CreateObject();
    discard cJSON_AddStringToObject(page, "instance", instance);
    discard cJSON_AddStringToObject(page, "epoch", epoch);
    discard cJSON_AddStringToObject(page, "digest", digest);
    pageNumber(page, "sequence", sequence);
    pageNumber(page, "config-revision", config);
    pageNumber(page, "stats-revision", stats);
    pageNumber(page, "server-time-ms", wall);
    pageNumber(page, "accounting-time-ms", accounting);
    pageNumber(page, "total", total);
    pageNumber(page, "position", position);
    pageNumber(page, "count", 0);
    char cursor[65];
    memset(cursor, 'f', 64);
    cursor[64] = 0;
    discard cJSON_AddStringToObject(page, "cursor", cursor);
    discard cJSON_AddBoolToObject(page, "complete", false);
    discard cJSON_AddBoolToObject(page, "validated", false);
    discard cJSON_AddArrayToObject(page, "users");
    return page;
}

void authenticationserverInitializeExportLimit(authenticationserver_tstate_t *ts)
{
    char instance[33], token[65];
    memset(instance, 'f', sizeof(instance) - 1);
    memset(token, 'f', sizeof(token) - 1);
    instance[sizeof(instance) - 1] = token[sizeof(token) - 1] = 0;
    cJSON *page                                               = createPageMetadata(
        instance, token, token, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX);
    pageNumber(page, "count", UINT64_MAX);
    char        *text     = cJSON_PrintUnformatted(page);
    const size_t overhead = strlen(text);
    const size_t data_cap = kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize;
    assert(overhead < data_cap);
    ts->max_user_export_bytes = data_cap - overhead;
    cJSON_free(text);
    cJSON_Delete(page);
}

/* One immutable encoded table may be shared by sessions that acquire the same
 * configuration and accounting revision. Only session references retain it. */
struct authenticationserver_snapshot_s
{
    size_t   refs, count, charge, capacity;
    size_t  *offsets;
    char    *rows;
    uint64_t config_revision, stats_revision;
};

void authenticationserverSnapshotRelease(authenticationserver_tstate_t *ts, authenticationserver_session_t *session)
{
    authenticationserver_snapshot_t *snapshot = session->snapshot;
    if (snapshot == NULL)
        return;
    session->snapshot = NULL;
    assert(snapshot->refs != 0);
    if (--snapshot->refs != 0)
        return;
    assert(ts->snapshot_bytes >= snapshot->charge);
    ts->snapshot_bytes -= snapshot->charge;
    memorySecureZero(snapshot->rows, snapshot->capacity);
    memoryFree(snapshot->rows);
    memoryFree(snapshot->offsets);
    memoryFree(snapshot);
}

void authenticationserverSnapshotsExpire(authenticationserver_tstate_t *ts, uint64_t now_ms)
{
    const uint64_t timeout = ts->snapshot_idle_timeout_ms != 0 ? ts->snapshot_idle_timeout_ms
                                                               : kAuthenticationServerDefaultSnapshotIdleTimeoutMs;
    for (uint32_t i = 0; i < ts->sessions_count; ++i)
    {
        authenticationserver_session_t *session = ts->sessions[i];
        if (session->snapshot != NULL && now_ms - session->snapshot_last_page_ms >= timeout)
            authenticationserverSnapshotRelease(ts, session);
    }
}

static const char *acquireSnapshot(authenticationserver_tstate_t *ts, authenticationserver_session_t *session)
{
    authenticationserverSnapshotRelease(ts, session);
    for (uint32_t i = 0; i < ts->sessions_count; ++i)
    {
        authenticationserver_snapshot_t *other = ts->sessions[i]->snapshot;
        if (other != NULL && other->config_revision == ts->store.config_revision &&
            other->stats_revision == ts->store.stats_revision)
        {
            ++other->refs;
            session->snapshot          = other;
            session->snapshot_sequence = session->accounting_client->last_sequence;
            return NULL;
        }
    }
    const size_t maximum =
        ts->snapshot_max_bytes != 0 ? ts->snapshot_max_bytes : kAuthenticationServerDefaultSnapshotMaxBytes;
    const size_t count = usersCount(&ts->store.users);
    size_t       offsets_bytes;
    if (count == SIZE_MAX || ! memoryTryComputeArraySize(count + 1U, sizeof(size_t), &offsets_bytes) ||
        ts->snapshot_bytes > maximum || sizeof(authenticationserver_snapshot_t) > maximum - ts->snapshot_bytes ||
        offsets_bytes > maximum - ts->snapshot_bytes - sizeof(authenticationserver_snapshot_t))
        return "snapshot-resource-limit";
    size_t available = maximum - ts->snapshot_bytes - sizeof(authenticationserver_snapshot_t) - offsets_bytes;
    size_t capacity = 0, largest_row = 0;
    for (size_t i = 0; i < count; ++i)
    {
        size_t size;
        if (userMeasureExportUpperBound(usersGetAtConst(&ts->store.users, i), &size) != kUserPublicOk)
            return "invalid-user-record";
        if (size > ts->max_user_export_bytes)
            return "user-too-large";
        /* cJSON's preallocated printer needs five spare bytes. Every stored
         * row keeps one NUL; reserve all five so no row can overlap capacity. */
        if (size > available || available - size < 5U)
            return "snapshot-resource-limit";
        capacity += size + 5U;
        available -= size + 5U;
        largest_row = max(largest_row, size);
    }
    /* Full user JSON has fewer than 128 fixed nodes/keys. The scalar-only
     * measurement printer and key storage fit in 16 KiB; arbitrary copied
     * strings are bounded by the row's encoded upper bound. The row prints
     * directly into final storage, without a second table or blob allocation. */
    const size_t fixed_scratch = 128U * sizeof(cJSON) + 16384U;
    if (largest_row > available || fixed_scratch > available - largest_row)
        return "snapshot-resource-limit";
    const size_t scratch = fixed_scratch + largest_row;
    const size_t charge  = sizeof(authenticationserver_snapshot_t) + offsets_bytes + capacity;
    ts->snapshot_bytes += charge + scratch;
    authenticationserver_snapshot_t *snapshot = memoryAllocateZero(sizeof(*snapshot));
    *snapshot                                 = (authenticationserver_snapshot_t) {.refs            = 1,
                                                                                   .count           = count,
                                                                                   .charge          = charge,
                                                                                   .capacity        = capacity,
                                                                                   .offsets         = memoryAllocate(offsets_bytes),
                                                                                   .rows            = capacity != 0 ? memoryAllocate(capacity) : NULL,
                                                                                   .config_revision = ts->store.config_revision,
                                                                                   .stats_revision  = ts->store.stats_revision};
    session->snapshot                         = snapshot;
    session->snapshot_sequence                = session->accounting_client->last_sequence;
    size_t      used                          = 0;
    const char *error                         = NULL;
    for (size_t i = 0; i < count; ++i)
    {
        cJSON                     *row = NULL;
        size_t                     encoded;
        const user_public_result_t result =
            usersCopyFullUserJsonAt(&ts->store.users, i, ts->max_user_export_bytes, &row, &encoded);
        if (result != kUserPublicOk)
        {
            error = result == kUserPublicTooLarge ? "user-too-large" : "invalid-user-record";
            break;
        }
        assert(encoded + 5U <= capacity - used && encoded + 5U <= INT_MAX);
        const bool printed = cJSON_PrintPreallocated(row, snapshot->rows + used, (int) (encoded + 5U), false);
        authenticationserverWipeJsonStrings(row);
        cJSON_Delete(row);
        if (! printed)
        {
            error = "invalid-user-record";
            break;
        }
        snapshot->offsets[i] = used;
        used += encoded + 1U;
    }
    snapshot->offsets[count] = used;
    ts->snapshot_bytes -= scratch;
    if (error != NULL)
        authenticationserverSnapshotRelease(ts, session);
    return error;
}

sbuf_t *authenticationserverGetAllUsersHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                              tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                              const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts      = tunnelGetState(t);
    const char                    *error   = "invalid-users-page-request";
    cJSON                         *request = NULL, *page = NULL;
    char                          *text = NULL;
    if (request_data_len == 0 || request_data_len > 1024)
        goto refused;
    request = configLexicalParseBoundedQuiet((const char *) request_data, request_data_len, 2, 16);
    if (! cJSON_IsObject(request))
        goto refused;
    for (const cJSON *field = request->child; field != NULL; field = field->next)
        if (strcmp(field->string, "epoch") != 0 && strcmp(field->string, "sequence") != 0 &&
            strcmp(field->string, "digest") != 0 && strcmp(field->string, "cursor") != 0 &&
            strcmp(field->string, "total") != 0 && strcmp(field->string, "validate") != 0)
            goto refused;
    const cJSON *epoch  = cJSON_GetObjectItemCaseSensitive(request, "epoch");
    const cJSON *digest = cJSON_GetObjectItemCaseSensitive(request, "digest");
    uint64_t     sequence;
    uint8_t      decoded[SHA256_DIGEST_SIZE];
    if (! cJSON_IsString(epoch) || epoch->valuestring == NULL || strlen(epoch->valuestring) != 64 ||
        ! cJSON_IsString(digest) || digest->valuestring == NULL || strlen(digest->valuestring) != 64 ||
        ! asciiHexDecodeBytes((const uint8_t *) digest->valuestring, 64, decoded, sizeof(decoded)) ||
        ! pageUnsigned(request, "sequence", &sequence))
        goto refused;
    authenticationserver_auth_client_t *checkpoint = session->accounting_client;
    if (memcmp(epoch->valuestring, checkpoint->accounting_epoch, 64) != 0 || sequence != checkpoint->last_sequence ||
        ! wCryptoEqual(decoded, checkpoint->last_digest, sizeof(decoded)))
    {
        error = "accounting-continuity-lost";
        goto refused;
    }
    authenticationserver_api_request_t cursor      = {0};
    const cJSON                       *cursor_json = cJSON_GetObjectItemCaseSensitive(request, "cursor");
    const cJSON                       *total_json  = cJSON_GetObjectItemCaseSensitive(request, "total");
    const cJSON                       *validation  = cJSON_GetObjectItemCaseSensitive(request, "validate");
    const bool                         validate    = validation != NULL && cJSON_IsTrue(validation);
    if (validation != NULL && ! cJSON_IsTrue(validation))
        goto refused;
    if ((cursor_json == NULL) != (total_json == NULL) || (validate && cursor_json == NULL))
        goto refused;
    const uint64_t now_ms = getHRTimeUs() / 1000U;
    authenticationserverSnapshotsExpire(ts, now_ms);
    if (cursor_json != NULL)
    {
        uint64_t supplied_total;
        error = "invalid_cursor";
        if (! cJSON_IsString(cursor_json) || cursor_json->valuestring == NULL ||
            ! authenticationserverApiCursorDecode(cursor_json->valuestring, &cursor) ||
            ! pageUnsigned(request, "total", &supplied_total))
            goto refused;
        if (session->snapshot == NULL || memcmp(cursor.instance_id, ts->api_instance_id, 16) != 0 ||
            cursor.revision != session->snapshot->config_revision || session->snapshot_sequence != sequence)
        {
            error = "stale_cursor";
            goto refused;
        }
        const size_t total = session->snapshot->count;
        if (supplied_total != total || cursor.position > total ||
            (validate ? cursor.position != total : cursor.position == total))
            goto refused;
    }
    else if ((error = acquireSnapshot(ts, session)) != NULL)
        goto refused;

    authenticationserver_snapshot_t *snapshot = session->snapshot;
    session->snapshot_last_page_ms            = getHRTimeUs() / 1000U;
    authenticationserver_page_view_t view     = {
            .config_revision = snapshot->config_revision, .position = (size_t) cursor.position, .total = snapshot->count};
    memoryCopy(view.instance_id, ts->api_instance_id, sizeof(view.instance_id));
    char instance[33], digest_text[65];
    asciiHexEncodeBytesLower(ts->api_instance_id, sizeof(ts->api_instance_id), (uint8_t *) instance);
    instance[32] = 0;
    asciiHexEncodeBytesLower(checkpoint->last_digest, sizeof(checkpoint->last_digest), (uint8_t *) digest_text);
    digest_text[64] = 0;
    page            = createPageMetadata(instance,
                              epoch->valuestring,
                              digest_text,
                              checkpoint->last_sequence,
                              snapshot->config_revision,
                              snapshot->stats_revision,
                              getTimeOfDayMS(),
                              authenticationserverAccountingTimeMS(ts),
                              snapshot->count,
                              view.position);
    /* Reserve maximum-width count/cursor metadata once, then append the stored
     * rows directly to a bounded frame. No row strings or JSON trees are copied. */
    pageNumber(page, "count", UINT64_MAX);
    text                  = cJSON_PrintUnformatted(page);
    const size_t overhead = strlen(text);
    cJSON_free(text);
    text                = NULL;
    const size_t hard   = kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize;
    const size_t target = kAuthenticationUsersPageTargetBytes - kAuthenticationServerResponseEnvelopeHeaderSize -
                          kAuthenticationServerResponseHeaderSize;
    size_t count = 0, row_bytes = 0;
    while (! validate && view.position + count < snapshot->count && count < kAuthenticationUsersPageMaxUsers)
    {
        const size_t index   = view.position + count;
        const size_t encoded = snapshot->offsets[index + 1U] - snapshot->offsets[index] - 1U;
        const size_t added   = encoded + (count != 0);
        if (overhead > hard || added > hard - overhead - row_bytes)
        {
            if (count != 0)
                break;
            error = "user-too-large";
            goto refused;
        }
        if (count != 0 && overhead + row_bytes + added > target)
            break;
        row_bytes += added;
        ++count;
    }
    pagePosition(page, &view, count, validate);
    text              = cJSON_PrintUnformatted(page);
    const char *array = strstr(text, "\"users\":[]");
    assert(array != NULL);
    const size_t prefix        = (size_t) (array + strlen("\"users\":[") - text);
    const size_t metadata_size = strlen(text);
    const size_t length        = metadata_size + row_bytes;
    assert(length <= hard);
    sbuf_t *response =
        authenticationserverCreateResponseFrame(l, kAuthenticationServerResponseTypeUsers, correlation_id, NULL, 0);
    response = sbufReserveSpace(response, (uint32_t) length + kAuthenticationServerResponseHeaderSize);
    sbufSetLength(response, (uint32_t) length + kAuthenticationServerResponseHeaderSize);
    const uint32_t network_length = htonl((uint32_t) length);
    memoryCopy(sbufGetMutablePtr(response) + 1 + kAuthenticationServerCorrelationIdSize, &network_length, 4);
    uint8_t *output = sbufGetMutablePtr(response) + kAuthenticationServerResponseHeaderSize;
    memoryCopy(output, text, prefix);
    size_t used = prefix;
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
            output[used++] = ',';
        const size_t index = view.position + i;
        const size_t size  = snapshot->offsets[index + 1U] - snapshot->offsets[index] - 1U;
        memoryCopy(output + used, snapshot->rows + snapshot->offsets[index], size);
        used += size;
    }
    memoryCopy(output + used, text + prefix, metadata_size - prefix);
    cJSON_Delete(page);
    cJSON_Delete(request);
    cJSON_free(text);
    if (validate)
        authenticationserverSnapshotRelease(ts, session);
    return response;
refused:
    cJSON_Delete(page);
    cJSON_Delete(request);
    cJSON_free(text);
    return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
}
