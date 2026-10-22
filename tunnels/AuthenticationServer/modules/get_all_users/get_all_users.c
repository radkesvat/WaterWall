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
    const size_t total = usersCount(&ts->store.users);
    if (cursor_json != NULL)
    {
        uint64_t supplied_total;
        error = "invalid_cursor";
        if (! cJSON_IsString(cursor_json) || cursor_json->valuestring == NULL ||
            ! authenticationserverApiCursorDecode(cursor_json->valuestring, &cursor) ||
            ! pageUnsigned(request, "total", &supplied_total))
            goto refused;
        if (memcmp(cursor.instance_id, ts->api_instance_id, 16) != 0 || cursor.revision != ts->store.config_revision)
        {
            error = "stale_cursor";
            goto refused;
        }
        if (supplied_total != total || cursor.position > total ||
            (validate ? cursor.position != total : cursor.position == total))
            goto refused;
    }
    authenticationserver_page_view_t view = {
        .config_revision = ts->store.config_revision, .position = (size_t) cursor.position, .total = total};
    memoryCopy(view.instance_id, ts->api_instance_id, sizeof(view.instance_id));
    char              instance[33], digest_text[65];
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; ++i)
    {
        instance[2 * i]     = hex[ts->api_instance_id[i] >> 4];
        instance[2 * i + 1] = hex[ts->api_instance_id[i] & 15];
    }
    instance[32] = 0;
    for (size_t i = 0; i < sizeof(checkpoint->last_digest); ++i)
    {
        digest_text[2 * i]     = hex[checkpoint->last_digest[i] >> 4];
        digest_text[2 * i + 1] = hex[checkpoint->last_digest[i] & 15];
    }
    digest_text[64]    = 0;
    page               = createPageMetadata(instance,
                              epoch->valuestring,
                              digest_text,
                              checkpoint->last_sequence,
                              ts->store.config_revision,
                              ts->store.stats_revision,
                              getTimeOfDayMS(),
                              authenticationserverAccountingTimeMS(ts),
                              total,
                              view.position);
    cJSON       *users = cJSON_GetObjectItemCaseSensitive(page, "users");
    const size_t hard  = kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize;
    size_t       count = 0, row_bytes = 0;
    while (! validate && view.position + count < total && count < kAuthenticationUsersPageMaxUsers)
    {
        pagePosition(page, &view, count + 1, false);
        /* Measure metadata without constructing the next user's owned strings. */
        cJSON  *empty = cJSON_CreateArray();
        discard cJSON_DetachItemFromObjectCaseSensitive(page, "users");
        discard cJSON_AddItemToObject(page, "users", empty);
        text                  = cJSON_PrintUnformatted(page);
        const size_t overhead = strlen(text) + count; /* Between-row commas. */
        cJSON_free(text);
        text = NULL;
        /* Restore ownership of previously admitted rows after metadata measuring. */
        discard cJSON_DetachItemFromObjectCaseSensitive(page, "users");
        cJSON_Delete(empty);
        discard      cJSON_AddItemToObject(page, "users", users);
        const size_t target = kAuthenticationUsersPageTargetBytes - kAuthenticationServerResponseEnvelopeHeaderSize -
                              kAuthenticationServerResponseHeaderSize;
        const size_t         allowance = overhead + row_bytes < target ? target - overhead - row_bytes : 0;
        cJSON               *row       = NULL;
        size_t               encoded   = 0;
        user_public_result_t result =
            usersCopyFullUserJsonAt(&ts->store.users, view.position + count, allowance, &row, &encoded);
        if (count == 0 && result == kUserPublicTooLarge && overhead < hard)
            result = usersCopyFullUserJsonAt(&ts->store.users, view.position, hard - overhead, &row, &encoded);
        if (result == kUserPublicTooLarge && count != 0)
            break;
        if (result != kUserPublicOk)
        {
            error = result == kUserPublicTooLarge ? "user-too-large" : "invalid-user-record";
            goto refused;
        }
        discard cJSON_AddItemToArray(users, row);
        row_bytes += encoded;
        ++count;
        if (overhead + row_bytes > target)
            break; /* Exceptional first row. */
    }
    pagePosition(page, &view, count, validate);
    text = authenticationserverSerializeResponseJson(page);
    if (text == NULL)
    {
        error = "user-too-large";
        goto refused;
    }
    sbuf_t *response = authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeUsers, correlation_id, (const uint8_t *) text, (uint32_t) strlen(text));
    authenticationserverWipeJsonStrings(page);
    cJSON_Delete(page);
    cJSON_Delete(request);
    memorySecureZero(text, strlen(text));
    cJSON_free(text);
    return response;
refused:
    authenticationserverWipeJsonStrings(page);
    cJSON_Delete(page);
    cJSON_Delete(request);
    if (text != NULL)
    {
        memorySecureZero(text, strlen(text));
        cJSON_free(text);
    }
    return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
}
