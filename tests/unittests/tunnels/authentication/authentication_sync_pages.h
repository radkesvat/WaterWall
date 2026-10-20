/* Included by authentication_sync_test.c after the paired transport helpers. */
typedef enum auth_page_fault_e
{
    kAuthPageFaultNone,
    kAuthPageFaultMissingCount,
    kAuthPageFaultRepeatedPosition,
    kAuthPageFaultSkippedPosition,
    kAuthPageFaultWrongInstance,
    kAuthPageFaultDuplicateId,
    kAuthPageFaultDuplicateCredential,
    kAuthPageFaultCheckpoint,
    kAuthPageFaultCorrelation
} auth_page_fault_t;

static auth_page_fault_t auth_page_fault;
static uint64_t          auth_page_fault_position;
static sbuf_t           *auth_page_original;

static void authPageSetText(cJSON *json, const char *key, const char *text)
{
    require(cJSON_ReplaceItemInObjectCaseSensitive(json, key, cJSON_CreateString(text)),
            "page fault could not replace a string field");
}

static sbuf_t *authPageResponseFault(sbuf_t *buffer)
{
    if (auth_page_fault == kAuthPageFaultNone || sbufGetLength(buffer) < 29 ||
        ((const uint8_t *) sbufGetRawPtr(buffer))[20] != kAuthenticationClientResponseTypeUsers)
        return buffer;
    cJSON   *json = cJSON_ParseWithLength((const char *) sbufGetRawPtr(buffer) + 29, sbufGetLength(buffer) - 29);
    uint64_t position;
    require(json != NULL && getUint64FromJson(&position, cJSON_GetObjectItemCaseSensitive(json, "position")),
            "page fault source lacks an exact position");
    if (position != auth_page_fault_position)
    {
        cJSON_Delete(json);
        return buffer;
    }
    const auth_page_fault_t fault = auth_page_fault;
    auth_page_fault               = kAuthPageFaultNone;
    if (fault == kAuthPageFaultCorrelation)
    {
        require(auth_page_original == NULL, "page fault overwrote an owned original response");
        auth_page_original = sbufDuplicate(buffer);
        /* Zero never names a live request; keep a valid body and envelope. */
        const uint32_t correlation = 0;
        memoryCopy(sbufGetMutablePtr(buffer) + 21, &correlation, sizeof(correlation));
        cJSON_Delete(json);
        return buffer;
    }
    cJSON *rows = cJSON_GetObjectItemCaseSensitive(json, "users");
    cJSON *row  = cJSON_GetArrayItem(rows, 0);
    switch (fault)
    {
    case kAuthPageFaultMissingCount:
        cJSON_DeleteItemFromObjectCaseSensitive(json, "count");
        break;
    case kAuthPageFaultRepeatedPosition:
        authPageSetText(json, "position", "0");
        break;
    case kAuthPageFaultSkippedPosition:
        authPageSetText(json, "position", "129");
        break;
    case kAuthPageFaultWrongInstance: {
        cJSON *instance = cJSON_GetObjectItemCaseSensitive(json, "instance");
        cJSON *cursor   = cJSON_GetObjectItemCaseSensitive(json, "cursor");
        require(cJSON_IsString(instance) && cJSON_IsString(cursor), "instance fault source lacks cursor");
        /* The cursor is internally consistent, but belongs to another instance. */
        instance->valuestring[0] = instance->valuestring[0] == 'a' ? 'b' : 'a';
        cursor->valuestring[0]   = instance->valuestring[0];
        break;
    }
    case kAuthPageFaultDuplicateId:
        require(cJSON_IsObject(row), "duplicate-ID fault source lacks a row");
        authPageSetText(row, "id", "42");
        break;
    case kAuthPageFaultDuplicateCredential:
        require(cJSON_IsObject(row), "duplicate-credential fault source lacks a row");
        authPageSetText(row, "password", "account-0");
        break;
    case kAuthPageFaultCheckpoint:
        authPageSetText(json, "sequence", "1");
        break;
    default:
        require(false, "unknown page mutation");
        break;
    }
    char *text = cJSON_PrintUnformatted(json);
    require(text != NULL, "page mutation could not serialize its bounded fixture");
    cJSON_Delete(json);
    const uint32_t length = (uint32_t) strlen(text);
    buffer                = sbufReserveSpace(buffer, 29 + length);
    sbufSetLength(buffer, 29 + length);
    uint32_t number = htonl(25 + length);
    memoryCopy(sbufGetMutablePtr(buffer), &number, sizeof(number));
    number = htonl(length);
    memoryCopy(sbufGetMutablePtr(buffer) + 25, &number, sizeof(number));
    memoryCopy(sbufGetMutablePtr(buffer) + 29, text, length);
    cJSON_free(text);
    return buffer;
}

static void testMalformedPagesAndBackoff(void)
{
    /* The second page imports into an already populated private table. A bad
     * page must leave the generation, cache and local observations untouched. */
    setup(129);
    start(0);
    const auth_page_fault_t faults[] = {kAuthPageFaultMissingCount,
                                        kAuthPageFaultRepeatedPosition,
                                        kAuthPageFaultSkippedPosition,
                                        kAuthPageFaultWrongInstance,
                                        kAuthPageFaultDuplicateId,
                                        kAuthPageFaultDuplicateCredential};
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i)
    {
        const uint64_t generation = state(0)->users_generation;
        auth_page_fault           = faults[i];
        auth_page_fault_position  = 128;
        authenticationclientRequestPull(clients[0]);
        require(auth_page_fault == kAuthPageFaultNone && state(0)->users_generation == generation &&
                    ! state(0)->staging.active && ! state(0)->continuity_error &&
                    state(0)->last_failure == kAuthenticationClientFailureInvalidResponse &&
                    authenticationclientCanAuthenticate(clients[0]),
                "malformed page replaced cache, escaped validation or lost cached admission");
        pump(10);
        require(state(0)->users_generation == generation + 1 && state(0)->sync_retry_streak == 0 &&
                    ! state(0)->staging.active,
                "valid retry did not recover a discarded private traversal");
    }

    /* A valid page carrying an unknown correlation cannot advance staging or
     * settle the real pending page. Deliver its untouched original afterward. */
    const uint64_t generation = state(0)->users_generation;
    auth_page_fault           = kAuthPageFaultCorrelation;
    auth_page_fault_position  = 128;
    authenticationclientRequestPull(clients[0]);
    require(auth_page_original != NULL && state(0)->staging.active && state(0)->staging.position == 128 &&
                state(0)->pull_in_flight && state(0)->pending_count == 1 && state(0)->users_generation == generation &&
                state(0)->sync_retry_streak == 0,
            "stale page correlation advanced staging or settled a current request");
    sbuf_t *valid_page = auth_page_original;
    sbuf_t *late_page  = sbufDuplicate(valid_page);
    auth_page_original = NULL;
    tunnelDownStreamPayload(clients[0], state(0)->control_line, valid_page);
    require(state(0)->users_generation == generation + 1 && ! state(0)->staging.active,
            "ignored stale correlation prevented the current page from completing");
    disconnect(0);
    hold_page_position = 128;
    pump(10);
    require(held_request != NULL && state(0)->staging.position == 128,
            "new line did not reach its independently correlated second page");
    const authenticationclient_failure_t previous_failure = state(0)->last_failure;
    const uint32_t                       previous_streak  = state(0)->sync_retry_streak;
    tunnelDownStreamPayload(clients[0], state(0)->control_line, late_page);
    require(state(0)->staging.position == 128 && state(0)->pull_in_flight && state(0)->pending_count == 1 &&
                state(0)->users_generation == generation + 1 && state(0)->last_failure == previous_failure &&
                state(0)->sync_retry_streak == previous_streak,
            "late page from an old line advanced a new traversal or rewrote failure history");
    deliverHeldRequest();
    require(state(0)->users_generation == generation + 2 && ! state(0)->staging.active,
            "late old-line page prevented current traversal completion");
    teardown();

    /* Checkpoint contradictions are terminal continuity failures rather than
     * a reason to discard debt, re-enroll and accept arbitrary page metadata. */
    setup(129);
    start(0);
    const uint64_t checkpoint_generation = state(0)->users_generation;
    traffic(0, 9);
    auth_page_fault          = kAuthPageFaultCheckpoint;
    auth_page_fault_position = 128;
    authenticationclientRequestPull(clients[0]);
    require(auth_page_fault == kAuthPageFaultNone && state(0)->continuity_error &&
                state(0)->last_failure == kAuthenticationClientFailureContinuity &&
                state(0)->users_generation == checkpoint_generation && local(0, false) == 9 &&
                ! state(0)->staging.active && state(0)->control_line == NULL && state(0)->last_ack_sequence == 0 &&
                ! authenticationclientCanAuthenticate(clients[0]),
            "wrong page checkpoint cleared debt, installed a table or bypassed continuity handling");
    teardown();

    /* Each reconnect authenticates and accepts page one before page two fails.
     * Session, Pong and intermediate progress must preserve the failure streak. */
    setup(129);
    start(0);
    const uint64_t stable_generation = state(0)->users_generation;
    auth_page_fault                  = kAuthPageFaultMissingCount;
    auth_page_fault_position         = 128;
    authenticationclientRequestPull(clients[0]);
    for (uint32_t streak = 1; streak <= 3; ++streak)
    {
        authenticationclient_tstate_t *ts    = state(0);
        const uint64_t                 now   = authenticationclientLocalTimeMS();
        const uint64_t                 delay = streak == 1 ? 10 : streak == 2 ? 1000 : 2000;
        require(ts->sync_retry_streak == streak && ts->sync_retry_not_before_ms == now + delay &&
                    ts->control_line == NULL && ! ts->staging.active && ts->reconnect_timer != NULL &&
                    ts->users_generation == stable_generation && authenticationclientCanAuthenticate(clients[0]),
                "repeated bad pages lost their fixed exponential retry deadline or old cache");
        const unsigned requests = page_requests;
        authenticationclientRequestPull(clients[0]);
        authenticationclientResumeSync(clients[0]);
        authenticationclientOpenControlLine(clients[0]);
        require(page_requests == requests && ts->control_line == NULL && ts->progress_timer == NULL &&
                    ts->sync_retry_not_before_ms == now + delay,
                "direct work bypassed or extended a failed-page retry deadline");
        hold_page_position = 128;
        pump((unsigned) delay);
        require(held_request != NULL && ts->authenticated && ts->staging.active && ts->staging.position == 128 &&
                    ts->sync_retry_streak == streak && ts->sync_retry_not_before_ms == now + delay,
                "Session or valid intermediate page reset the failed-refresh streak");
        require(authenticationclientSendPing(clients[0]) && ts->sync_retry_streak == streak &&
                    ts->sync_retry_not_before_ms == now + delay && ts->staging.position == 128,
                "valid Pong reset retry history or changed page progress");
        if (streak < 3)
        {
            auth_page_fault          = kAuthPageFaultMissingCount;
            auth_page_fault_position = 128;
        }
        deliverHeldRequest();
    }
    require(state(0)->users_generation == stable_generation + 1 && ! state(0)->staging.active &&
                state(0)->sync_retry_streak == 0 && state(0)->sync_retry_not_before_ms == 0 &&
                state(0)->sync_retry_failure == kAuthenticationClientFailureNone,
            "successful final validation did not reset the failed-refresh streak");
    teardown();
}
