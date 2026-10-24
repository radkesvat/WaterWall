/*
 * Covers: authenticationclient profile; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testSuccess, testAbsentFields
 * Checks: Assertion labels include: user construction failed; user insertion failed; alice; profile lookup
 * returns complete owned credentials
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.authenticationclient_profile_unit
 */
#include "AuthenticationClient/structure.h"
#include "fixtures/user_runtime.h"
#include "wthread.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "loggers/network_logger.h"

typedef enum lookup_kind_e
{
    kLookupSha224,
    kLookupUuid,
    kLookupWireGuard,
    kLookupPassword
} lookup_kind_t;

typedef struct profile_fixture_s
{
    tunnel_t     *tunnel;
    users_t       users;
    user_t       *user;
    const char   *password;
    lookup_kind_t kind;
    uint8_t       sha224[SHA224_DIGEST_SIZE];
    uint8_t       uuid[kWwUuidBytesLen];
    uint8_t       publickey[USER_WIREGUARD_PUBLICKEY_SIZE];
} profile_fixture_t;

static atomic_u32_t copy_calls;
static void    *sensitive_release;
static size_t   sensitive_length;
static unsigned wiped_releases;

void __real_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr)
{
    if (ptr != NULL && ptr == sensitive_release)
    {
        for (size_t i = 0; i < sensitive_length; ++i)
            require(((const uint8_t *) ptr)[i] == 0, "owned sensitive allocation was freed without secure wiping");
        sensitive_release = NULL;
        ++wiped_releases;
    }
    __real_memoryFree(ptr);
}

static void watchSensitiveRelease(char *value)
{
    require(value != NULL && sensitive_release == NULL, "sensitive release watch is already occupied");
    sensitive_release = value;
    sensitive_length  = strlen(value) + 1;
}

char *__real_stringDuplicate(const char *source);
char *__wrap_stringDuplicate(const char *source);

char *__wrap_stringDuplicate(const char *source)
{
    atomicIncU32(&copy_calls);
    return __real_stringDuplicate(source);
}

static void fixtureCreate(profile_fixture_t *fixture, lookup_kind_t kind)
{
    *fixture          = (profile_fixture_t) {.kind = kind};
    fixture->password = kind == kLookupWireGuard ? "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA="
                                                 : "00112233-4455-6677-8899-aabbccddeeff";
    fixture->tunnel   = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), 0);
    require(fixture->tunnel != NULL && usersCreate(&fixture->users), "fixture allocation failed");
    authenticationclient_tstate_t *state = tunnelGetState(fixture->tunnel);
    rwlockinit(&state->users_lock);
    state->users = &fixture->users;
    mutexInit(&state->control_mutex);
    state->started          = true;
    state->clock_loaded     = true;
    state->users_loaded     = true;
    state->users_generation = 7;
    state->sync_max_users   = 100000;
    state->sync_max_bytes   = 268435456;
    user_t user;
    require(userCreate(&user, fixture->password), "user construction failed");
    userSetId(&user, 42);
    require(usersAddUser(&fixture->users, &user), "user insertion failed");
    memoryCopy(fixture->sha224, user.sha224_pass.bytes, sizeof(fixture->sha224));
    memoryCopy(fixture->uuid, user.uuid_pass, sizeof(fixture->uuid));
    memoryCopy(fixture->publickey, user.wireguard_publickey, sizeof(fixture->publickey));
    require(kind != kLookupUuid || user.uuid_pass_valid, "UUID fixture has no UUID");
    require(kind != kLookupWireGuard || user.wireguard_publickey_valid, "WireGuard fixture has no public key");
    userDestroy(&user);
    fixture->user = usersLookupByIdentifier(&fixture->users, 42);
    require(fixture->user != NULL && usersSetUserName(&fixture->users, fixture->user, "alice"), "user naming failed");
}

static void fixtureDestroy(profile_fixture_t *fixture)
{
    authenticationclient_tstate_t *state = tunnelGetState(fixture->tunnel);
    usersDestroy(&fixture->users);
    rwlockDestroy(&state->users_lock);
    mutexDestroy(&state->control_mutex);
    tunnelDestroy(fixture->tunnel);
}

static bool lookup(const profile_fixture_t *fixture, user_handle_t *handle,
                   authenticationclient_user_profile_t *profile)
{
    switch (fixture->kind)
    {
    case kLookupSha224:
        return authenticationclientGetUserBySHA224WithProfile(fixture->tunnel, fixture->sha224, handle, profile);
    case kLookupUuid:
        return authenticationclientGetUserByUUIDWithProfile(fixture->tunnel, fixture->uuid, handle, profile) ==
               kAuthenticationClientUserLookupOk;
    case kLookupWireGuard:
        return authenticationclientGetUserByWireGuardPublicKeyWithProfile(
                   fixture->tunnel, fixture->publickey, handle, profile) == kAuthenticationClientUserLookupOk;
    case kLookupPassword:
        return authenticationclientGetUserByPasswordWithProfile(fixture->tunnel, fixture->password, handle, profile) ==
               kAuthenticationClientUserLookupOk;
    }
    require(false, "unknown fixture lookup");
    return false;
}

static void testSuccess(const profile_fixture_t *fixture)
{
    user_handle_t                       handle  = {0};
    authenticationclient_user_profile_t profile = {0};
    require(lookup(fixture, &handle, &profile) && userHandleIsValid(&handle) && profile.name != NULL &&
                profile.password != NULL && stringCompare(profile.name, "alice") == 0 &&
                stringCompare(profile.password, fixture->password) == 0,
            "successful lookup did not publish complete identity");
    require(profile.name != fixture->user->name && profile.password != fixture->user->password,
            "profile borrowed database strings");
    unsigned before = wiped_releases;
    watchSensitiveRelease(profile.password);
    authenticationclientUserProfileClear(&profile);
    require(sensitive_release == NULL && wiped_releases == before + 1, "profile password release was not observed");
    require(profile.name == NULL && profile.password == NULL, "profile clear left owned fields");

    atomicStoreU32(&copy_calls, 0);
    require(lookup(fixture, &handle, NULL) && userHandleIsValid(&handle) && atomicLoadU32(&copy_calls) == 0,
            "handle-only lookup attempted a profile allocation");
}

static void testAbsentFields(profile_fixture_t *fixture)
{
    /* Lookup keys remain indexed while optional plaintext fields are absent.
     * Restore their owned strings before any index operation or teardown. */
    for (unsigned empty = 0; empty < 2; ++empty)
    {
        for (unsigned absent = 1; absent <= 3; ++absent)
        {
            if (fixture->kind == kLookupPassword && (absent & 2U) != 0)
                continue; /* Password matching itself requires the plaintext. */
            char *name = fixture->user->name, *password = fixture->user->password;
            char  blank[] = "";
            rwlockWriteLock(&fixture->user->lock);
            if ((absent & 1U) != 0)
                fixture->user->name = empty ? blank : NULL;
            if ((absent & 2U) != 0)
                fixture->user->password = empty ? blank : NULL;
            rwlockWriteUnlock(&fixture->user->lock);

            user_handle_t                       handle  = {0};
            authenticationclient_user_profile_t profile = {0};
            require(lookup(fixture, &handle, &profile) && userHandleIsValid(&handle),
                    "lookup rejected an absent optional field");
            require(((profile.name == NULL) == ((absent & 1U) != 0)) &&
                        ((profile.password == NULL) == ((absent & 2U) != 0)),
                    "absent optional field changed representation");
            authenticationclientUserProfileClear(&profile);

            rwlockWriteLock(&fixture->user->lock);
            fixture->user->name     = name;
            fixture->user->password = password;
            rwlockWriteUnlock(&fixture->user->lock);
        }
    }
}

static void testEligibilityAndAdmission(profile_fixture_t *fixture)
{
    user_t *user    = fixture->user;
    user->limit.ips = user->limit.devices = user->limit.cons_in = 1;
    user->limit.cons_out                                        = 2;
    user->limit.bandwidth                                       = (user_ud_t) {1, 1};
    user->stats.ips = user->stats.devices = user->stats.cons_in = user->stats.cons_out = 100;
    user->stats.speed                                                                  = (user_ud_t) {100, 100};
    testSuccess(fixture);

    user_handle_t handle = {0};
    require(authenticationclientGetUserBySHA256(fixture->tunnel, user->sha256_pass.bytes, &handle),
            "saved gauges blocked SHA256 lookup");
    require(authenticationclientUserHandleIsLive(fixture->tunnel, &handle), "saved gauges blocked handle liveness");
    user_ip_key_t first = {.type = 4, .bytes = {127, 0, 0, 1}};
    user_ip_key_t other = {.type = 4, .bytes = {127, 0, 0, 2}};
    require(authenticationclientUserTryAdmitConnection(fixture->tunnel, &handle, &first, 0) == kUserAdmissionOk,
            "saved gauges blocked live admission");
    require(authenticationclientUserTryAdmitConnection(fixture->tunnel, &handle, &other, 0) == kUserAdmissionIpLimited,
            "distinct IP limit was bypassed");
    require(authenticationclientUserTryAdmitConnection(fixture->tunnel, &handle, &first, 0) == kUserAdmissionOk,
            "same IP could not share its reservation");
    require(authenticationclientUserTryAdmitConnection(fixture->tunnel, &handle, &first, 0) ==
                kUserAdmissionConnectionLimited,
            "live connection limit was bypassed");
    authenticationclientUserReleaseConnection(fixture->tunnel, &handle, &first);
    authenticationclientUserReleaseConnection(fixture->tunnel, &handle, &first);
    require(authenticationclientUserTryAdmitConnection(fixture->tunnel, &handle, &other, 0) == kUserAdmissionOk,
            "release failed to restore capacity");
    authenticationclientUserReleaseConnection(fixture->tunnel, &handle, &other);

    for (unsigned refusal = 0; refusal < 3; ++refusal)
    {
        user->enabled               = refusal != 0;
        user->timeinfo.expire_at_ms = refusal == 1 ? 1 : 0;
        user->limit.traffic.u       = refusal == 2 ? 1 : 0;
        user->stats.traffic.u       = 1;
        require(! lookup(fixture, &handle, NULL) && ! userHandleIsValid(&handle), "ineligible profile was accepted");
        require(! authenticationclientGetUserBySHA256(fixture->tunnel, user->sha256_pass.bytes, &handle),
                "ineligible SHA256 was accepted");
        userHandleSet(&handle, 7, 42);
        require(! authenticationclientUserHandleIsLive(fixture->tunnel, &handle), "ineligible handle remained live");
        const authenticationclient_user_lookup_result_t expected[] = {kAuthenticationClientUserLookupUserDisabled,
                                                                      kAuthenticationClientUserLookupUserExpired,
                                                                      kAuthenticationClientUserLookupUserLimitReached};
        require(authenticationclientGetUserByPasswordWithResult(fixture->tunnel, fixture->password, &handle) ==
                    expected[refusal],
                "eligibility rejection lost its reason");
    }
    user->enabled               = true;
    user->timeinfo.expire_at_ms = 0;
    user->limit.traffic.u = user->stats.traffic.u = 0;
}

static void testAdmissionAvailability(profile_fixture_t *fixture)
{
    authenticationclient_tstate_t *ts = tunnelGetState(fixture->tunnel);
    require(! authenticationclientIsReady(fixture->tunnel) && authenticationclientCanAuthenticate(fixture->tunnel),
            "loaded offline cache has wrong control/admission state");
    for (unsigned block = 0; block < 6; ++block)
    {
        ts->started                                 = block != 0;
        ts->users_loaded                            = block != 1;
        ts->clock_loaded                            = block != 2;
        ts->stopping                                = block == 3;
        ts->auth_rejected                           = block == 4;
        ts->continuity_error                        = block == 5;
        user_handle_t                       handle  = {.generation = 7, .user_id = 42};
        authenticationclient_user_profile_t profile = {0};
        require(! authenticationclientCanAuthenticate(fixture->tunnel) && ! lookup(fixture, &handle, &profile) &&
                    ! userHandleIsValid(&handle) && profile.name == NULL && profile.password == NULL,
                "credential family bypassed availability or published stale identity");
        handle = (user_handle_t) {.generation = 7, .user_id = 42};
        require(! authenticationclientGetUserBySHA256(fixture->tunnel, fixture->user->sha256_pass.bytes, &handle) &&
                    ! userHandleIsValid(&handle),
                "SHA256 bypassed availability");
        handle = (user_handle_t) {.generation = 7, .user_id = 42};
        require(authenticationclientUserTryAdmitConnection(fixture->tunnel, &handle, NULL, 0) == kUserAdmissionInvalid,
                "reservation bypassed availability");
    }
    ts->started = ts->users_loaded = ts->clock_loaded = true;
    ts->stopping = ts->auth_rejected = ts->continuity_error = false;
}

static void testOwnedSecretCleanup(void)
{
    for (unsigned rollback = 0; rollback < 2; ++rollback)
    {
        tunnel_t *t = tunnelCreate(NULL, sizeof(authenticationclient_tstate_t), 0);
        require(t != NULL, "secret cleanup tunnel allocation");
        authenticationclient_tstate_t *state = tunnelGetState(t);
        mutexInit(&state->control_mutex);
        rwlockinit(&state->users_lock);
        state->secret   = stringDuplicate("owned-client-SECRET");
        unsigned before = wiped_releases;
        watchSensitiveRelease(state->secret);
        authenticationclientTunnelDestroy(t, rollback ? wwLifecycleStartupRollback() : wwLifecycleProcessShutdown());
        require(sensitive_release == NULL && wiped_releases == before + 1,
                "node-owned secret was not wiped on normal or rollback destruction");
    }
}

static void replaceUuidTable(profile_fixture_t *fixture, uint64_t id, const char *password, const char *name)
{
    users_t replacement;
    require(usersCreate(&replacement), "replacement table construction failed");
    user_t *fresh = NULL;
    if (id != 0)
    {
        user_t user;
        require(userCreate(&user, password), "replacement user construction failed");
        userSetId(&user, id);
        require(usersAddUser(&replacement, &user), "replacement user insertion failed");
        userDestroy(&user);
        fresh = usersLookupByIdentifier(&replacement, id);
        require(fresh != NULL && usersSetUserName(&replacement, fresh, name), "replacement user naming failed");
    }
    authenticationclient_tstate_t *ts = tunnelGetState(fixture->tunnel);
    mutexLock(&ts->control_mutex);
    rwlockWriteLock(&ts->users_lock);
    if (fresh != NULL)
        fresh->runtime.identity_generation_floor = ts->users_generation + 1;
    require(usersMigrateRuntimeStateByIdentifier(&replacement, &fixture->users), "replacement migration failed");
    usersPublishCandidate(&fixture->users, &replacement);
    ++ts->users_generation;
    rwlockWriteUnlock(&ts->users_lock);
    mutexUnlock(&ts->control_mutex);
    usersDestroy(&replacement);
    fixture->user = fresh;
}

static void testUuidSourceAndRevalidation(void)
{
    profile_fixture_t fixture;
    fixtureCreate(&fixture, kLookupUuid);
    authenticationclient_tstate_t *ts               = tunnelGetState(fixture.tunnel);
    fixture.user->runtime.identity_generation_floor = 7;
    authenticationclient_uuid_source_t source       = {0};
    require(authenticationclientGetUUIDSource(fixture.tunnel, &source) == kAuthenticationClientUuidSnapshotOk &&
                source.users_generation == 7 && source.total_users == 1 && source.max_users == 100000 &&
                source.max_bytes == 268435456,
            "UUID source metadata lost its installed table or bounds");
    authenticationclient_uuid_candidate_t candidate = {0};
    size_t                                count = SIZE_MAX, next = SIZE_MAX;
    require(authenticationclientCopyUUIDCandidatePage(fixture.tunnel, 7, 0, 1, &candidate, &count, &next) ==
                    kAuthenticationClientUuidSnapshotOk &&
                count == 1 && next == 1 && candidate.user_id == 42 &&
                memoryEqual(candidate.uuid, fixture.uuid, sizeof(candidate.uuid)),
            "UUID source did not copy its account");
    const authenticationclient_uuid_candidate_t original = candidate;
    replaceUuidTable(&fixture, 42, fixture.password, "renamed");
    require(authenticationclientCopyUUIDCandidatePage(fixture.tunnel, 7, 0, 1, &candidate, &count, &next) ==
                    kAuthenticationClientUuidSnapshotChanged &&
                count == 0 && next == 0 && memoryEqual(&candidate, &original, sizeof(candidate)),
            "UUID source mixed table generations or wrote a stale page");
    user_handle_t                       handle  = {0};
    authenticationclient_user_profile_t profile = {0};
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 7, &candidate, &handle, &profile) ==
                    kAuthenticationClientUserLookupOk &&
                handle.generation == 8 && handle.user_id == 42 && strcmp(profile.name, "renamed") == 0 &&
                strcmp(profile.password, fixture.password) == 0,
            "continuous UUID identity did not resolve the current profile and generation");
    authenticationclientUserProfileClear(&profile);
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 9, &candidate, &handle, &profile) ==
                    kAuthenticationClientUserLookupUserNotFound &&
                ! userHandleIsValid(&handle) && profile.name == NULL,
            "future UUID candidate generation was accepted");
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 0, &candidate, &handle, NULL) ==
                    kAuthenticationClientUserLookupInvalidArgument &&
                ! userHandleIsValid(&handle),
            "zero UUID candidate generation was accepted");
    require(usersSetUserEnabled(&fixture.users, fixture.user, false), "candidate disable failed");
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 7, &candidate, &handle, &profile) ==
                    kAuthenticationClientUserLookupUserDisabled &&
                profile.name == NULL && profile.password == NULL,
            "UUID candidate bypassed current eligibility");
    require(usersSetUserEnabled(&fixture.users, fixture.user, true), "candidate enable failed");
    require(usersChangePassword(&fixture.users, fixture.user, "rotated-plain"), "candidate rotation failed");
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 7, &candidate, &handle, NULL) ==
                kAuthenticationClientUserLookupUserNotFound,
            "rotated UUID candidate was accepted");
    replaceUuidTable(&fixture, 43, fixture.password, "reassigned");
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 7, &candidate, &handle, NULL) ==
                kAuthenticationClientUserLookupUserNotFound,
            "reassigned UUID candidate changed account identity");
    require(authenticationclientCopyUUIDCandidatePage(fixture.tunnel, 9, 0, 1, &candidate, &count, &next) ==
                    kAuthenticationClientUuidSnapshotOk &&
                candidate.user_id == 43,
            "reassigned UUID candidate was not visible to a fresh snapshot");
    replaceUuidTable(&fixture, 0, NULL, NULL);
    require(authenticationclientGetUUIDSource(fixture.tunnel, &source) == kAuthenticationClientUuidSnapshotOk &&
                source.total_users == 0 && source.users_generation == 10,
            "empty installed UUID source was unavailable");
    require(authenticationclientCopyUUIDCandidatePage(fixture.tunnel, 10, 0, 1, &candidate, &count, &next) ==
                    kAuthenticationClientUuidSnapshotOk &&
                count == 0 && next == 0,
            "empty UUID source did not return a terminal page");
    replaceUuidTable(&fixture, 43, fixture.password, "recreated");
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 9, &candidate, &handle, NULL) ==
                kAuthenticationClientUserLookupUserNotFound,
            "recreated UUID identity accepted an old candidate");
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 11, &candidate, &handle, NULL) ==
                    kAuthenticationClientUserLookupOk &&
                handle.generation == 11,
            "new incarnation UUID candidate did not authenticate");
    ts->stopping = true;
    require(authenticationclientGetUUIDSource(fixture.tunnel, &source) ==
                    kAuthenticationClientUuidSnapshotUnavailable &&
                source.users_generation == 0 && source.total_users == 0 && source.max_bytes == 0,
            "unavailable UUID source exposed metadata");
    require(authenticationclientCopyUUIDCandidatePage(fixture.tunnel, 11, 0, 1, &candidate, &count, &next) ==
                    kAuthenticationClientUuidSnapshotUnavailable &&
                count == 0 && next == 0,
            "UUID page bypassed admission closure");
    require(authenticationclientResolveUUIDCandidateWithProfile(fixture.tunnel, 11, &candidate, &handle, &profile) ==
                    kAuthenticationClientUserLookupUsersUnavailable &&
                ! userHandleIsValid(&handle) && profile.name == NULL && profile.password == NULL,
            "UUID candidate bypassed admission closure");
    memorySecureZero(&candidate, sizeof(candidate));
    fixtureDestroy(&fixture);
}

static WTHREAD_ROUTINE(replaceUuidTables)
{
    profile_fixture_t *fixture = userdata;
    for (unsigned i = 0; i < 64; ++i)
        replaceUuidTable(fixture, 42, fixture->password, (i & 1U) != 0 ? "alice" : "bob");
    return 0;
}

static void testUuidConcurrentRefresh(void)
{
    profile_fixture_t fixture;
    fixtureCreate(&fixture, kLookupUuid);
    fixture.user->runtime.identity_generation_floor = 7;
    wthread_t writer;
    require(threadCreate(&writer, replaceUuidTables, &fixture) == kWThreadErrorNone, "UUID refresh writer failed");
    for (unsigned i = 0; i < 1024; ++i)
    {
        authenticationclient_uuid_source_t source;
        require(authenticationclientGetUUIDSource(fixture.tunnel, &source) == kAuthenticationClientUuidSnapshotOk,
                "concurrent UUID source was unavailable");
        authenticationclient_uuid_candidate_t       candidate = {0};
        size_t                                      count, next;
        authenticationclient_uuid_snapshot_result_t result = authenticationclientCopyUUIDCandidatePage(
            fixture.tunnel, source.users_generation, 0, 1, &candidate, &count, &next);
        if (result == kAuthenticationClientUuidSnapshotChanged)
        {
            require(count == 0 && next == 0 && candidate.user_id == 0, "concurrent stale page published an identity");
            continue;
        }
        require(result == kAuthenticationClientUuidSnapshotOk && count == 1 && next == 1 && candidate.user_id == 42,
                "concurrent UUID page returned a partial identity");
        user_handle_t                       handle  = {0};
        authenticationclient_user_profile_t profile = {0};
        require(authenticationclientResolveUUIDCandidateWithProfile(
                    fixture.tunnel, source.users_generation, &candidate, &handle, &profile) ==
                        kAuthenticationClientUserLookupOk &&
                    handle.user_id == 42 && handle.generation >= source.users_generation && profile.name != NULL &&
                    profile.password != NULL &&
                    (strcmp(profile.name, "alice") == 0 || strcmp(profile.name, "bob") == 0) &&
                    strcmp(profile.password, fixture.password) == 0,
                "concurrent refresh mixed credential identity, profile or generation");
        authenticationclientUserProfileClear(&profile);
        memorySecureZero(&candidate, sizeof(candidate));
    }
    require(threadJoin(writer) == 0, "UUID refresh writer join failed");
    fixtureDestroy(&fixture);
}

int main(void)
{
    testCaseSet("authenticationclient_profile_test");
    require(createNetworkLogger(NULL, false) != NULL, "network logger initialization failed");
    require(userTestRuntimeInitialize(), "crypto initialization failed");
    for (lookup_kind_t kind = kLookupSha224; kind <= kLookupPassword; ++kind)
    {
        profile_fixture_t fixture;
        fixtureCreate(&fixture, kind);
        testAdmissionAvailability(&fixture);
        testSuccess(&fixture);
        testAbsentFields(&fixture);
        testEligibilityAndAdmission(&fixture);
        fixtureDestroy(&fixture);
    }
    testUuidSourceAndRevalidation();
    testUuidConcurrentRefresh();
    testOwnedSecretCleanup();
    userTestRuntimeCleanup();
    networkloggerDestroy();
    puts("AuthenticationClient owned credential profiles passed");
    return 0;
}
