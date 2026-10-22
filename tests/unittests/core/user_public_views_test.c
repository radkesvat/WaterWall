/*
 * Covers: bounded credential-free owned projections, UTF-8 previews, indexed
 * details/range pages, deadlines and nonblocking collection/user/stats locks.
 * Setup: real user/users helpers; semaphore-held writer locks prove refusal
 * happens before the writer releases its lock. No timing threshold is used.
 * CTest: waterwall.user_public_views_unit
 * Limits: native execution covers the available platform lock implementation.
 */

#include "objects/user_internal.h"
#include "objects/users.h"
#include "test_assert.h"
#include "utils/json_helpers.h"
#include "wthread.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct lock_holder_s
{
    wrwlock_t  *lock;
    wsem_t      acquired, release;
    atomic_bool held;
    wthread_t   thread;
} lock_holder_t;

static WTHREAD_ROUTINE(holdWriter)
{
    lock_holder_t *holder = userdata;
    rwlockWriteLock(holder->lock);
    atomic_store(&holder->held, true);
    semaphorePost(&holder->acquired);
    require(semaphoreWait(&holder->release), "writer release wait failed");
    atomic_store(&holder->held, false);
    rwlockWriteUnlock(holder->lock);
    return 0;
}

static void holdStart(lock_holder_t *holder, wrwlock_t *lock)
{
    memoryZero(holder, sizeof(*holder));
    holder->lock = lock;
    semaphoreInit(&holder->acquired, 0);
    semaphoreInit(&holder->release, 0);
    atomic_init(&holder->held, false);
    require(threadCreate(&holder->thread, holdWriter, holder) == kWThreadErrorNone, "writer creation failed");
    require(semaphoreWait(&holder->acquired), "writer acquired wait failed");
}

static void holdFinish(lock_holder_t *holder)
{
    require(atomic_load(&holder->held), "query waited for writer release");
    semaphorePost(&holder->release);
    require(threadJoin(holder->thread) == 0, "writer join failed");
    semaphoreDestroy(&holder->acquired);
    semaphoreDestroy(&holder->release);
}

static void addUser(users_t *users, uint64_t id)
{
    user_t user;
    char   password[80];
    snprintf(password, sizeof(password), "secret-credential-%" PRIu64, id);
    require(userCreate(&user, password), "user creation failed");
    userSetId(&user, id);
    require(usersAddUser(users, &user), "user insertion failed");
    userDestroy(&user);
}

static void testOwnedDetail(void)
{
    users_t users;
    require(usersCreate(&users), "collection creation failed");
    addUser(&users, UINT64_MAX);
    user_t       *user   = usersLookupByIdentifier(&users, UINT64_MAX);
    user_update_t update = {
        .mask = kUserUpdateName | kUserUpdateEmail | kUserUpdateNotes | kUserUpdateGid | kUserUpdateEnabled |
                kUserUpdateLimit | kUserUpdateTimeInfo | kUserUpdateStats | kUserUpdateRecordStatInterval |
                kUserUpdateWireGuardAllowedIps,
        .name                    = "Public name",
        .email                   = "public@example.test",
        .notes                   = "Public notes",
        .wireguard_allowed_ips   = "10.1.0.0/24",
        .gid                     = UINT64_MAX,
        .enabled                 = false,
        .record_stat_interval_ms = 123,
        .limit    = {.traffic = {1, 2, 3}, .bandwidth = {4, 5}, .ips = 6, .devices = 7, .cons_in = 8, .cons_out = 9},
        .timeinfo = {.created_at_ms               = 11,
                     .expire_at_ms                = 12,
                     .expire_after_first_usage_ms = 13,
                     .first_usage_at_ms           = 14},
        .stats    = {.traffic = {15, 16}, .speed = {991, 992}, .ips = 993, .devices = 994}};
    require(usersUpdateUser(&users, user, &update), "public field setup failed");
    user_public_detail_t detail;
    require(usersCopyPublicDetailByIdentifier(&users, UINT64_MAX, 4096, 0, &detail) == kUserPublicOk,
            "exact UINT64_MAX lookup failed");
    require(detail.id == UINT64_MAX && detail.gid == UINT64_MAX && ! detail.enabled &&
                detail.record_stat_interval_ms == 123 && detail.limit.traffic.total == 3 &&
                detail.limit.bandwidth.d == 5 && detail.limit.ips == 6 && detail.limit.devices == 7 &&
                detail.limit.cons_in == 8 && detail.limit.cons_out == 9 && detail.timeinfo.created_at_ms == 11 &&
                detail.timeinfo.expire_at_ms == 12 && detail.timeinfo.expire_after_first_usage_ms == 13 &&
                detail.timeinfo.first_usage_at_ms == 14 && detail.usage.u == 15 && detail.usage.d == 16,
            "public scalar projection mismatch");
    usersDestroy(&users);
    require(strcmp(detail.name, "Public name") == 0 && strcmp(detail.email, "public@example.test") == 0 &&
                strcmp(detail.notes, "Public notes") == 0 && strcmp(detail.wireguard_allowed_ips, "10.1.0.0/24") == 0,
            "detail strings did not survive storage destruction");
    size_t exact =
        strlen(detail.name) + strlen(detail.email) + strlen(detail.notes) + strlen(detail.wireguard_allowed_ips) + 4U;
    require(detail.owned_string_bytes == exact, "owned string charge mismatch");
    userPublicDetailDestroy(&detail);
    require(detail.name == NULL && detail.owned_string_bytes == 0, "destroy did not clear detail");
    userPublicDetailDestroy(&detail);
}

static void replaceStandaloneName(user_t *user, const char *name)
{
    memoryFree(user->name);
    user->name                = stringDuplicate(name);
    user->export_strings.name = userMeasureExportString(name);
}

static void checkCachedStrings(const user_t *user)
{
    const char *texts[] = {user->name, user->password, user->email, user->notes, user->wireguard_allowed_ips};
    const user_export_string_measure_t *measures[] = {&user->export_strings.name,
                                                      &user->password_export,
                                                      &user->export_strings.email,
                                                      &user->export_strings.notes,
                                                      &user->export_strings.allowed_ips};
    size_t                              total      = userExportFixedOverhead();
    for (size_t i = 0; i < ARRAY_SIZE(texts); ++i)
    {
        cJSON *value   = cJSON_CreateString(texts[i] == NULL ? "" : texts[i]);
        char  *encoded = cJSON_PrintUnformatted(value);
        size_t bytes   = strlen(encoded) - 2U;
        require(measures[i]->result == kUserPublicOk && measures[i]->escaped_bytes == bytes,
                "cached charge differs from independent JSON escaping");
        total += bytes;
        cJSON_free(encoded);
        cJSON_Delete(value);
    }
    size_t upper;
    require(userMeasureExportUpperBound(user, &upper) == kUserPublicOk && upper == total,
            "row upper bound differs from cached field charges");
    cJSON *row     = userToJson((user_t *) user);
    char  *encoded = cJSON_PrintUnformatted(row);
    require(strlen(encoded) <= upper, "current exact row exceeds future-growth bound");
    cJSON_free(encoded);
    cJSON_Delete(row);
}

static void testCachedExportMeasurements(void)
{
    const char *texts[] = {"", "plain ASCII", "\xE2\x82\xAC \xF0\x9F\x8C\x8A", "quote\" slash\\", "\b\f\n\r\t\x01\x1F"};
    for (size_t i = 0; i < ARRAY_SIZE(texts); ++i)
    {
        cJSON  *json = cJSON_CreateObject();
        discard cJSON_AddStringToObject(json, "password", i == 0 ? "nonempty" : texts[i]);
        discard cJSON_AddStringToObject(json, "name", texts[i]);
        discard cJSON_AddStringToObject(json, "email", texts[i]);
        discard cJSON_AddStringToObject(json, "notes", texts[i]);
        discard cJSON_AddStringToObject(json, "wireguard-allowed-ips", " 10.42.7.255/24 ");
        user_t  user, copy, moved;
        require(userCreateFromJsonResult(&user, json) == kUserJsonOk, "measured import failed");
        cJSON_Delete(json);
        require(strcmp(user.wireguard_allowed_ips, "10.42.7.0/24") == 0, "CIDR was not normalized");
        checkCachedStrings(&user);
        require(userCopy(&copy, &user), "measured snapshot copy failed");
        checkCachedStrings(&copy);
        require(userMoveOwnedValue(&moved, &copy), "measured value move failed");
        checkCachedStrings(&moved);
        userDestroy(&copy);
        require(userSetWireGuardAllowedIps(&user, ""), "Allowed-IP clearing failed");
        require(userSetPassword(&user, "new \"\\\t password"), "standalone password replacement failed");
        checkCachedStrings(&user);
        userDestroy(&moved);
        userDestroy(&user);
    }
    user_t invalid;
    require(userCreate(&invalid, "valid"), "invalid generic text setup failed");
    replaceStandaloneName(&invalid, "\xC0\x80");
    size_t upper = 77;
    require(invalid.export_strings.name.result == kUserPublicInvalidEncoding &&
                userMeasureExportUpperBound(&invalid, &upper) == kUserPublicInvalidEncoding && upper == 0,
            "invalid generic text was not represented safely");
    userDestroy(&invalid);

    user_t maximum;
    require(userCreate(&maximum, "password"), "maximum metadata setup failed");
    maximum.id = maximum.gid        = UINT64_MAX;
    maximum.enabled                 = false;
    maximum.record_stat_interval_ms = INT_MAX;
    maximum.limit                   = (user_limit_t) {.traffic   = {UINT64_MAX, UINT64_MAX, UINT64_MAX},
                                                      .bandwidth = {UINT64_MAX, UINT64_MAX},
                                                      .ips       = UINT64_MAX,
                                                      .devices   = UINT64_MAX,
                                                      .cons_in   = UINT64_MAX,
                                                      .cons_out  = UINT64_MAX};
    maximum.timeinfo                = (user_time_info_t) {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
    maximum.stats                   = (user_stat_t) {.ips      = UINT64_MAX,
                                                     .devices  = UINT64_MAX,
                                                     .cons_in  = UINT64_MAX,
                                                     .cons_out = UINT64_MAX,
                                                     .traffic  = {UINT64_MAX, UINT64_MAX}};
    replaceStandaloneName(&maximum, "x");
    memoryFree(maximum.email);
    maximum.email                = stringDuplicate("x");
    maximum.export_strings.email = userMeasureExportString(maximum.email);
    memoryFree(maximum.notes);
    maximum.notes                = stringDuplicate("x");
    maximum.export_strings.notes = userMeasureExportString(maximum.notes);
    require(userSetWireGuardAllowedIps(&maximum, "10.71.0.0/24"), "maximum CIDR setup failed");
    checkCachedStrings(&maximum);
    cJSON *row     = userToJson(&maximum);
    char  *encoded = cJSON_PrintUnformatted(row);
    require(userMeasureExportUpperBound(&maximum, &upper) == kUserPublicOk && strlen(encoded) + 12U == upper,
            "maximum scalar serializer layout disagrees with fixed reserve");
    cJSON_free(encoded);
    cJSON_Delete(row);
    userDestroy(&maximum);

    users_t users;
    require(usersCreate(&users), "generic metadata setup failed");
    addUser(&users, 44);
    user_t *stored = usersLookupByIdentifier(&users, 44);
    require(usersSetUserName(&users, stored, "new \"name") &&
                usersSetUserEmail(&users, stored, "\xE2\x82\xAC@example.test") &&
                usersSetUserNotes(&users, stored, "notes\\\n\x01") &&
                usersChangePassword(&users, stored, "generic \tpassword"),
            "generic string setters failed");
    checkCachedStrings(stored);
    user_export_strings_t before = stored->export_strings;
    user_update_t         update = {.mask                  = kUserUpdateName | kUserUpdateWireGuardAllowedIps,
                                    .name                  = "refused",
                                    .wireguard_allowed_ips = "bad-cidr"};
    require(! usersUpdateUser(&users, stored, &update) &&
                memcmp(&before, &stored->export_strings, sizeof(before)) == 0 &&
                strcmp(stored->name, "new \"name") == 0,
            "failed generic preparation changed cached fields");
    checkCachedStrings(stored);
    usersDestroy(&users);

    require(usersCreate(&users), "name-map metadata setup failed");
    cJSON *map = cJSON_CreateObject();
    row        = cJSON_CreateObject();
    discard cJSON_AddStringToObject(row, "password", "name-map-password");
    discard jsonAddUint64ToObject(row, "id", 45);
    discard cJSON_AddItemToObject(map, "mapped \"name", row);
    require(usersFeedJson(&users, map), "name-map import failed");
    cJSON_Delete(map);
    checkCachedStrings(usersLookupByIdentifier(&users, 45));
    usersDestroy(&users);
}

static void testBoundsAndEncoding(void)
{
    user_t user;
    require(userCreate(&user, "private-password-sentinel"), "standalone creation failed");
    user_public_detail_t detail;
    require(userCopyPublicDetail(&user, 4, 0, &detail) == kUserPublicOk && detail.owned_string_bytes == 4 &&
                detail.name[0] == 0 && detail.email[0] == 0 && detail.notes[0] == 0 &&
                detail.wireguard_allowed_ips[0] == 0 && detail.limit.traffic.total == 0 &&
                detail.record_stat_interval_ms == USER_DEFAULT_RECORD_STAT_INTERVAL_MS,
            "default detail fields mismatch");
    userPublicDetailDestroy(&detail);
    require(userCopyPublicDetail(&user, 3, 0, &detail) == kUserPublicTooLarge && detail.name == NULL,
            "exact string budget was not enforced");
    require(userCopyPublicDetail(&user, 4096, 1, &detail) == kUserPublicTimeout && detail.name == NULL,
            "expired detail was not refused");

    char name[400];
    memset(name, 'a', sizeof(name));
    name[sizeof(name) - 1] = 0;
    replaceStandaloneName(&user, name);
    user_public_summary_t summary;
    require(userCopyPublicSummary(&user, 0, &summary) == kUserPublicOk && summary.name_preview_length == 256 &&
                summary.name_preview_state == kUserPublicNameTruncated,
            "long name was not bounded");
    require(userCopyPublicDetail(&user, 128, 0, &detail) == kUserPublicTooLarge && detail.name == NULL,
            "oversized detail was not refused");
    name[254] = (char) 0xE2;
    name[255] = (char) 0x82;
    name[256] = (char) 0xAC;
    name[257] = 0;
    replaceStandaloneName(&user, name);
    require(userCopyPublicSummary(&user, 0, &summary) == kUserPublicOk && summary.name_preview_length == 254 &&
                summary.name_preview_state == kUserPublicNameTruncated,
            "preview split UTF-8 codepoint");
    name[253] = (char) 0xE2;
    name[254] = (char) 0x82;
    name[255] = (char) 0xAC;
    name[256] = 0;
    replaceStandaloneName(&user, name);
    require(userCopyPublicSummary(&user, 0, &summary) == kUserPublicOk && summary.name_preview_length == 256 &&
                summary.name_preview_state == kUserPublicNameComplete,
            "exact UTF-8 preview terminator mismatch");
    const char *invalid[] = {"\xC0\x80", "\xED\xA0\x80", "\xF4\x90\x80\x80", "\xE2", "\x80"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        replaceStandaloneName(&user, invalid[i]);
        require(userCopyPublicSummary(&user, 0, &summary) == kUserPublicOk &&
                    summary.name_preview_state == kUserPublicNameInvalidEncoding && summary.name_preview_length == 0,
                "invalid preview was not marked");
        require(userCopyPublicDetail(&user, 4096, 0, &detail) == kUserPublicInvalidEncoding && detail.name == NULL,
                "invalid detail was not refused");
    }
    memset(name, 'a', 256);
    name[256] = (char) 0x80;
    name[257] = 0;
    replaceStandaloneName(&user, name);
    require(userCopyPublicSummary(&user, 0, &summary) == kUserPublicOk &&
                summary.name_preview_state == kUserPublicNameTruncated,
            "preview inspected invalid tail beyond bound");
    userDestroy(&user);
}

static void testPagesAndLocks(void)
{
    users_t users;
    require(usersCreate(&users), "collection creation failed");
    user_public_summary_t entries[100];
    size_t                count = 77, total = 77;
    require(usersCopyPublicPage(&users, 0, 100, 0, entries, &count, &total) == kUserPublicOk && count == 0 &&
                total == 0,
            "empty page mismatch");
    for (size_t i = 1; i <= 103; ++i)
        addUser(&users, i);
    require(usersTryCount(&users, 0, &total) == kUserPublicOk && total == 103, "nonblocking count mismatch");
    require(usersCopyPublicPage(&users, 0, 100, 0, entries, &count, &total) == kUserPublicOk && count == 100 &&
                total == 103 && entries[0].id == 1 && entries[99].id == 100,
            "first indexed range mismatch");
    require(usersCopyPublicPage(&users, 100, 50, 0, entries, &count, &total) == kUserPublicOk && count == 3 &&
                total == 103 && entries[2].id == 103,
            "terminal prefix mismatch");
    require(usersCopyPublicPage(&users, 103, 1, 0, entries, &count, &total) == kUserPublicOk && count == 0 &&
                total == 103,
            "terminal position mismatch");
    require(usersCopyPublicPage(&users, 104, 1, 0, entries, &count, &total) == kUserPublicOutOfRange && count == 0 &&
                total == 0,
            "invalid page position accepted");
    user_public_detail_t detail;
    require(usersCopyPublicDetailByIdentifier(&users, UINT64_MAX, 4096, 0, &detail) == kUserPublicNotFound &&
                detail.name == NULL,
            "absent indexed user mismatch");
    require(usersTryCount(&users, 1, &count) == kUserPublicTimeout && count == 0, "expired count mismatch");
    require(usersCopyPublicPage(&users, 0, 1, 1, entries, &count, &total) == kUserPublicTimeout && count == 0 &&
                total == 0,
            "expired page mismatch");

    lock_holder_t holder;
    /* Lock access is the explicit contention-test seam. Production callers use helpers. */
    holdStart(&holder, &users.lock);
    require(! rwlockTryReadLock(&users.lock), "try-read acquired writer-held lock");
    require(usersTryCount(&users, 0, &count) == kUserPublicBusy && count == 0, "contended count fabricated success");
    require(usersCopyPublicDetailByIdentifier(&users, 1, 4096, 0, &detail) == kUserPublicBusy && detail.name == NULL,
            "detail waited behind collection writer");
    require(usersCopyPublicPage(&users, 0, 2, 0, entries, &count, &total) == kUserPublicBusy && count == 0,
            "page waited behind collection writer");
    holdFinish(&holder);
    require(rwlockTryReadLock(&users.lock), "try-read refused uncontended lock");
    rwlockReadUnlock(&users.lock);
    user_t    *second  = usersLookupByIdentifier(&users, 2);
    wrwlock_t *locks[] = {&second->lock, &second->stats_lock};
    for (size_t i = 0; i < 2; ++i)
    {
        holdStart(&holder, locks[i]);
        require(usersCopyPublicPage(&users, 0, 1, 0, entries, &count, &total) == kUserPublicOk && count == 1,
                "range snapshot inspected an unrequested account");
        require(usersCopyPublicPage(&users, 0, 2, 0, entries, &count, &total) == kUserPublicBusy && count == 0 &&
                    total == 0 && entries[0].id == 0,
                "partial page survived user lock refusal");
        require(usersCopyPublicDetailByIdentifier(&users, 2, 4096, 0, &detail) == kUserPublicBusy &&
                    detail.name == NULL,
                "detail waited behind user writer");
        holdFinish(&holder);
        require(usersCopyPublicDetailByIdentifier(&users, 2, 4096, 0, &detail) == kUserPublicOk,
                "refused snapshot leaked a lock");
        userPublicDetailDestroy(&detail);
    }
    usersDestroy(&users);
}

typedef struct public_writer_s
{
    user_t     *user;
    atomic_bool done;
} public_writer_t;

static WTHREAD_ROUTINE(writePublicValues)
{
    public_writer_t *writer = userdata;
    for (uint64_t value = 1; value <= 4000; ++value)
    {
        rwlockWriteLock(&writer->user->lock);
        rwlockWriteLock(&writer->user->stats_lock);
        writer->user->gid                   = value;
        writer->user->stats.traffic         = (user_ud_t) {.u = value, .d = value * 2};
        writer->user->timeinfo.expire_at_ms = value + 1;
        rwlockWriteUnlock(&writer->user->stats_lock);
        rwlockWriteUnlock(&writer->user->lock);
    }
    atomic_store(&writer->done, true);
    return 0;
}

static void testConcurrentCoherence(void)
{
    user_t user;
    require(userCreate(&user, "private-concurrent-password"), "concurrent user creation failed");
    user.timeinfo.expire_at_ms = 1;
    public_writer_t writer     = {.user = &user};
    atomic_init(&writer.done, false);
    wthread_t thread;
    require(threadCreate(&thread, writePublicValues, &writer) == kWThreadErrorNone, "public writer creation failed");
    do
    {
        user_public_summary_t summary;
        user_public_result_t  result = userCopyPublicSummary(&user, 0, &summary);
        require(result == kUserPublicBusy || result == kUserPublicOk, "concurrent summary returned unexpected refusal");
        if (result == kUserPublicOk)
            require(summary.gid == summary.usage.u && summary.usage.d == summary.gid * 2 &&
                        summary.expire_at_ms == summary.gid + 1,
                    "concurrent summary mixed config and statistics");
        user_public_detail_t detail;
        result = userCopyPublicDetail(&user, 4096, 0, &detail);
        require(result == kUserPublicBusy || result == kUserPublicOk, "concurrent detail returned unexpected refusal");
        if (result == kUserPublicOk)
            require(detail.gid == detail.usage.u && detail.usage.d == detail.gid * 2 &&
                        detail.timeinfo.expire_at_ms == detail.gid + 1,
                    "concurrent detail mixed config and statistics");
        userPublicDetailDestroy(&detail);
    } while (! atomic_load(&writer.done));
    require(threadJoin(thread) == 0, "public writer join failed");
    userDestroy(&user);
}

int main(void)
{
    testCaseSet("user_public_views_test");
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    testOwnedDetail();
    testBoundsAndEncoding();
    testPagesAndLocks();
    testConcurrentCoherence();
    testCachedExportMeasurements();
    puts("user_public_views_test: all checks passed");
    return 0;
}
