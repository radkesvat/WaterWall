#include "objects/users.h"
#include "utils/json_helpers.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(WCRYPTO_BACKEND_SODIUM)
#include <sodium.h>
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void initializeCryptoBackend(void)
{
#if defined(WCRYPTO_BACKEND_SODIUM)
    require(sodium_init() != -1, "sodium_init failed");
#endif
}

static user_ip_key_t testIp(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    user_ip_key_t ip = {.type = 4};

    ip.bytes[0] = a;
    ip.bytes[1] = b;
    ip.bytes[2] = c;
    ip.bytes[3] = d;
    return ip;
}

static void testIdentifierLookupAndJsonRoundTrip(void)
{
    users_t users;
    user_t  first;
    user_t  second;
    user_t  duplicate;
    user_t  legacy;
    uint8_t legacy_sha224[SHA224_DIGEST_SIZE] = {0};
    uint8_t legacy_sha256[SHA256_DIGEST_SIZE] = {0};

    memoryZero(&users, sizeof(users));
    memoryZero(&first, sizeof(first));
    memoryZero(&second, sizeof(second));
    memoryZero(&duplicate, sizeof(duplicate));
    memoryZero(&legacy, sizeof(legacy));

    require(usersCreate(&users), "failed to create identifier users table");

    require(userCreate(&first, "identifier-first-password"), "failed to create first identifier user");
    require(userCreate(&second, "identifier-second-password"), "failed to create second identifier user");
    require(userCreate(&duplicate, "identifier-duplicate-password"), "failed to create duplicate identifier user");
    require(userCreate(&legacy, "identifier-legacy-password"), "failed to create legacy identifier user");

    userSetId(&first, 101);
    userSetId(&second, 202);
    userSetId(&duplicate, 101);
    memoryCopy(legacy_sha224, legacy.sha224_pass.bytes, sizeof(legacy_sha224));
    memoryCopy(legacy_sha256, legacy.sha256_pass.bytes, sizeof(legacy_sha256));

    require(usersAddUser(&users, &first), "failed to add first id user");
    require(usersAddUser(&users, &second), "failed to add second id user");
    require(usersAddUser(&users, &legacy), "failed to add legacy id user");
    require(usersAddUserChecked(&users, &duplicate) == kUsersAddResultDuplicateId,
            "duplicate id was not rejected by checked insert");

    user_t *first_lookup = usersLookupByIdentifier(&users, 101);
    user_t *second_lookup = usersLookupByIdentifier(&users, 202);
    require(first_lookup != NULL && userGetId(first_lookup) == 101, "failed to look first user up by id");
    require(second_lookup != NULL && userGetId(second_lookup) == 202, "failed to look second user up by id");
    require(usersLookupByIdentifier(&users, 0) == NULL, "id 0 unexpectedly resolved through id table");
    require(usersLookupBySHA224(&users, legacy_sha224) != NULL, "legacy user did not resolve by SHA-224");
    require(usersLookupBySHA256(&users, legacy_sha256) != NULL, "legacy user did not resolve by SHA-256");

    cJSON *json = userToJson(first_lookup);
    require(json != NULL, "failed to serialize id user");
    require(cJSON_GetObjectItemCaseSensitive(json, "id") != NULL, "serialized id user omitted id");

    user_t parsed;
    memoryZero(&parsed, sizeof(parsed));
    require(userCreateFromJson(&parsed, json), "failed to parse serialized id user");
    require(userGetId(&parsed) == 101, "parsed id user did not preserve id");
    userDestroy(&parsed);
    cJSON_Delete(json);

    userDestroy(&legacy);
    userDestroy(&duplicate);
    userDestroy(&second);
    userDestroy(&first);
    usersDestroy(&users);
}

static void testSHA224LookupAndHashAlignment(void)
{
    users_t users;
    user_t  source_user;
    user_t  duplicate_user;
    uint8_t old_sha224[SHA224_DIGEST_SIZE] = {0};
    uint8_t new_sha224[SHA224_DIGEST_SIZE] = {0};

    require(offsetof(user_t, sha224_pass) % 32U == 0, "user_t SHA-224 field is not 32-byte aligned by layout");
    require(offsetof(user_t, sha256_pass) % 32U == 0, "user_t SHA-256 field is not 32-byte aligned by layout");

    memoryZero(&users, sizeof(users));
    memoryZero(&source_user, sizeof(source_user));
    memoryZero(&duplicate_user, sizeof(duplicate_user));

    require(usersCreate(&users), "failed to create SHA-224 lookup users table");
    require(userCreate(&source_user, "sha224-lookup-password"), "failed to create SHA-224 lookup user");
    require(userCreate(&duplicate_user, "sha224-lookup-password"), "failed to create duplicate SHA-224 lookup user");

    require(((uintptr_t) &source_user.sha224_pass % 32U) == 0, "stack user SHA-224 field is not 32-byte aligned");
    require(((uintptr_t) &source_user.sha256_pass % 32U) == 0, "stack user SHA-256 field is not 32-byte aligned");

    memoryCopy(old_sha224, source_user.sha224_pass.bytes, sizeof(old_sha224));
    require(usersAddUser(&users, &source_user), "failed to add SHA-224 lookup user");
    require(usersAddUserChecked(&users, &duplicate_user) == kUsersAddResultDuplicateSHA224,
            "duplicate SHA-224 lookup key was not rejected by checked insert");

    user_t *lookup = usersLookupBySHA224(&users, old_sha224);
    require(lookup != NULL, "failed to look user up by SHA-224");
    require(lookup == usersLookupBySHA256(&users, source_user.sha256_pass.bytes),
            "SHA-224 and SHA-256 lookup did not resolve the same user");
    require(((uintptr_t) &lookup->sha224_pass % 32U) == 0, "stored user SHA-224 field is not 32-byte aligned");
    require(((uintptr_t) &lookup->sha256_pass % 32U) == 0, "stored user SHA-256 field is not 32-byte aligned");

    cJSON *json = usersUserToJsonBySHA224(&users, old_sha224);
    require(json != NULL, "failed to export user by SHA-224");
    cJSON_Delete(json);

    require(usersChangePassword(&users, lookup, "sha224-lookup-new-password"), "failed to change SHA-224 user password");
    memoryCopy(new_sha224, lookup->sha224_pass.bytes, sizeof(new_sha224));
    require(! memoryEqual(old_sha224, new_sha224, sizeof(old_sha224)),
            "password change did not change SHA-224");
    require(usersLookupBySHA224(&users, old_sha224) == NULL, "old SHA-224 still resolved after password change");
    require(usersLookupBySHA224(&users, new_sha224) == lookup, "new SHA-224 did not resolve after password change");

    userDestroy(&duplicate_user);
    userDestroy(&source_user);
    usersDestroy(&users);
}

static void testRuntimeMigrationPreservesActiveIpOnly(void)
{
    users_t old_users;
    users_t new_users;
    user_t  source_user;
    uint8_t sha256[SHA256_DIGEST_SIZE] = {0};

    memoryZero(&old_users, sizeof(old_users));
    memoryZero(&new_users, sizeof(new_users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&old_users), "failed to create old users table");
    require(usersCreate(&new_users), "failed to create new users table");

    require(userCreate(&source_user, "runtime-migration-password"), "failed to create source user");
    source_user.limit.ips      = 1;
    source_user.limit.cons_out = 2;
    memoryCopy(sha256, source_user.sha256_pass.bytes, sizeof(sha256));

    require(usersAddUser(&old_users, &source_user), "failed to add old user");
    require(usersAddUser(&new_users, &source_user), "failed to add refreshed user");
    userDestroy(&source_user);

    user_ip_key_t ip1 = testIp(10, 0, 0, 1);
    user_ip_key_t ip2 = testIp(10, 0, 0, 2);

    require(usersTryAdmitConnectionBySHA256(&old_users, sha256, &ip1, 1234) == kUserAdmissionOk,
            "old users table did not admit first connection");

    user_t *old_user = usersLookupBySHA256(&old_users, sha256);
    user_t *new_user = usersLookupBySHA256(&new_users, sha256);
    require(old_user != NULL && new_user != NULL, "failed to look users up by SHA-256");
    require(old_user->timeinfo.first_usage_at_ms == 0, "old user first usage was unexpectedly marked");
    require(new_user->timeinfo.first_usage_at_ms == 0, "refreshed user unexpectedly had first usage");

    require(usersMigrateRuntimeStateBySHA256(&new_users, &old_users), "runtime migration failed");

    old_user = usersLookupBySHA256(&old_users, sha256);
    new_user = usersLookupBySHA256(&new_users, sha256);
    require(old_user != NULL && new_user != NULL, "users disappeared after migration");
    require(old_user->runtime.active_cons_out == 0, "old user kept migrated active connection count");
    require(old_user->runtime.ip_usage_count == 0, "old user kept migrated IP usage entries");
    require(new_user->timeinfo.first_usage_at_ms == 0, "new user unexpectedly inherited first usage");

    require(usersTryAdmitConnectionBySHA256(&new_users, sha256, &ip2, 2000) == kUserAdmissionIpLimited,
            "new users table did not enforce migrated active IP usage");

    usersReleaseConnectionBySHA256(&new_users, sha256, &ip1);
    require(usersTryAdmitConnectionBySHA256(&new_users, sha256, &ip2, 2000) == kUserAdmissionOk,
            "new users table did not release migrated active IP usage");
    usersReleaseConnectionBySHA256(&new_users, sha256, &ip2);

    usersDestroy(&new_users);
    usersDestroy(&old_users);
}

static void testRuntimeMigrationPrefersIdentifierAcrossPasswordChange(void)
{
    users_t old_users;
    users_t new_users;
    user_t  old_source;
    user_t  new_source;
    uint8_t old_sha256[SHA256_DIGEST_SIZE] = {0};
    uint8_t new_sha256[SHA256_DIGEST_SIZE] = {0};
    const uint64_t user_id                 = 9001;

    memoryZero(&old_users, sizeof(old_users));
    memoryZero(&new_users, sizeof(new_users));
    memoryZero(&old_source, sizeof(old_source));
    memoryZero(&new_source, sizeof(new_source));

    require(usersCreate(&old_users), "failed to create old id migration users table");
    require(usersCreate(&new_users), "failed to create new id migration users table");

    require(userCreate(&old_source, "id-migration-old-password"), "failed to create old id migration user");
    require(userCreate(&new_source, "id-migration-new-password"), "failed to create new id migration user");
    userSetId(&old_source, user_id);
    userSetId(&new_source, user_id);
    old_source.limit.ips      = 1;
    old_source.limit.cons_out = 2;
    new_source.limit.ips      = 1;
    new_source.limit.cons_out = 2;
    memoryCopy(old_sha256, old_source.sha256_pass.bytes, sizeof(old_sha256));
    memoryCopy(new_sha256, new_source.sha256_pass.bytes, sizeof(new_sha256));

    require(usersAddUser(&old_users, &old_source), "failed to add old id migration user");
    require(usersAddUser(&new_users, &new_source), "failed to add new id migration user");
    userDestroy(&new_source);
    userDestroy(&old_source);

    user_ip_key_t ip1 = testIp(10, 1, 0, 1);
    user_ip_key_t ip2 = testIp(10, 1, 0, 2);

    require(usersTryAdmitConnectionByIdentifier(&old_users, user_id, &ip1, 1234) == kUserAdmissionOk,
            "old id users table did not admit first connection");

    require(usersLookupBySHA256(&new_users, old_sha256) == NULL, "new users table unexpectedly had old SHA-256");
    require(usersLookupBySHA256(&new_users, new_sha256) != NULL, "new users table did not have new SHA-256");

    require(usersMigrateRuntimeStateByIdentifier(&new_users, &old_users),
            "id-preferring runtime migration failed");

    user_t *old_user = usersLookupByIdentifier(&old_users, user_id);
    user_t *new_user = usersLookupByIdentifier(&new_users, user_id);
    require(old_user != NULL && new_user != NULL, "id migration users disappeared after migration");
    require(old_user->runtime.active_cons_out == 0, "old id user kept migrated active connection count");
    require(new_user->runtime.active_cons_out == 1, "new id user did not receive active connection count");

    require(usersTryAdmitConnectionByIdentifier(&new_users, user_id, &ip2, 2000) == kUserAdmissionIpLimited,
            "new id users table did not enforce migrated active IP usage");

    usersReleaseConnectionByIdentifier(&new_users, user_id, &ip1);
    require(usersTryAdmitConnectionByIdentifier(&new_users, user_id, &ip2, 2000) == kUserAdmissionOk,
            "new id users table did not release migrated active IP usage");
    usersReleaseConnectionByIdentifier(&new_users, user_id, &ip2);

    usersDestroy(&new_users);
    usersDestroy(&old_users);
}

static void testIdentifierLookupSurvivesPasswordChange(void)
{
    users_t users;
    user_t  source_user;
    uint8_t old_sha256[SHA256_DIGEST_SIZE] = {0};
    uint8_t new_sha256[SHA256_DIGEST_SIZE] = {0};
    const uint64_t user_id                 = 777;

    memoryZero(&users, sizeof(users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&users), "failed to create password-change users table");
    require(userCreate(&source_user, "id-password-change-old"), "failed to create password-change user");
    userSetId(&source_user, user_id);
    memoryCopy(old_sha256, source_user.sha256_pass.bytes, sizeof(old_sha256));
    require(usersAddUser(&users, &source_user), "failed to add password-change user");
    userDestroy(&source_user);

    user_ip_key_t ip = testIp(10, 2, 0, 1);
    require(usersTryAdmitConnectionByIdentifier(&users, user_id, &ip, 1000) == kUserAdmissionOk,
            "id user was not admitted before password change");

    user_t *user = usersLookupByIdentifier(&users, user_id);
    require(user != NULL, "failed to look id user up before password change");
    require(usersChangePassword(&users, user, "id-password-change-new"), "failed to change id user password");

    user = usersLookupByIdentifier(&users, user_id);
    require(user != NULL, "failed to look id user up after password change");
    memoryCopy(new_sha256, user->sha256_pass.bytes, sizeof(new_sha256));
    require(! memoryEqual(old_sha256, new_sha256, sizeof(old_sha256)), "password change did not change SHA-256");
    require(usersLookupBySHA256(&users, old_sha256) == NULL, "old SHA-256 still resolved after password change");
    require(usersLookupBySHA256(&users, new_sha256) == user, "new SHA-256 did not resolve after password change");
    require(user->runtime.active_cons_out == 1, "id user lost runtime state after password change");

    usersReleaseConnectionByIdentifier(&users, user_id, &ip);
    require(usersRuntimeShouldCloseByIdentifier(&users, user_id, 2000) == false,
            "id user unexpectedly needed close after password change");

    usersDestroy(&users);
}

static void testFirstUsageSetIfMissingKeepsServerValue(void)
{
    users_t users;
    user_t  source_user;
    uint8_t sha256[SHA256_DIGEST_SIZE] = {0};
    bool    changed                    = false;

    memoryZero(&users, sizeof(users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&users), "failed to create users table");
    require(userCreate(&source_user, "first-usage-set-missing-password"), "failed to create merge source user");
    memoryCopy(sha256, source_user.sha256_pass.bytes, sizeof(sha256));
    require(usersAddUser(&users, &source_user), "failed to add merge user");
    userDestroy(&source_user);

    require(usersSetFirstUsageIfMissingBySHA256(&users, sha256, 5000, &changed) == kUsersUpdateResultOk,
            "failed to set initial first usage");
    require(changed, "initial first usage set did not report a change");

    user_t *user = usersLookupBySHA256(&users, sha256);
    require(user != NULL, "failed to look up merge user");
    user_time_info_t timeinfo = {0};
    userGetTimeInfo(user, &timeinfo);
    require(timeinfo.first_usage_at_ms == 5000, "initial first usage was not stored");

    require(usersSetFirstUsageIfMissingBySHA256(&users, sha256, 7000, &changed) == kUsersUpdateResultOk,
            "failed to ignore later first usage");
    require(! changed, "later first usage unexpectedly reported a change");
    userGetTimeInfo(user, &timeinfo);
    require(timeinfo.first_usage_at_ms == 5000, "later first usage replaced an earlier value");

    require(usersSetFirstUsageIfMissingBySHA256(&users, sha256, 3000, &changed) == kUsersUpdateResultOk,
            "failed to ignore earlier first usage");
    require(! changed, "earlier first usage unexpectedly reported a change");
    userGetTimeInfo(user, &timeinfo);
    require(timeinfo.first_usage_at_ms == 5000, "earlier first usage replaced the server value");

    usersDestroy(&users);
}

static void testClientViewExpiryOverridesServerTimeFields(void)
{
    user_t user;

    memoryZero(&user, sizeof(user));
    require(userCreate(&user, "client-view-expiry-password"), "failed to create client view user");
    user.timeinfo.expire_at_ms = 1000;

    require(! userIsExpired(&user, 999), "server-clock expiry fired too early");
    require(userIsExpired(&user, 1000), "server-clock expiry did not fire");

    userSetClientViewExpiry(&user, 5000, true);
    require(! userIsExpired(&user, 4999), "client-view expiry fired too early");
    require(userIsExpired(&user, 5000), "client-view expiry did not fire");

    userSetClientViewExpiry(&user, 0, true);
    require(! userIsExpired(&user, UINT64_MAX), "client-view no-expiry still used server time fields");

    userSetClientViewExpiry(&user, 0, false);
    require(userIsExpired(&user, 1000), "clearing client view did not restore server-clock expiry");

    userDestroy(&user);
}

static void testZeroUserLimitsAreUnlimited(void)
{
    static const char json_text[] =
        "{"
        "\"password\":\"zero-limit-password\","
        "\"limit\":{"
        "\"traffic\":{\"up\":0,\"down\":0,\"total\":0},"
        "\"bandwidth\":{\"up\":0,\"down\":0},"
        "\"ips\":0,"
        "\"devices\":0,"
        "\"connections-in\":0,"
        "\"connections-out\":0"
        "},"
        "\"stats\":{"
        "\"traffic\":{\"up\":\"18446744073709551615\",\"down\":\"18446744073709551615\"},"
        "\"speed\":{\"up\":\"18446744073709551615\",\"down\":\"18446744073709551615\"},"
        "\"ips\":\"18446744073709551615\","
        "\"devices\":\"18446744073709551615\","
        "\"connections-in\":\"18446744073709551615\","
        "\"connections-out\":\"18446744073709551615\""
        "}"
        "}";

    cJSON *json = cJSON_Parse(json_text);
    require(json != NULL, "failed to parse zero-limit user JSON");

    user_t user;
    memoryZero(&user, sizeof(user));
    require(userCreateFromJson(&user, json), "failed to create zero-limit user from JSON");
    cJSON_Delete(json);

    require(! userHasReachedTrafficLimit(&user), "zero traffic limits were treated as reached");
    require(! userHasReachedBandwidthLimit(&user), "zero bandwidth limits were treated as reached");
    require(! userHasReachedLimit(&user), "zero aggregate limits were treated as reached");
    require(userIsActive(&user, UINT64_MAX), "zero-limit user was not active");

    user_ip_key_t ip1 = testIp(192, 0, 2, 1);
    user_ip_key_t ip2 = testIp(192, 0, 2, 2);

    require(userTryAdmitConnection(&user, &ip1, UINT64_MAX) == kUserAdmissionOk,
            "zero connection/ip limits rejected first connection");
    require(userTryAdmitConnection(&user, &ip2, UINT64_MAX) == kUserAdmissionOk,
            "zero connection/ip limits rejected second distinct IP");
    require(! userAccountTraffic(&user, UINT64_MAX, UINT64_MAX, UINT64_MAX, NULL),
            "zero traffic limits closed after additional traffic");
    require(! userRuntimeShouldClose(&user, UINT64_MAX), "zero traffic limits required runtime close");

    userReleaseConnection(&user, &ip2);
    userReleaseConnection(&user, &ip1);
    userDestroy(&user);
}

static void testTotalTrafficLimitCountsUploadAndDownload(void)
{
    user_t user;

    memoryZero(&user, sizeof(user));
    require(userCreate(&user, "total-traffic-limit-password"), "failed to create total traffic limit user");
    user.limit.traffic.u     = USER_NO_LIMIT;
    user.limit.traffic.d     = USER_NO_LIMIT;
    user.limit.traffic.total = 100;

    require(! userHasReachedTrafficLimit(&user), "fresh total-limit user unexpectedly reached traffic limit");
    require(! userAccountTraffic(&user, 99, 0, 0, NULL), "upload below total limit closed user");
    require(! userHasReachedTrafficLimit(&user), "upload below total limit reached traffic limit");
    require(userAccountTraffic(&user, 1, 0, 0, NULL), "upload reaching total limit did not close user");
    require(userHasReachedTrafficLimit(&user), "upload reaching total limit did not mark limit reached");
    userDestroy(&user);

    memoryZero(&user, sizeof(user));
    require(userCreate(&user, "total-traffic-download-limit-password"),
            "failed to create download total traffic limit user");
    user.limit.traffic.total = 100;

    require(! userAccountTraffic(&user, 0, 99, 0, NULL), "download below total limit closed user");
    require(userAccountTraffic(&user, 0, 1, 0, NULL), "download reaching total limit did not close user");
    userDestroy(&user);

    memoryZero(&user, sizeof(user));
    require(userCreate(&user, "total-traffic-mixed-limit-password"),
            "failed to create mixed total traffic limit user");
    user.limit.traffic.total = 100;

    require(! userAccountTraffic(&user, 40, 59, 0, NULL), "mixed traffic below total limit closed user");
    require(userAccountTraffic(&user, 0, 1, 0, NULL), "mixed traffic reaching total limit did not close user");
    userDestroy(&user);
}

static void testFirstUsagePushRequestFlagIsOneShot(void)
{
    users_t users;
    user_t  source_user;
    uint8_t sha256[SHA256_DIGEST_SIZE] = {0};
    bool    needed                    = false;

    memoryZero(&users, sizeof(users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&users), "failed to create first usage push users table");
    require(userCreate(&source_user, "first-usage-push-flag-password"),
            "failed to create first usage push flag user");
    memoryCopy(sha256, source_user.sha256_pass.bytes, sizeof(sha256));
    require(usersAddUser(&users, &source_user), "failed to add first usage push flag user");
    userDestroy(&source_user);

    require(! usersAccountTrafficBySHA256(&users, sha256, 0, 0, 0, NULL, &needed),
            "zero traffic unexpectedly closed user");
    require(! needed, "zero traffic requested first usage push");

    require(! usersAccountTrafficBySHA256(&users, sha256, 10, 0, 0, NULL, &needed),
            "first traffic unexpectedly closed user");
    require(needed, "first non-zero traffic did not request first usage push");

    needed = false;
    require(! usersAccountTrafficBySHA256(&users, sha256, 1, 0, 0, NULL, &needed),
            "second traffic unexpectedly closed user");
    require(! needed, "first usage push request was not one-shot");

    usersResetFirstUsagePushRequestBySHA256(&users, sha256);
    needed = false;
    require(! usersAccountTrafficBySHA256(&users, sha256, 1, 0, 0, NULL, &needed),
            "traffic after per-user reset unexpectedly closed user");
    require(needed, "per-user reset did not re-enable first usage push request");

    needed = false;
    require(! usersAccountTrafficBySHA256(&users, sha256, 1, 0, 0, NULL, &needed),
            "traffic after per-user retry unexpectedly closed user");
    require(! needed, "per-user reset allowed more than one retry");

    usersResetFirstUsagePushRequests(&users);
    needed = false;
    require(! usersAccountTrafficBySHA256(&users, sha256, 1, 0, 0, NULL, &needed),
            "traffic after table reset unexpectedly closed user");
    require(needed, "table reset did not re-enable first usage push request");

    usersDestroy(&users);
}

static void testTrafficStatsJsonUsesExactBytes(void)
{
    const uint64_t upload_bytes   = 1024ULL * 1024ULL + 123ULL;
    const uint64_t download_bytes = 2ULL * 1024ULL * 1024ULL + 456ULL;
    user_t         user;

    memoryZero(&user, sizeof(user));
    require(userCreate(&user, "traffic-json-bytes-password"), "failed to create byte stats user");

    require(! userAccountTraffic(&user, upload_bytes, download_bytes, 0, NULL),
            "byte stats accounting unexpectedly closed user");

    user_stat_t stats = {0};
    userGetStats(&user, &stats);
    require(stats.traffic.u == upload_bytes, "upload traffic counter was not stored as exact bytes");
    require(stats.traffic.d == download_bytes, "download traffic counter was not stored as exact bytes");

    cJSON *json = userToJson(&user);
    require(json != NULL, "failed to serialize byte stats user");

    const cJSON *stats_json = cJSON_GetObjectItemCaseSensitive(json, "stats");
    require(cJSON_IsObject(stats_json), "serialized byte stats omitted stats object");

    const cJSON *traffic_json = cJSON_GetObjectItemCaseSensitive(stats_json, "traffic");
    require(cJSON_IsObject(traffic_json), "serialized byte stats omitted traffic object");

    uint64_t serialized_upload   = 0;
    uint64_t serialized_download = 0;
    require(getUint64FromJson(&serialized_upload, cJSON_GetObjectItemCaseSensitive(traffic_json, "up")),
            "serialized upload traffic was not a valid uint64");
    require(getUint64FromJson(&serialized_download, cJSON_GetObjectItemCaseSensitive(traffic_json, "down")),
            "serialized download traffic was not a valid uint64");
    require(serialized_upload == upload_bytes, "serialized upload traffic was scaled instead of byte-exact");
    require(serialized_download == download_bytes, "serialized download traffic was scaled instead of byte-exact");

    cJSON_Delete(json);
    userDestroy(&user);
}

int main(void)
{
    initializeCryptoBackend();
    testIdentifierLookupAndJsonRoundTrip();
    testSHA224LookupAndHashAlignment();
    testRuntimeMigrationPreservesActiveIpOnly();
    testRuntimeMigrationPrefersIdentifierAcrossPasswordChange();
    testIdentifierLookupSurvivesPasswordChange();
    testFirstUsageSetIfMissingKeepsServerValue();
    testClientViewExpiryOverridesServerTimeFields();
    testZeroUserLimitsAreUnlimited();
    testTotalTrafficLimitCountsUploadAndDownload();
    testFirstUsagePushRequestFlagIsOneShot();
    testTrafficStatsJsonUsesExactBytes();
    return 0;
}
