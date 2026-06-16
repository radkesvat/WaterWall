#include "objects/users.h"

#include <stdbool.h>
#include <stdint.h>
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

int main(void)
{
    initializeCryptoBackend();
    testRuntimeMigrationPreservesActiveIpOnly();
    testFirstUsageSetIfMissingKeepsServerValue();
    testClientViewExpiryOverridesServerTimeFields();
    testFirstUsagePushRequestFlagIsOneShot();
    return 0;
}
