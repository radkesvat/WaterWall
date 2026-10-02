/*
 * Covers: authenticationclient profile; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: testCopyRefusal, testSuccess, testAbsentFields
 * Checks: Assertion labels include: user construction failed; user insertion failed; alice; profile lookup
 * returned after credential-copy refusal
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.authenticationclient_profile_unit
 */
#include "AuthenticationClient/structure.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "loggers/network_logger.h"

#include <sys/wait.h>
#include <unistd.h>

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

static unsigned fail_copy, copy_calls;


char *__real_stringDuplicate(const char *source);
char *__wrap_stringDuplicate(const char *source);

char *__wrap_stringDuplicate(const char *source)
{
    ++copy_calls;
    if (fail_copy != 0 && copy_calls == fail_copy)
        return NULL;
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
    state->users            = &fixture->users;
    state->users_loaded     = true;
    state->users_generation = 7;
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

static void testCopyRefusal(const profile_fixture_t *fixture)
{
    for (unsigned refuse = 1; refuse <= 2; ++refuse)
    {
        pid_t child = fork();
        require(child >= 0, "failed to fork profile refusal fixture");
        if (child == 0)
        {
            user_handle_t                       handle  = {0};
            authenticationclient_user_profile_t profile = {0};
            copy_calls                                  = 0;
            fail_copy                                   = refuse;
            discard lookup(fixture, &handle, &profile);
            _exit(99); /* Allocation refusal must terminate before lookup returns. */
        }
        int status;
        require(waitpid(child, &status, 0) == child, "failed to join profile refusal fixture");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 1, "profile lookup returned after credential-copy refusal");
    }
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
    authenticationclientUserProfileClear(&profile);
    require(profile.name == NULL && profile.password == NULL, "profile clear left owned fields");

    copy_calls = 0;
    fail_copy  = 1;
    require(lookup(fixture, &handle, NULL) && userHandleIsValid(&handle) && copy_calls == 0,
            "handle-only lookup attempted a profile allocation");
    fail_copy = 0;
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

int main(void)
{
    testCaseSet("authenticationclient_profile_test");
    require(createNetworkLogger(NULL, false) != NULL, "network logger initialization failed");
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");
    for (lookup_kind_t kind = kLookupSha224; kind <= kLookupPassword; ++kind)
    {
        profile_fixture_t fixture;
        fixtureCreate(&fixture, kind);
        testCopyRefusal(&fixture);
        testSuccess(&fixture);
        testAbsentFields(&fixture);
        fixtureDestroy(&fixture);
    }
    wCryptoGlobalCleanup();
    networkloggerDestroy();
    puts("AuthenticationClient credential-copy refusal fails fast");
    return 0;
}
