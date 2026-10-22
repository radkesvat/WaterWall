/*
 * Covers: users runtime migration; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Cases: testDuplicateCredentialLogsOmitCredentials, testCryptoFailureDoesNotPublishCredentials,
 * testIdentifierLookupAndJsonRoundTrip, testSHA224LookupAndHashAlignment,
 * testJsonFeedRejectsDuplicateKeysWithoutTerminating, testUUIDCredentialLookupAndDerivation,
 * testUUIDLookupUpdatesOnPasswordChange, testWireGuardPublicKeyLookupAndDerivation; the driver lists the
 * remaining cases
 * Checks: Assertion labels include: duplicate-log JSON feed unexpectedly worked; duplicate SHA-224 lookup
 * key; log-second; duplicate SHA-224 diagnostic exposed the plaintext password
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.users_runtime_migration_unit
 * Organization: Credential changes, runtime-state migration and JSON round trips use one users table and
 * the same lock/statistics observations; the driver names the independent resettable cases.
 */
#include "loggers/internal_logger.h"

#include "fixtures/user_runtime.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "wwapi.h"

#if defined(WCRYPTO_TEST_LINKER_WRAP)
static atomic_bool   client_clock_test;
static atomic_ullong client_clock_ms;
static atomic_ullong client_wall_ms;
static atomic_bool   client_wall_test;
int                  __real_gettimeofday(struct timeval *tv, void *tz);
int                  __wrap_gettimeofday(struct timeval *tv, void *tz);
int                  __wrap_gettimeofday(struct timeval *tv, void *tz)
{
    if (! atomic_load(&client_wall_test))
        return __real_gettimeofday(tv, tz);
    uint64_t now = atomic_load(&client_wall_ms);
    tv->tv_sec   = (time_t) (now / 1000U);
    tv->tv_usec  = (suseconds_t) ((now % 1000U) * 1000U);
    return 0;
}
unsigned long long __real_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void);
unsigned long long __wrap_getHRTimeUs(void)
{
    return atomic_load(&client_clock_test) ? atomic_load(&client_clock_ms) * 1000ULL : __real_getHRTimeUs();
}

typedef enum crypto_failure_injection_e
{
    kCryptoFailureNone,
    kCryptoFailureSha224,
    kCryptoFailureSha256,
    kCryptoFailureX25519,
} crypto_failure_injection_t;

static crypto_failure_injection_t crypto_failure_injection;

wcrypto_status_t __real_wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen);
wcrypto_status_t __real_wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen);
wcrypto_status_t __real_wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE]);
wcrypto_status_t __wrap_wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen);
wcrypto_status_t __wrap_wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen);
wcrypto_status_t __wrap_wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE]);

wcrypto_status_t __wrap_wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
    if (crypto_failure_injection == kCryptoFailureSha224)
    {
        if (out != NULL)
        {
            memoryZero(out, sizeof(*out));
        }
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoSHA224(out, in, inlen);
}

wcrypto_status_t __wrap_wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    if (crypto_failure_injection == kCryptoFailureSha256)
    {
        if (out != NULL)
        {
            memoryZero(out, sizeof(*out));
        }
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoSHA256(out, in, inlen);
}

wcrypto_status_t __wrap_wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE])
{
    if (crypto_failure_injection == kCryptoFailureX25519)
    {
        if (out != NULL)
        {
            memoryZero(out, WCRYPTO_X25519_KEY_SIZE);
        }
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoX25519(out, scalar, point);
}
#endif

enum
{
    kTestLogCaptureCapacity          = 4096,
    kRuntimeMigrationLockProbeMs     = 200,
    kRuntimeMigrationLockPollDelayMs = 1
};

static char   test_log_capture[kTestLogCaptureCapacity];
static size_t test_log_capture_len;
static bool   test_log_capture_enabled;

static void testLogCaptureHandler(int loglevel, const char *buf, int len)
{
    discard loglevel;

    if (! test_log_capture_enabled || buf == NULL || len <= 0 || test_log_capture_len >= sizeof(test_log_capture) - 1U)
    {
        return;
    }

    size_t copy_len = min((size_t) len, sizeof(test_log_capture) - test_log_capture_len - 1U);
    memoryCopy(test_log_capture + test_log_capture_len, buf, copy_len);
    test_log_capture_len += copy_len;
    test_log_capture[test_log_capture_len] = '\0';
}

static void testLogCaptureBegin(void)
{
    memoryZero(test_log_capture, sizeof(test_log_capture));
    test_log_capture_len     = 0;
    test_log_capture_enabled = true;
}

static void testLogCaptureEnd(void)
{
    test_log_capture_enabled = false;
}

static void testDuplicateCredentialLogsOmitCredentials(void)
{
    static const char duplicate_password[] = "credential-log-regression-password";
    static const char duplicate_sha_json[] =
        "{\"users\":["
        "{\"name\":\"log-first\",\"password\":\"credential-log-regression-password\"},"
        "{\"name\":\"log-second\",\"password\":\"credential-log-regression-password\"}"
        "]}";
    static const char uuid_a[]                                 = "84949cc5-4701-4a84-895b-354c584a981b";
    static const char uuid_b[]                                 = "7783a3e7-e373-51cd-8642-c83782b807c5";
    static const char uuid_b_uppercase[]                       = "7783A3E7-E373-51CD-8642-C83782B807C5";
    sha224_hash_t     sha224                                   = {0};
    sha256_hash_t     sha256                                   = {0};
    char              sha224_hex[SHA224_DIGEST_SIZE * 2U + 1U] = {0};
    char              sha256_hex[SHA256_DIGEST_SIZE * 2U + 1U] = {0};
    uint8_t           uuid_a_bytes[kWwUuidBytesLen]            = {0};
    users_t           users;
    user_t            first_source;
    user_t            second_source;

    require(wCryptoSHA224(&sha224, (const unsigned char *) duplicate_password, stringLength(duplicate_password)) ==
                kWCryptoOk,
            "failed to derive duplicate-log SHA-224 test credential");
    require(wCryptoSHA256(&sha256, (const unsigned char *) duplicate_password, stringLength(duplicate_password)) ==
                kWCryptoOk,
            "failed to derive duplicate-log SHA-256 test credential");
    asciiHexEncodeBytesLower(sha224.bytes, SHA224_DIGEST_SIZE, (uint8_t *) sha224_hex);
    asciiHexEncodeBytesLower(sha256.bytes, SHA256_DIGEST_SIZE, (uint8_t *) sha256_hex);

    memoryZero(&users, sizeof(users));
    require(usersCreate(&users), "failed to create duplicate-log users table");

    cJSON *json = cJSON_Parse(duplicate_sha_json);
    require(json != NULL, "failed to parse duplicate-log users JSON");
    testLogCaptureBegin();
    require(! usersFeedJson(&users, json), "duplicate-log JSON feed unexpectedly worked");
    testLogCaptureEnd();
    cJSON_Delete(json);

    require(strstr(test_log_capture, "duplicate SHA-224 lookup key") != NULL,
            "duplicate SHA-224 load did not produce a diagnostic");
    require(strstr(test_log_capture, "log-second") != NULL, "duplicate SHA-224 diagnostic omitted the affected user");
    require(strstr(test_log_capture, duplicate_password) == NULL,
            "duplicate SHA-224 diagnostic exposed the plaintext password");
    require(strstr(test_log_capture, sha224_hex) == NULL, "duplicate SHA-224 diagnostic exposed the bearer credential");
    require(strstr(test_log_capture, sha256_hex) == NULL,
            "duplicate SHA-224 diagnostic exposed the SHA-256 credential");

    memoryZero(&first_source, sizeof(first_source));
    memoryZero(&second_source, sizeof(second_source));
    require(userCreate(&first_source, uuid_a), "failed to create first duplicate-log UUID user");
    require(userCreate(&second_source, uuid_b), "failed to create second duplicate-log UUID user");
    require(usersAddUser(&users, &first_source), "failed to add first duplicate-log UUID user");
    require(usersAddUser(&users, &second_source), "failed to add second duplicate-log UUID user");
    userDestroy(&second_source);
    userDestroy(&first_source);

    require(wwUuidParseString(uuid_a, uuid_a_bytes), "failed to parse first duplicate-log UUID");
    user_t *first = usersLookupByUUID(&users, uuid_a_bytes);
    require(first != NULL, "failed to look up first duplicate-log UUID user");

    testLogCaptureBegin();
    require(! usersChangePassword(&users, first, uuid_b_uppercase),
            "duplicate-log UUID password update unexpectedly worked");
    testLogCaptureEnd();

    require(strstr(test_log_capture, "duplicate UUID credential while updating user") != NULL,
            "duplicate UUID update did not produce a diagnostic");
    require(strstr(test_log_capture, uuid_b) == NULL, "duplicate UUID diagnostic exposed the canonical credential");
    require(strstr(test_log_capture, uuid_b_uppercase) == NULL,
            "duplicate UUID diagnostic exposed the submitted credential");

    usersDestroy(&users);
    memorySecureZero(&sha224, sizeof(sha224));
    memorySecureZero(&sha256, sizeof(sha256));
    memorySecureZero(sha224_hex, sizeof(sha224_hex));
    memorySecureZero(sha256_hex, sizeof(sha256_hex));
    memorySecureZero(uuid_a_bytes, sizeof(uuid_a_bytes));
}

static bool testBytesAreZero(const void *bytes, size_t len)
{
    const uint8_t *cursor = bytes;
    uint8_t        value  = 0;
    for (size_t i = 0; i < len; ++i)
    {
        value |= cursor[i];
    }
    return value == 0;
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

static void deriveWireGuardPublicKey(const char *password, uint8_t out[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    static const uint8_t basepoint[USER_WIREGUARD_PUBLICKEY_SIZE] = {9};
    sha256_hash_t        sha256                                   = {0};

    require(wCryptoSHA256(&sha256, (const unsigned char *) password, stringLength(password)) == kWCryptoOk,
            "failed to derive WireGuard private key seed");
    require(wCryptoX25519(out, sha256.bytes, basepoint) == kWCryptoOk, "failed to derive WireGuard public key");
    memoryZero(&sha256, sizeof(sha256));
}

static void testCryptoFailureDoesNotPublishCredentials(void)
{
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    static const crypto_failure_injection_t failures[] = {
        kCryptoFailureSha224,
        kCryptoFailureSha256,
        kCryptoFailureX25519,
    };

    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i)
    {
        user_t rejected;
        memorySet(&rejected, 0xa5, sizeof(rejected));
        crypto_failure_injection = failures[i];
        require(! userCreate(&rejected, "crypto-failure-new-password"),
                "user creation published a crypto derivation failure");
        crypto_failure_injection = kCryptoFailureNone;
        require(! rejected.initialized && rejected.password == NULL && ! rejected.sha224_pass_valid &&
                    ! rejected.sha256_pass_valid && ! rejected.wireguard_publickey_valid &&
                    testBytesAreZero(&rejected.sha224_pass, sizeof(rejected.sha224_pass)) &&
                    testBytesAreZero(&rejected.sha256_pass, sizeof(rejected.sha256_pass)) &&
                    testBytesAreZero(rejected.wireguard_publickey, sizeof(rejected.wireguard_publickey)),
                "failed user creation retained derived credentials");

        user_t existing;
        memoryZero(&existing, sizeof(existing));
        require(userCreate(&existing, "crypto-failure-old-password"), "failed to create crypto-failure update fixture");
        sha224_hash_t old_sha224 = existing.sha224_pass;
        sha256_hash_t old_sha256 = existing.sha256_pass;
        uint8_t       old_wireguard[USER_WIREGUARD_PUBLICKEY_SIZE];
        memoryCopy(old_wireguard, existing.wireguard_publickey, sizeof(old_wireguard));

        crypto_failure_injection = failures[i];
        require(! userChangePassword(&existing, "crypto-failure-replacement-password"),
                "password update published a crypto derivation failure");
        crypto_failure_injection = kCryptoFailureNone;
        require(userPasswordMatches(&existing, "crypto-failure-old-password") &&
                    ! userPasswordMatches(&existing, "crypto-failure-replacement-password") &&
                    memoryEqual(&existing.sha224_pass, &old_sha224, sizeof(old_sha224)) &&
                    memoryEqual(&existing.sha256_pass, &old_sha256, sizeof(old_sha256)) &&
                    memoryEqual(existing.wireguard_publickey, old_wireguard, sizeof(old_wireguard)),
                "failed password update changed published credentials");
        userDestroy(&existing);
    }
#endif
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
    require(! usersAddUser(&users, &duplicate), "duplicate id legacy insert unexpectedly worked");
    require(usersCount(&users) == 3, "duplicate id legacy insert changed the users table");

    user_t *first_lookup  = usersLookupByIdentifier(&users, 101);
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
    require(! usersAddUser(&users, &duplicate_user), "duplicate SHA legacy insert unexpectedly worked");
    require(usersCount(&users) == 1, "duplicate SHA legacy insert changed the users table");

    user_t *lookup = usersLookupBySHA224(&users, old_sha224);
    require(lookup != NULL, "failed to look user up by SHA-224");
    require(lookup == usersLookupBySHA256(&users, source_user.sha256_pass.bytes),
            "SHA-224 and SHA-256 lookup did not resolve the same user");
    require(((uintptr_t) &lookup->sha224_pass % 32U) == 0, "stored user SHA-224 field is not 32-byte aligned");
    require(((uintptr_t) &lookup->sha256_pass % 32U) == 0, "stored user SHA-256 field is not 32-byte aligned");

    cJSON *json = usersUserToJsonBySHA224(&users, old_sha224);
    require(json != NULL, "failed to export user by SHA-224");
    cJSON_Delete(json);

    require(usersChangePassword(&users, lookup, "sha224-lookup-new-password"),
            "failed to change SHA-224 user password");
    memoryCopy(new_sha224, lookup->sha224_pass.bytes, sizeof(new_sha224));
    require(! memoryEqual(old_sha224, new_sha224, sizeof(old_sha224)), "password change did not change SHA-224");
    require(usersLookupBySHA224(&users, old_sha224) == NULL, "old SHA-224 still resolved after password change");
    require(usersLookupBySHA224(&users, new_sha224) == lookup, "new SHA-224 did not resolve after password change");

    userDestroy(&duplicate_user);
    userDestroy(&source_user);
    usersDestroy(&users);
}

static void testJsonFeedRejectsDuplicateKeysWithoutTerminating(void)
{
    static const char duplicate_sha_json[] = "{\"users\":["
                                             "{\"id\":5101,\"password\":\"json-duplicate-password\"},"
                                             "{\"id\":5102,\"password\":\"json-duplicate-password\"}"
                                             "]}";
    static const char duplicate_id_json[]  = "{\"users\":["
                                             "{\"id\":5201,\"password\":\"json-duplicate-id-a\"},"
                                             "{\"id\":5201,\"password\":\"json-duplicate-id-b\"}"
                                             "]}";
    users_t           users;
    user_t            seed;

    memoryZero(&users, sizeof(users));
    memoryZero(&seed, sizeof(seed));

    require(usersCreate(&users), "failed to create duplicate JSON users table");
    require(userCreate(&seed, "json-feed-seed-password"), "failed to create duplicate JSON seed user");
    userSetId(&seed, 5001);
    require(usersAddUser(&users, &seed), "failed to add duplicate JSON seed user");
    userDestroy(&seed);

    cJSON *json = cJSON_Parse(duplicate_sha_json);
    require(json != NULL, "failed to parse duplicate SHA JSON");
    require(! usersFeedJson(&users, json), "duplicate SHA JSON feed unexpectedly worked");
    cJSON_Delete(json);
    require(usersCount(&users) == 1, "duplicate SHA JSON feed did not roll back");
    require(usersLookupByIdentifier(&users, 5001) != NULL, "duplicate SHA JSON feed lost existing user");

    json = cJSON_Parse(duplicate_id_json);
    require(json != NULL, "failed to parse duplicate id JSON");
    require(! usersFeedJson(&users, json), "duplicate id JSON feed unexpectedly worked");
    cJSON_Delete(json);
    require(usersCount(&users) == 1, "duplicate id JSON feed did not roll back");
    require(usersLookupByIdentifier(&users, 5001) != NULL, "duplicate id JSON feed lost existing user");

    usersDestroy(&users);
}

static void testUUIDCredentialLookupAndDerivation(void)
{
    static const char canonical_uuid[]               = "84949cc5-4701-4a84-895b-354c584a981b";
    static const char uppercase_uuid[]               = "84949CC5-4701-4A84-895B-354C584A981B";
    static const char compact_uuid[]                 = "84949cc547014a84895b354c584a981b";
    uint8_t           expected_uuid[kWwUuidBytesLen] = {0};
    users_t           users;
    user_t            canonical_user;
    user_t            uppercase_user;
    user_t            compact_user;
    user_t            plain_user;

    memoryZero(&users, sizeof(users));
    memoryZero(&canonical_user, sizeof(canonical_user));
    memoryZero(&uppercase_user, sizeof(uppercase_user));
    memoryZero(&compact_user, sizeof(compact_user));
    memoryZero(&plain_user, sizeof(plain_user));

    require(wwUuidParseString(canonical_uuid, expected_uuid), "failed to parse expected UUID");
    require(usersCreate(&users), "failed to create UUID lookup users table");
    require(userCreate(&canonical_user, canonical_uuid), "failed to create canonical UUID user");
    require(userCreate(&uppercase_user, uppercase_uuid), "failed to create uppercase UUID user");
    require(userCreate(&compact_user, compact_uuid), "failed to create compact UUID user");
    require(userCreate(&plain_user, "plain-non-uuid-password"), "failed to create plain password user");

    userSetId(&canonical_user, 3001);
    userSetId(&uppercase_user, 3002);
    userSetId(&compact_user, 3003);
    userSetId(&plain_user, 3004);

    require(canonical_user.uuid_pass_valid, "canonical UUID password did not derive UUID bytes");
    require(uppercase_user.uuid_pass_valid, "uppercase UUID password did not derive UUID bytes");
    require(compact_user.uuid_pass_valid, "compact UUID password did not derive UUID bytes");
    require(! plain_user.uuid_pass_valid, "plain password unexpectedly derived UUID bytes");
    require(memoryEqual(canonical_user.uuid_pass, expected_uuid, sizeof(expected_uuid)),
            "canonical UUID bytes were not derived as expected");
    require(memoryEqual(uppercase_user.uuid_pass, expected_uuid, sizeof(expected_uuid)),
            "uppercase UUID bytes did not match canonical bytes");
    require(memoryEqual(compact_user.uuid_pass, expected_uuid, sizeof(expected_uuid)),
            "compact UUID bytes did not match canonical bytes");

    require(usersAddUser(&users, &canonical_user), "failed to add canonical UUID user");
    require(usersAddUser(&users, &plain_user), "failed to add plain password user");
    require(usersLookupByUUID(&users, expected_uuid) != NULL, "failed to look user up by UUID");
    require(usersAddUserChecked(&users, &uppercase_user) == kUsersAddResultDuplicateUUID,
            "uppercase UUID duplicate was not rejected");
    require(usersAddUserChecked(&users, &compact_user) == kUsersAddResultDuplicateUUID,
            "compact UUID duplicate was not rejected");

    user_t *lookup = usersLookupByUUID(&users, expected_uuid);
    require(lookup != NULL && userGetId(lookup) == 3001, "UUID lookup returned the wrong user");

    cJSON *json = userToJson(lookup);
    require(json != NULL, "failed to serialize UUID user");
    require(cJSON_GetObjectItemCaseSensitive(json, "uuid") == NULL, "serialized user unexpectedly included UUID");

    user_t parsed;
    memoryZero(&parsed, sizeof(parsed));
    require(userCreateFromJson(&parsed, json), "failed to parse serialized UUID user");
    require(parsed.uuid_pass_valid, "JSON round trip did not re-derive UUID bytes from password");
    require(memoryEqual(parsed.uuid_pass, expected_uuid, sizeof(expected_uuid)),
            "JSON round trip derived different UUID bytes");
    userDestroy(&parsed);
    cJSON_Delete(json);

    userDestroy(&plain_user);
    userDestroy(&compact_user);
    userDestroy(&uppercase_user);
    userDestroy(&canonical_user);
    usersDestroy(&users);
}

static void testUUIDLookupUpdatesOnPasswordChange(void)
{
    static const char uuid_a[]                      = "11111111-1111-1111-1111-111111111111";
    static const char uuid_b[]                      = "22222222-2222-2222-2222-222222222222";
    static const char uuid_c[]                      = "33333333-3333-3333-3333-333333333333";
    static const char uuid_c_compact[]              = "33333333333333333333333333333333";
    uint8_t           uuid_a_bytes[kWwUuidBytesLen] = {0};
    uint8_t           uuid_b_bytes[kWwUuidBytesLen] = {0};
    uint8_t           uuid_c_bytes[kWwUuidBytesLen] = {0};
    users_t           users;
    user_t            first_source;
    user_t            second_source;

    memoryZero(&users, sizeof(users));
    memoryZero(&first_source, sizeof(first_source));
    memoryZero(&second_source, sizeof(second_source));

    require(wwUuidParseString(uuid_a, uuid_a_bytes), "failed to parse UUID A");
    require(wwUuidParseString(uuid_b, uuid_b_bytes), "failed to parse UUID B");
    require(wwUuidParseString(uuid_c, uuid_c_bytes), "failed to parse UUID C");
    require(usersCreate(&users), "failed to create UUID password-change users table");
    require(userCreate(&first_source, uuid_a), "failed to create UUID A user");
    require(userCreate(&second_source, uuid_c), "failed to create UUID C user");
    userSetId(&first_source, 4001);
    userSetId(&second_source, 4002);
    require(usersAddUser(&users, &first_source), "failed to add UUID A user");
    require(usersAddUser(&users, &second_source), "failed to add UUID C user");
    userDestroy(&second_source);
    userDestroy(&first_source);

    user_t *first  = usersLookupByUUID(&users, uuid_a_bytes);
    user_t *second = usersLookupByUUID(&users, uuid_c_bytes);
    require(first != NULL && userGetId(first) == 4001, "failed to look first UUID user up");
    require(second != NULL && userGetId(second) == 4002, "failed to look second UUID user up");

    require(usersChangePassword(&users, first, "changed-to-non-uuid-password"),
            "failed to change UUID user to non-UUID password");
    require(usersLookupByUUID(&users, uuid_a_bytes) == NULL, "old UUID still resolved after non-UUID password change");
    require(! first->uuid_pass_valid, "non-UUID password left UUID key marked valid");

    require(usersChangePassword(&users, first, uuid_b), "failed to change UUID user to UUID B");
    require(usersLookupByUUID(&users, uuid_b_bytes) == first, "UUID B did not resolve after password change");
    require(first->uuid_pass_valid, "UUID B password did not mark UUID key valid");

    require(! usersChangePassword(&users, first, uuid_c), "exact duplicate UUID password change unexpectedly worked");
    require(usersLookupByUUID(&users, uuid_b_bytes) == first,
            "exact duplicate UUID change displaced previous UUID key");
    require(usersLookupByUUID(&users, uuid_c_bytes) == second, "exact duplicate UUID change displaced existing owner");

    require(! usersChangePassword(&users, first, uuid_c_compact), "duplicate UUID password change unexpectedly worked");
    require(usersLookupByUUID(&users, uuid_b_bytes) == first, "duplicate UUID change displaced previous UUID key");
    require(usersLookupByUUID(&users, uuid_c_bytes) == second, "duplicate UUID change displaced existing owner");

    usersDestroy(&users);
}

static void testWireGuardPublicKeyLookupAndDerivation(void)
{
    static const char password_a[]                               = "wireguard-publickey-password-a";
    static const char password_b[]                               = "wireguard-publickey-password-b";
    static const char password_c[]                               = "wireguard-publickey-password-c";
    uint8_t           publickey_a[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    uint8_t           publickey_b[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    uint8_t           publickey_c[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    uint8_t           current_sha256[SHA256_DIGEST_SIZE]         = {0};
    users_t           users;
    user_t            first_source;
    user_t            second_source;
    user_update_t     update = {0};

    memoryZero(&users, sizeof(users));
    memoryZero(&first_source, sizeof(first_source));
    memoryZero(&second_source, sizeof(second_source));
    deriveWireGuardPublicKey(password_a, publickey_a);
    deriveWireGuardPublicKey(password_b, publickey_b);
    deriveWireGuardPublicKey(password_c, publickey_c);

    require(usersCreate(&users), "failed to create WireGuard public key users table");
    require(userCreate(&first_source, password_a), "failed to create first WireGuard-key user");
    require(userCreate(&second_source, password_c), "failed to create second WireGuard-key user");
    userSetId(&first_source, 4301);
    userSetId(&second_source, 4302);

    require(first_source.wireguard_publickey_valid, "WireGuard public key was not derived from password");
    require(memoryEqual(first_source.wireguard_publickey, publickey_a, sizeof(publickey_a)),
            "derived WireGuard public key did not match expected X25519 output");
    require(usersAddUser(&users, &first_source), "failed to add first WireGuard-key user");
    require(usersAddUser(&users, &second_source), "failed to add second WireGuard-key user");
    userDestroy(&second_source);
    userDestroy(&first_source);

    user_t *first  = usersLookupByWireGuardPublicKey(&users, publickey_a);
    user_t *second = usersLookupByWireGuardPublicKey(&users, publickey_c);
    require(first != NULL && userGetId(first) == 4301, "failed to look first user up by WireGuard public key");
    require(second != NULL && userGetId(second) == 4302, "failed to look second user up by WireGuard public key");

    cJSON *json = userToJson(first);
    require(json != NULL, "failed to serialize WireGuard-key user");
    require(cJSON_GetObjectItemCaseSensitive(json, "wireguard-publickey") == NULL,
            "serialized user unexpectedly included WireGuard public key");

    user_t parsed;
    memoryZero(&parsed, sizeof(parsed));
    require(userCreateFromJson(&parsed, json), "failed to parse serialized WireGuard-key user");
    require(parsed.wireguard_publickey_valid, "JSON round trip did not re-derive WireGuard public key");
    require(memoryEqual(parsed.wireguard_publickey, publickey_a, sizeof(publickey_a)),
            "JSON round trip derived a different WireGuard public key");
    userDestroy(&parsed);
    cJSON_Delete(json);

    require(usersChangePassword(&users, first, password_b), "failed to change WireGuard-key user password");
    require(usersLookupByWireGuardPublicKey(&users, publickey_a) == NULL,
            "old WireGuard public key still resolved after password change");
    require(usersLookupByWireGuardPublicKey(&users, publickey_b) == first,
            "new WireGuard public key did not resolve after password change");
    require(first->wireguard_publickey_valid, "password change left WireGuard public key invalid");

    memoryCopy(current_sha256, first->sha256_pass.bytes, sizeof(current_sha256));
    update.mask     = kUserUpdatePassword;
    update.password = password_c;
    require(usersUpdateUserBySHA256(&users, current_sha256, &update) == kUsersUpdateResultDuplicateWireGuardPublicKey,
            "duplicate WireGuard public key password update returned the wrong result");
    require(usersLookupByWireGuardPublicKey(&users, publickey_b) == first,
            "duplicate WireGuard public key update displaced previous key");
    require(usersLookupByWireGuardPublicKey(&users, publickey_c) == second,
            "duplicate WireGuard public key update displaced existing owner");

    usersDestroy(&users);
}

static ip_addr_t parseTestIp(const char *text)
{
    ip_addr_t ip;

    memoryZero(&ip, sizeof(ip));
    require(parseIpAddress(text, &ip) != IPADDR_TYPE_ANY, "failed to parse test IP address");
    return ip;
}

static void testWireGuardAllowedIpsJsonValidationAndLookup(void)
{
    users_t       users;
    user_t        first;
    user_t        second;
    user_t        overlap;
    user_t        ipv6_user;
    user_update_t update                            = {0};
    uint8_t       second_sha256[SHA256_DIGEST_SIZE] = {0};

    memoryZero(&users, sizeof(users));
    memoryZero(&first, sizeof(first));
    memoryZero(&second, sizeof(second));
    memoryZero(&overlap, sizeof(overlap));
    memoryZero(&ipv6_user, sizeof(ipv6_user));

    require(usersCreate(&users), "failed to create WireGuard allowed IP users table");
    require(userCreate(&first, "wireguard-allowed-ips-first-password"), "failed to create first allowed IP user");
    require(userCreate(&second, "wireguard-allowed-ips-second-password"), "failed to create second allowed IP user");
    require(userCreate(&overlap, "wireguard-allowed-ips-overlap-password"),
            "failed to create overlapping allowed IP user");
    require(userCreate(&ipv6_user, "wireguard-allowed-ips-ipv6-password"), "failed to create IPv6 allowed IP user");

    userSetId(&first, 4401);
    userSetId(&second, 4402);
    userSetId(&overlap, 4403);
    userSetId(&ipv6_user, 4404);

    require(userSetWireGuardAllowedIps(&first, "10.44.0.23/24"), "failed to set first WireGuard allowed IPs");
    require(first.wireguard_allowed_ips_valid, "first WireGuard allowed IPs were not marked valid");
    require(stringCompare(first.wireguard_allowed_ips, "10.44.0.0/24") == 0,
            "WireGuard allowed IPs were not normalized to the network CIDR");
    require(first.wireguard_allowed_ip_family == 4 && first.wireguard_allowed_ip_prefix == 24,
            "IPv4 WireGuard allowed IP family/prefix were wrong");
    require(first.wireguard_allowed_ip_count == 256, "IPv4 WireGuard allowed IP count was wrong");

    require(userSetWireGuardAllowedIps(&second, "10.44.2.9/32"), "failed to set second WireGuard allowed IPs");
    require(second.wireguard_allowed_ip_count == 1, "IPv4 host route count was wrong");
    require(userSetWireGuardAllowedIps(&overlap, "10.44.0.128/25"), "failed to set overlapping allowed IPs");
    require(userSetWireGuardAllowedIps(&ipv6_user, "fd00::1234/64"), "failed to set IPv6 WireGuard allowed IPs");
    ip_addr_t expected_ipv6_network = parseTestIp("fd00::");
    require(ipAddrCmp(&ipv6_user.wireguard_allowed_ip, &expected_ipv6_network) != 0 &&
                stringChr(ipv6_user.wireguard_allowed_ips, '/') != NULL,
            "IPv6 WireGuard allowed IPs were not normalized");
    require(ipv6_user.wireguard_allowed_ip_family == 6 && ipv6_user.wireguard_allowed_ip_prefix == 64,
            "IPv6 WireGuard allowed IP family/prefix were wrong");
    require(ipv6_user.wireguard_allowed_ip_count == UINT64_MAX,
            "large IPv6 WireGuard allowed IP count did not saturate");

    require(usersAddUser(&users, &first), "failed to add first WireGuard allowed IP user");
    require(usersAddUser(&users, &second), "failed to add second WireGuard allowed IP user");
    require(usersAddUserChecked(&users, &overlap) == kUsersAddResultDuplicateWireGuardAllowedIps,
            "overlapping WireGuard allowed IPs were not rejected");
    require(usersAddUser(&users, &ipv6_user), "failed to add IPv6 WireGuard allowed IP user");
    userDestroy(&ipv6_user);
    userDestroy(&overlap);
    userDestroy(&second);
    userDestroy(&first);

    ip_addr_t inside_first = parseTestIp("10.44.0.200");
    ip_addr_t outside      = parseTestIp("10.44.1.1");
    ip_addr_t inside_ipv6  = parseTestIp("fd00::abcd");
    user_t   *first_lookup = usersLookupByWireGuardAllowedIp(&users, &inside_first);
    user_t   *ipv6_lookup  = usersLookupByWireGuardAllowedIp(&users, &inside_ipv6);
    require(first_lookup != NULL && userGetId(first_lookup) == 4401, "failed to lookup user by IPv4 allowed IP");
    require(usersLookupByWireGuardAllowedIp(&users, &outside) == NULL, "outside IPv4 address unexpectedly matched");
    require(ipv6_lookup != NULL && userGetId(ipv6_lookup) == 4404, "failed to lookup user by IPv6 allowed IP");

    cJSON *json = userToJson(first_lookup);
    require(json != NULL, "failed to serialize WireGuard allowed IP user");
    const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(json, "wireguard-allowed-ips");
    require(cJSON_IsString(allowed) && stringCompare(allowed->valuestring, "10.44.0.0/24") == 0,
            "serialized WireGuard allowed IPs were missing or not normalized");

    user_t parsed;
    memoryZero(&parsed, sizeof(parsed));
    require(userCreateFromJson(&parsed, json), "failed to parse serialized WireGuard allowed IP user");
    require(parsed.wireguard_allowed_ips_valid, "JSON round trip lost WireGuard allowed IPs");
    require(stringCompare(parsed.wireguard_allowed_ips, "10.44.0.0/24") == 0,
            "JSON round trip changed WireGuard allowed IPs");
    userDestroy(&parsed);
    cJSON_Delete(json);

    static const char empty_json_text[] =
        "{\"id\":4501,\"password\":\"wireguard-allowed-ips-empty\",\"wireguard-allowed-ips\":\"\"}";
    cJSON *empty_json = cJSON_Parse(empty_json_text);
    require(empty_json != NULL, "failed to parse empty WireGuard allowed IPs JSON");
    require(userCreateFromJson(&parsed, empty_json), "empty WireGuard allowed IPs JSON was rejected");
    require(! parsed.wireguard_allowed_ips_valid, "empty WireGuard allowed IPs were marked valid");
    cJSON *empty_out = userToJson(&parsed);
    require(empty_out != NULL, "failed to serialize empty WireGuard allowed IPs user");
    require(cJSON_GetObjectItemCaseSensitive(empty_out, "wireguard-allowed-ips") == NULL,
            "empty WireGuard allowed IPs were unexpectedly serialized");
    cJSON_Delete(empty_out);
    userDestroy(&parsed);
    cJSON_Delete(empty_json);

    static const char invalid_missing_prefix[] =
        "{\"id\":4502,\"password\":\"wireguard-allowed-ips-invalid-a\",\"wireguard-allowed-ips\":\"10.0.0.1\"}";
    static const char invalid_list[] = "{\"id\":4503,\"password\":\"wireguard-allowed-ips-invalid-b\","
                                       "\"wireguard-allowed-ips\":\"10.0.0.1/32,10.0.0.2/32\"}";
    static const char invalid_prefix[] =
        "{\"id\":4504,\"password\":\"wireguard-allowed-ips-invalid-c\",\"wireguard-allowed-ips\":\"10.0.0.1/33\"}";
    cJSON *invalid_json = cJSON_Parse(invalid_missing_prefix);
    require(invalid_json != NULL, "failed to parse invalid missing-prefix JSON");
    require(! userCreateFromJson(&parsed, invalid_json), "missing-prefix WireGuard allowed IPs were accepted");
    cJSON_Delete(invalid_json);
    invalid_json = cJSON_Parse(invalid_list);
    require(invalid_json != NULL, "failed to parse invalid list JSON");
    require(! userCreateFromJson(&parsed, invalid_json), "comma-separated WireGuard allowed IPs were accepted");
    require(usersAddUserFromJsonChecked(&users, invalid_json) == kUsersAddResultInvalidWireGuardAllowedIps,
            "invalid WireGuard allowed IPs JSON returned the wrong checked add result");
    cJSON_Delete(invalid_json);
    invalid_json = cJSON_Parse(invalid_prefix);
    require(invalid_json != NULL, "failed to parse invalid prefix JSON");
    require(! userCreateFromJson(&parsed, invalid_json), "bad-prefix WireGuard allowed IPs were accepted");
    cJSON_Delete(invalid_json);

    user_t *second_lookup = usersLookupByIdentifier(&users, 4402);
    require(second_lookup != NULL, "failed to lookup second WireGuard allowed IP user by id");
    memoryCopy(second_sha256, second_lookup->sha256_pass.bytes, sizeof(second_sha256));
    update.mask                  = kUserUpdateWireGuardAllowedIps;
    update.wireguard_allowed_ips = "10.44.0.44/32";
    require(usersUpdateUserBySHA256(&users, second_sha256, &update) == kUsersUpdateResultDuplicateWireGuardAllowedIps,
            "overlapping WireGuard allowed IP update was not rejected");
    require(stringCompare(second_lookup->wireguard_allowed_ips, "10.44.2.9/32") == 0,
            "rejected WireGuard allowed IP update changed the user");

    update.wireguard_allowed_ips = "not-a-cidr";
    require(usersUpdateUserBySHA256(&users, second_sha256, &update) == kUsersUpdateResultInvalidWireGuardAllowedIps,
            "invalid WireGuard allowed IP update returned the wrong result");

    update.wireguard_allowed_ips = "";
    require(usersUpdateUserBySHA256(&users, second_sha256, &update) == kUsersUpdateResultOk,
            "failed to clear WireGuard allowed IPs");
    require(! second_lookup->wireguard_allowed_ips_valid, "cleared WireGuard allowed IPs stayed valid");

    static const char overlap_feed_json[] =
        "{\"users\":["
        "{\"id\":4601,\"password\":\"wireguard-feed-a\",\"wireguard-allowed-ips\":\"172.16.0.0/24\"},"
        "{\"id\":4602,\"password\":\"wireguard-feed-b\",\"wireguard-allowed-ips\":\"172.16.0.128/25\"}"
        "]}";
    cJSON *feed_json = cJSON_Parse(overlap_feed_json);
    require(feed_json != NULL, "failed to parse overlapping feed JSON");
    require(! usersFeedJson(&users, feed_json), "overlapping WireGuard allowed IP feed unexpectedly worked");
    require(usersLookupByIdentifier(&users, 4401) == first_lookup, "failed feed did not preserve existing table");
    cJSON_Delete(feed_json);

    usersDestroy(&users);
}

static void testRuntimeMigrationPreservesActiveIpByIdentifier(void)
{
    users_t        old_users;
    users_t        new_users;
    user_t         source_user;
    const uint64_t user_id = 8080;

    memoryZero(&old_users, sizeof(old_users));
    memoryZero(&new_users, sizeof(new_users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&old_users), "failed to create old users table");
    require(usersCreate(&new_users), "failed to create new users table");

    require(userCreate(&source_user, "runtime-migration-password"), "failed to create source user");
    userSetId(&source_user, user_id);
    source_user.limit.ips      = 1;
    source_user.limit.cons_out = 2;

    require(usersAddUser(&old_users, &source_user), "failed to add old user");
    require(usersAddUser(&new_users, &source_user), "failed to add refreshed user");
    userDestroy(&source_user);

    user_ip_key_t ip1 = testIp(10, 0, 0, 1);
    user_ip_key_t ip2 = testIp(10, 0, 0, 2);

    require(usersTryAdmitConnectionByIdentifier(&old_users, user_id, &ip1, 1234) == kUserAdmissionOk,
            "old users table did not admit first connection");

    user_t *old_user = usersLookupByIdentifier(&old_users, user_id);
    user_t *new_user = usersLookupByIdentifier(&new_users, user_id);
    require(old_user != NULL && new_user != NULL, "failed to look users up by id");
    require(old_user->timeinfo.first_usage_at_ms == 0, "old user first usage was unexpectedly marked");
    require(new_user->timeinfo.first_usage_at_ms == 0, "refreshed user unexpectedly had first usage");
    old_user->runtime.identity_generation_floor = 7;
    new_user->runtime.identity_generation_floor = 20;

    require(usersMigrateRuntimeStateByIdentifier(&new_users, &old_users), "runtime migration failed");

    old_user = usersLookupByIdentifier(&old_users, user_id);
    new_user = usersLookupByIdentifier(&new_users, user_id);
    require(old_user != NULL && new_user != NULL, "users disappeared after migration");
    require(old_user->runtime.active_cons_out == 0, "old user kept migrated active connection count");
    require(old_user->runtime.ip_usage_count == 0, "old user kept migrated IP usage entries");
    require(new_user->runtime.identity_generation_floor == 7 && old_user->runtime.identity_generation_floor == 0,
            "continuous membership did not preserve its original handle generation floor");
    require(new_user->timeinfo.first_usage_at_ms == 0, "new user unexpectedly inherited first usage");

    require(usersTryAdmitConnectionByIdentifier(&new_users, user_id, &ip2, 2000) == kUserAdmissionIpLimited,
            "new users table did not enforce migrated active IP usage");

    usersReleaseConnectionByIdentifier(&new_users, user_id, &ip1);
    require(usersTryAdmitConnectionByIdentifier(&new_users, user_id, &ip2, 2000) == kUserAdmissionOk,
            "new users table did not release migrated active IP usage");
    usersReleaseConnectionByIdentifier(&new_users, user_id, &ip2);

    usersDestroy(&new_users);
    usersDestroy(&old_users);
}

static void testRuntimeMigrationPrefersIdentifierAcrossPasswordChange(void)
{
    users_t        old_users;
    users_t        new_users;
    user_t         old_source;
    user_t         new_source;
    uint8_t        old_sha256[SHA256_DIGEST_SIZE] = {0};
    uint8_t        new_sha256[SHA256_DIGEST_SIZE] = {0};
    const uint64_t user_id                        = 9001;

    memoryZero(&old_users, sizeof(old_users));
    memoryZero(&new_users, sizeof(new_users));
    memoryZero(&old_source, sizeof(old_source));
    memoryZero(&new_source, sizeof(new_source));

    require(usersCreate(&old_users), "failed to create old id migration users table");
    require(usersCreate(&new_users), "failed to create new id migration users table");

    require(userCreate(&old_source, "id-migration-old-password"), "failed to create old id migration user");
    require(userCreate(&new_source, "id-migration-old-password"), "failed to create new id migration user");
    userSetId(&old_source, user_id);
    userSetId(&new_source, user_id);
    old_source.limit.ips      = 1;
    old_source.limit.cons_out = 2;
    new_source.limit.ips      = 1;
    new_source.limit.cons_out = 2;
    memoryCopy(old_sha256, old_source.sha256_pass.bytes, sizeof(old_sha256));

    require(usersAddUser(&old_users, &old_source), "failed to add old id migration user");
    require(usersAddUser(&new_users, &new_source), "failed to add new id migration user");
    userDestroy(&new_source);
    userDestroy(&old_source);

    /* A normal refreshed collection publishes the API-rotated credentials for
     * this same durable ID before moving existing runtime reservations. */
    user_prepared_password_change_t *prepared = NULL;
    require(usersPreparePasswordChange("id-migration-new-password", SIZE_MAX, 0, &prepared) == kUsersPasswordOk,
            "id migration password preparation failed");
    require(usersTryChangePreparedPasswordByIdentifier(&new_users, user_id, prepared, SIZE_MAX, 0, NULL, NULL) ==
                kUsersPasswordOk,
            "id migration password rotation failed");
    usersFreePreparedPasswordChange(prepared);
    user_t *rotated = usersLookupByIdentifier(&new_users, user_id);
    require(rotated != NULL, "rotated ID missing before migration");
    memoryCopy(new_sha256, rotated->sha256_pass.bytes, sizeof(new_sha256));

    user_ip_key_t ip1 = testIp(10, 1, 0, 1);
    user_ip_key_t ip2 = testIp(10, 1, 0, 2);

    require(usersTryAdmitConnectionByIdentifier(&old_users, user_id, &ip1, 1234) == kUserAdmissionOk,
            "old id users table did not admit first connection");

    require(usersLookupBySHA256(&new_users, old_sha256) == NULL, "new users table unexpectedly had old SHA-256");
    require(usersLookupBySHA256(&new_users, new_sha256) != NULL, "new users table did not have new SHA-256");

    require(usersMigrateRuntimeStateByIdentifier(&new_users, &old_users), "id-preferring runtime migration failed");

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

typedef struct runtime_migration_thread_context_s
{
    users_t    *dest;
    users_t    *src;
    atomic_bool started;
    atomic_bool finished;
    bool        migrated;
} runtime_migration_thread_context_t;

static WTHREAD_ROUTINE(runtimeMigrationThread)
{
    runtime_migration_thread_context_t *context = userdata;

    atomic_store(&context->started, true);
    context->migrated = usersMigrateRuntimeStateByIdentifier(context->dest, context->src);
    atomic_store(&context->finished, true);
    return 0;
}

static void requireRuntimeMigrationWaitsForLock(users_t *dest, users_t *src, user_t *locked_user, bool time_lock,
                                                const char *blocked_message)
{
    runtime_migration_thread_context_t context = {
        .dest     = dest,
        .src      = src,
        .migrated = false,
    };
    atomic_init(&context.started, false);
    atomic_init(&context.finished, false);

    /*
     * A users_t write lock alone cannot synchronize direct user runtime APIs.
     * Holding either user's stats_lock must therefore stop the state move.
     */
    wrwlock_t *lock = time_lock ? &locked_user->lock : &locked_user->stats_lock;
    rwlockWriteLock(lock);
    wthread_t       migration_thread;
    wthread_error_t thread_error = threadCreate(&migration_thread, runtimeMigrationThread, &context);
    require(thread_error == kWThreadErrorNone, "failed to create runtime migration thread");
    while (! atomic_load(&context.started))
    {
        wwSleepMS(kRuntimeMigrationLockPollDelayMs);
    }
    wwSleepMS(kRuntimeMigrationLockProbeMs);
    require(! atomic_load(&context.finished), blocked_message);
    rwlockWriteUnlock(lock);

    require(threadJoin(migration_thread) == 0, "failed to join runtime migration thread");
    require(atomic_load(&context.finished), "runtime migration thread did not finish after releasing stats_lock");
    require(context.migrated, "runtime migration failed after releasing stats_lock");
}

static void testRuntimeMigrationHonorsPerUserStatsLocks(void)
{
    users_t        old_users;
    users_t        new_users;
    user_t         source_user;
    const uint64_t user_id = 9050;

    memoryZero(&old_users, sizeof(old_users));
    memoryZero(&new_users, sizeof(new_users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&old_users), "failed to create old locking-test users table");
    require(usersCreate(&new_users), "failed to create new locking-test users table");
    require(userCreate(&source_user, "runtime-migration-locking-password"),
            "failed to create locking-test source user");
    userSetId(&source_user, user_id);
    source_user.limit.cons_out = 2;
    require(usersAddUser(&old_users, &source_user), "failed to add old locking-test user");
    require(usersAddUser(&new_users, &source_user), "failed to add new locking-test user");
    userDestroy(&source_user);

    user_ip_key_t ip = testIp(10, 5, 0, 1);
    require(usersTryAdmitConnectionByIdentifier(&old_users, user_id, &ip, 1234) == kUserAdmissionOk,
            "old locking-test user did not admit a connection");

    user_t *old_user = usersLookupByIdentifier(&old_users, user_id);
    require(old_user != NULL, "failed to look up old locking-test user");

    requireRuntimeMigrationWaitsForLock(
        &new_users, &old_users, old_user, false, "runtime migration ignored the source user's stats_lock");
    require(old_user->runtime.active_cons_out == 0, "source runtime state remained after locking-test migration");

    /*
     * Move the state back while locking the same object in its destination
     * role, proving that migration synchronizes both matched users.
     */
    requireRuntimeMigrationWaitsForLock(
        &old_users, &new_users, old_user, false, "runtime migration ignored the destination user's stats_lock");
    require(old_user->runtime.active_cons_out == 1, "destination runtime state was not restored after locking test");

    requireRuntimeMigrationWaitsForLock(
        &new_users, &old_users, old_user, true, "runtime migration ignored source time lock");
    requireRuntimeMigrationWaitsForLock(
        &old_users, &new_users, old_user, true, "runtime migration ignored destination time lock");
    require(old_user->runtime.active_cons_out == 1, "time-lock migration lost reservation");

    usersReleaseConnectionByIdentifier(&old_users, user_id, &ip);
    usersDestroy(&new_users);
    usersDestroy(&old_users);
}

static void testIdentifierLookupSurvivesPasswordChange(void)
{
    users_t        users;
    user_t         source_user;
    uint8_t        old_sha256[SHA256_DIGEST_SIZE] = {0};
    uint8_t        new_sha256[SHA256_DIGEST_SIZE] = {0};
    const uint64_t user_id                        = 777;

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
    static const char json_text[] = "{"
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
    require(userCreate(&user, "total-traffic-mixed-limit-password"), "failed to create mixed total traffic limit user");
    user.limit.traffic.total = 100;

    require(! userAccountTraffic(&user, 40, 59, 0, NULL), "mixed traffic below total limit closed user");
    require(userAccountTraffic(&user, 0, 1, 0, NULL), "mixed traffic reaching total limit did not close user");
    userDestroy(&user);
}

static void testScaledTrafficArithmeticAndLimits(void)
{
    const struct
    {
        uint32_t multiplier;
        uint64_t raw;
        uint64_t charged;
        uint32_t remainder;
    } cases[] = {{kUserTrafficMultiplierScale / 2, 1, 0, kUserTrafficMultiplierScale / 2},
                 {kUserTrafficMultiplierScale * 3 / 2, 3, 4, kUserTrafficMultiplierScale / 2},
                 {kUserTrafficMultiplierScale * 2, 17, 34, 0},
                 {kUserTrafficMultiplierScale, UINT64_MAX, UINT64_MAX, 0},
                 {kUserTrafficMultiplierScale / 2, UINT64_MAX, UINT64_MAX / 2, kUserTrafficMultiplierScale / 2},
                 {kUserTrafficMultiplierScale * 3 / 2,
                  UINT64_MAX / 2,
                  UINT64_MAX / 2 + (UINT64_MAX / 2) / 2,
                  kUserTrafficMultiplierScale / 2},
                 {kUserTrafficMultiplierScale * 2, UINT64_MAX, UINT64_MAX, 0},
                 {kUserTrafficMultiplierMax, UINT64_MAX, UINT64_MAX, 0},
                 {1, UINT64_MAX, UINT64_MAX / kUserTrafficMultiplierScale, UINT64_MAX % kUserTrafficMultiplierScale}};

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        user_t user;
        require(userCreate(&user, "scaled-arithmetic"), "scaled arithmetic fixture");
        require(! userAccountTrafficScaled(&user, cases[i].raw, cases[i].raw, cases[i].multiplier, 0, NULL),
                "scaled unlimited accounting unexpectedly closed");
        require(user.stats.traffic.u == cases[i].charged && user.stats.traffic.d == cases[i].charged &&
                    user.runtime.traffic_remainder_u == cases[i].remainder &&
                    user.runtime.traffic_remainder_d == cases[i].remainder,
                "scaled arithmetic overflowed or rounded incorrectly");
        userDestroy(&user);
    }

    user_t user;
    require(userCreate(&user, "scaled-limits"), "scaled limits fixture");
    user.limit.traffic.total = 2;
    require(! userAccountTrafficScaled(&user, 1, 1, kUserTrafficMultiplierScale / 2, 0, NULL) &&
                user.stats.traffic.u == 0 && user.stats.traffic.d == 0,
            "fractional directions shared carry or closed before charged limit");
    require(! userAccountTrafficScaled(&user, 1, 0, kUserTrafficMultiplierScale / 2, 0, NULL) &&
                user.stats.traffic.u == 1 && user.stats.traffic.d == 0 &&
                user.runtime.traffic_remainder_d == kUserTrafficMultiplierScale / 2,
            "upload carry corrupted download carry");
    require(userAccountTrafficScaled(&user, 0, 1, kUserTrafficMultiplierScale / 2, 0, NULL) &&
                user.stats.traffic.d == 1,
            "combined charged limit failed to close");
    userDestroy(&user);

    require(userCreate(&user, "scaled-wrapper"), "scaled wrapper fixture");
    require(! userAccountTrafficScaled(&user, 1, 0, kUserTrafficMultiplierScale * 3 / 2, 0, NULL),
            "initial fractional surcharge");
    require(! userAccountTraffic(&user, 5, 0, 0, NULL) &&
                user.runtime.traffic_remainder_u == kUserTrafficMultiplierScale / 2,
            "unit-factor wrapper cleared fractional carry");
    require(! userAccountTrafficScaled(&user, 1, 0, kUserTrafficMultiplierScale * 3 / 2, 0, NULL) &&
                user.stats.traffic.u == 8 && user.runtime.traffic_remainder_u == 0,
            "fractional surcharge was lost across unit-factor call");
    userDestroy(&user);

    require(userCreate(&user, "scaled-saturating-total"), "scaled saturation fixture");
    require(! userAccountTrafficScaled(&user, UINT64_MAX / 2, 0, kUserTrafficMultiplierScale * 2, 0, NULL) &&
                user.stats.traffic.u == UINT64_MAX - 1,
            "large nonsaturating scaled total was incorrect");
    require(! userAccountTrafficScaled(&user, 1, 0, kUserTrafficMultiplierScale * 2, 0, NULL) &&
                user.stats.traffic.u == UINT64_MAX,
            "scaled cumulative total wrapped");
    userDestroy(&user);
}

static void testScaledTrafficChunkingAndRuntimeMigration(void)
{
    const uint32_t multipliers[] = {1,
                                    kUserTrafficMultiplierScale / 3,
                                    kUserTrafficMultiplierScale / 2,
                                    kUserTrafficMultiplierScale * 3 / 2,
                                    kUserTrafficMultiplierMax};
    for (size_t m = 0; m < sizeof(multipliers) / sizeof(multipliers[0]); ++m)
    {
        user_t chunks, combined;
        require(userCreate(&chunks, "scaled-chunks") && userCreate(&combined, "scaled-combined"),
                "scaled chunking fixtures");
        for (unsigned i = 0; i < 1001; ++i)
            discard userAccountTrafficScaled(&chunks, 7, 11, multipliers[m], 0, NULL);
        discard userAccountTrafficScaled(&combined, 7007, 11011, multipliers[m], 0, NULL);
        require(chunks.stats.traffic.u == combined.stats.traffic.u &&
                    chunks.stats.traffic.d == combined.stats.traffic.d &&
                    chunks.runtime.traffic_remainder_u == combined.runtime.traffic_remainder_u &&
                    chunks.runtime.traffic_remainder_d == combined.runtime.traffic_remainder_d,
                "charged amount depended on payload fragmentation");
        userDestroy(&combined);
        userDestroy(&chunks);
    }

    users_t old_users, new_users;
    user_t  source, copy, parsed;
    require(usersCreate(&old_users) && usersCreate(&new_users) && userCreate(&source, "scaled-old"),
            "scaled migration fixtures");
    userSetId(&source, 9310);
    require(usersAddUser(&old_users, &source), "scaled old account");
    userDestroy(&source);
    require(userCreate(&source, "scaled-new"), "scaled new credentials");
    userSetId(&source, 9310);
    require(usersAddUser(&new_users, &source), "scaled new account");
    userDestroy(&source);
    bool found = false;
    require(! usersAccountTrafficScaledByIdentifier(
                &old_users, 9310, 1, 3, kUserTrafficMultiplierScale / 2, 0, &found, NULL) &&
                found,
            "scaled collection accounting failed");
    user_t *old = usersLookupByIdentifier(&old_users, 9310);
    require(userCopy(&copy, old), "scaled generic copy");
    cJSON *json = userToJson(old);
    require(json != NULL && userCreateFromJson(&parsed, json), "scaled JSON roundtrip");
    require(copy.runtime.traffic_remainder_u == 0 && copy.runtime.traffic_remainder_d == 0 &&
                parsed.runtime.traffic_remainder_u == 0 && parsed.runtime.traffic_remainder_d == 0,
            "generic copy or persistence retained process-local fractional carry");
    cJSON_Delete(json);
    userDestroy(&parsed);
    userDestroy(&copy);
    require(usersMigrateRuntimeStateByIdentifier(&new_users, &old_users), "scaled runtime migration");
    user_t *next = usersLookupByIdentifier(&new_users, 9310);
    require(old->runtime.traffic_remainder_u == 0 && old->runtime.traffic_remainder_d == 0 &&
                next->runtime.traffic_remainder_u == kUserTrafficMultiplierScale / 2 &&
                next->runtime.traffic_remainder_d == kUserTrafficMultiplierScale / 2,
            "same-ID refresh lost fractional carry across credentials change");
    require(! usersAccountTrafficByIdentifier(&new_users, 9310, 0, 0, 0, &found, NULL) && found &&
                next->runtime.traffic_remainder_u == kUserTrafficMultiplierScale / 2,
            "collection unit-factor wrapper erased fractional carry");
    require(! usersAccountTrafficScaledByIdentifier(
                &new_users, 9310, 1, 1, kUserTrafficMultiplierScale / 2, 0, &found, NULL) &&
                found && next->stats.traffic.u == 1 && next->stats.traffic.d == 1,
            "accounting after refresh ignored migrated carry");
    bool notification = true;
    require(usersAccountTrafficScaledByIdentifier(
                &new_users, 9311, 1, 1, kUserTrafficMultiplierScale / 2, 0, &found, &notification) &&
                ! found && ! notification,
            "missing user did not fail closed in scaled wrapper");
    usersDestroy(&new_users);
    usersDestroy(&old_users);
}

static WTHREAD_ROUTINE(scaledTrafficThread)
{
    user_t *user = userdata;
    for (unsigned i = 0; i < 2001; ++i)
        discard userAccountTrafficScaled(user, 1, 3, kUserTrafficMultiplierScale / 2, 0, NULL);
    return 0;
}

static void testScaledTrafficConcurrentCarry(void)
{
    user_t user;
    require(userCreate(&user, "scaled-concurrent"), "scaled concurrent fixture");
    wthread_t threads[4];
    for (unsigned i = 0; i < 4; ++i)
        require(threadCreate(&threads[i], scaledTrafficThread, &user) == kWThreadErrorNone,
                "scaled traffic thread creation");
    for (unsigned i = 0; i < 4; ++i)
        require(threadJoin(threads[i]) == 0, "scaled traffic thread join");
    require(user.stats.traffic.u == 4002 && user.stats.traffic.d == 12006 && user.runtime.traffic_remainder_u == 0 &&
                user.runtime.traffic_remainder_d == 0,
            "concurrent accounting lost or duplicated fractional carry");
    userDestroy(&user);
}

static void testFirstUsagePushRequestFlagIsOneShot(void)
{
    users_t        users;
    user_t         source_user;
    const uint64_t user_id = 5501;
    bool           needed  = false;

    memoryZero(&users, sizeof(users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&users), "failed to create first usage push users table");
    require(userCreate(&source_user, "first-usage-push-flag-password"), "failed to create first usage push flag user");
    userSetId(&source_user, user_id);
    require(usersAddUser(&users, &source_user), "failed to add first usage push flag user");
    userDestroy(&source_user);

    require(! usersAccountTrafficByIdentifier(&users, user_id, 0, 0, 0, NULL, &needed),
            "zero traffic unexpectedly closed user");
    require(! needed, "zero traffic requested first usage push");

    require(! usersAccountTrafficByIdentifier(&users, user_id, 10, 0, 0, NULL, &needed),
            "first traffic unexpectedly closed user");
    require(needed, "first non-zero traffic did not request first usage push");

    needed = false;
    require(! usersAccountTrafficByIdentifier(&users, user_id, 1, 0, 0, NULL, &needed),
            "second traffic unexpectedly closed user");
    require(! needed, "first usage push request was not one-shot");

    usersResetFirstUsagePushRequestByIdentifier(&users, user_id);
    needed = false;
    require(! usersAccountTrafficByIdentifier(&users, user_id, 1, 0, 0, NULL, &needed),
            "traffic after per-user reset unexpectedly closed user");
    require(needed, "per-user reset did not re-enable first usage push request");

    needed = false;
    require(! usersAccountTrafficByIdentifier(&users, user_id, 1, 0, 0, NULL, &needed),
            "traffic after per-user retry unexpectedly closed user");
    require(! needed, "per-user reset allowed more than one retry");

    usersResetFirstUsagePushRequests(&users);
    needed = false;
    require(! usersAccountTrafficByIdentifier(&users, user_id, 1, 0, 0, NULL, &needed),
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

static void testEarliestFirstUseMerge(void)
{
    user_t user;
    require(userCreate(&user, "earliest-observation"), "earliest fixture");
    userMergeFirstUsage(&user, UINT64_MAX);
    userMergeFirstUsage(&user, 5000);
    userMergeFirstUsage(&user, 7000);
    require(user.timeinfo.first_usage_at_ms == 5000, "earliest merge moved forward");
    userMergeFirstUsage(&user, 1);
    require(user.timeinfo.first_usage_at_ms == 1, "early merge was lost");
    userDestroy(&user);
}

#if defined(WCRYPTO_TEST_LINKER_WRAP)
static void testRestoreRetainedFirstUse(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 0);
    user_t original, restored;
    require(userCreate(&original, "retained-clock-original"), "retained clock origin setup");
    original.timeinfo.first_usage_at_ms           = 4800;
    original.timeinfo.expire_after_first_usage_ms = 300;
    userInstallClientClock(&original, 10000, 5000, 0);
    require(! userAccountTraffic(&original, 1, 0, 0, NULL), "retained first-use observation");
    user_accounting_snapshot_t evidence;
    userGetAccountingSnapshot(&original, &evidence);
    require(evidence.first_local_at_ms == 0 && evidence.first_usage_at_ms == 5000 && evidence.age_valid &&
                evidence.first_usage_age_ms == 200,
            "accounting snapshot lost original local origin or older server age");
    userDestroy(&original);

    atomic_store(&client_clock_ms, 120);
    require(userCreate(&restored, "retained-clock-reappeared"), "retained clock destination setup");
    restored.timeinfo.expire_after_first_usage_ms = 300;
    userRestoreClientObservation(&restored,
                                 evidence.first_usage_at_ms,
                                 evidence.first_local_at_ms,
                                 evidence.first_usage_age_ms,
                                 evidence.age_sample_ms,
                                 evidence.age_valid);
    userInstallClientClock(&restored, 1, 1, 120);
    require(userIsExpired(&restored, 120) && restored.client_time.age_ms >= 320 && restored.client_time.observed &&
                ! restored.client_time.observation_acked && restored.client_time.first_local_ms == 0 &&
                restored.client_time.first_report_ms == 5000,
            "reappearing account reset retained origin or elapsed expiry");
    require(restored.timeinfo.first_usage_at_ms == 0,
            "local observation restore overwrote authoritative first-use configuration");
    userRestoreClientObservation(&restored, 6000, 100, 1, 120, true);
    require(restored.client_time.age_ms >= 320 && restored.client_time.first_report_ms == 5000 &&
                restored.client_time.first_local_ms == 0,
            "younger retained evidence extended a known countdown");
    userDestroy(&restored);
    atomic_store(&client_clock_test, false);
}

static void testLocalFirstUseClockAndEdits(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 0);
    user_t user, copy;
    require(userCreate(&user, "local-clock"), "local clock fixture");
    user.timeinfo.expire_after_first_usage_ms = 100;
    userInstallClientClock(&user, 10000, 5000, 0);
    require(userTryAdmitConnection(&user, NULL, 0) == kUserAdmissionOk, "clock admission");
    require(! userAccountTraffic(&user, 0, 0, 0, NULL) && ! user.client_time.observed,
            "reservation or zero traffic created an observation");
    require(! userAccountTraffic(&user, 0, 1, UINT64_MAX, NULL), "zero-origin first download expired early");
    require(user.client_time.observed && user.client_time.first_local_ms == 0 &&
                user.client_time.first_report_ms == 5000 && user.client_view_expires_at_ms == 100,
            "zero-origin or null-notification accounting failed");
    atomic_store(&client_clock_ms, 70);
    /* A newer server sample, wall correction, delayed local parsing, and omitted
     * canonical first use cannot make a known countdown younger. */
    userInstallClientClock(&user, 1, 5010, 50);
    require(user.client_view_expires_at_ms == 100 && user.client_time.age_ms == 70,
            "delayed refresh extended the original countdown");
    user.timeinfo.expire_after_first_usage_ms = 200;
    userInstallClientClock(&user, UINT64_MAX, 5020, 70);
    require(user.client_view_expires_at_ms == 200, "duration increase restarted origin");
    user.timeinfo.expire_after_first_usage_ms = 60;
    userInstallClientClock(&user, 1, 5020, 70);
    require(userIsExpired(&user, 70), "duration decrease granted extra life");
    user.timeinfo.expire_after_first_usage_ms = 0;
    userInstallClientClock(&user, 10000, 5020, 70);
    require(! userIsExpired(&user, UINT64_MAX), "duration clear did not remove relative expiry");
    user.timeinfo.expire_at_ms = 10100;
    userInstallClientClock(&user, 10000, 5020, 70);
    require(user.client_view_expires_at_ms == 170, "absolute projection");
    atomic_store(&client_clock_ms, 80);
    userInstallClientClock(&user, 9000, 5030, 80);
    require(user.client_view_expires_at_ms == 170, "unchanged absolute policy extended its deadline");
    user.timeinfo.expire_at_ms = 10200;
    userInstallClientClock(&user, 10000, 5030, 80);
    require(user.client_view_expires_at_ms == 280, "explicit absolute edit did not recompute");
    user.timeinfo.expire_at_ms                = 0;
    user.timeinfo.expire_after_first_usage_ms = 100;
    userInstallClientClock(&user, 10000, 5030, 80);
    require(user.client_view_expires_at_ms == 100, "enabling relative expiry forgot unlimited use");
    require(userCopy(&copy, &user), "runtime-free copy");
    require(! copy.client_time.clock_valid && ! copy.client_time.observed && ! copy.client_view_expiry_valid &&
                copy.runtime.active_cons_out == 0,
            "generic copy leaked runtime time or reservations");
    cJSON *json = userToJson(&user);
    user_t parsed;
    require(userCreateFromJson(&parsed, json), "runtime-free JSON");
    require(! parsed.client_time.observed && ! parsed.client_time.clock_valid, "JSON leaked client clock");
    userDestroy(&parsed);
    cJSON_Delete(json);
    userDestroy(&copy);
    userReleaseConnection(&user, NULL);
    userDestroy(&user);

    atomic_store(&client_clock_ms, 0);
    require(userCreate(&user, "future-clock"), "future fixture");
    user.timeinfo.first_usage_at_ms           = 1100;
    user.timeinfo.expire_after_first_usage_ms = 50;
    userInstallClientClock(&user, 10000, 1000, 0);
    require(! user.client_time.age_valid && user.client_time.future_valid && user.client_view_expires_at_ms == 150,
            "future imported origin started immediately");
    atomic_store(&client_clock_ms, 20);
    userInstallClientClock(&user, 10000, 1005, 20);
    require(user.client_view_expires_at_ms == 150, "repeat pull postponed future origin");
    user.timeinfo.first_usage_at_ms = 0;
    userInstallClientClock(&user, 10000, 1010, 20);
    require(user.client_view_expires_at_ms == 150, "omitted import erased future origin");
    require(! userAccountTraffic(&user, 1, 0, 0, NULL) && user.client_view_expires_at_ms == 70,
            "real traffic did not supply earlier local origin");
    userDestroy(&user);

    atomic_store(&client_clock_ms, 0);
    require(userCreate(&user, "edge-clock"), "edge fixture");
    user.timeinfo.first_usage_at_ms           = 1;
    user.timeinfo.expire_after_first_usage_ms = 1;
    userInstallClientClock(&user, UINT64_MAX, UINT64_MAX, 0);
    require(userIsExpired(&user, 0), "expired-at-zero became unlimited");
    user.timeinfo.expire_after_first_usage_ms = UINT64_MAX;
    user.timeinfo.first_usage_at_ms           = 0;
    userInstallClientClock(&user, UINT64_MAX, UINT64_MAX, 0);
    require(user.client_view_expires_at_ms != 0, "saturated age/deadline became unlimited");
    require(! userAccountTraffic(&user, 1, 0, 0, NULL) && user.client_time.first_report_ms == UINT64_MAX,
            "saturated report overflowed");
    atomic_store(&client_clock_ms, UINT64_MAX / 1000);
    userInstallClientClock(&user, UINT64_MAX, UINT64_MAX, 0);
    require(userIsExpired(&user, UINT64_MAX), "saturated deadline did not expire");
    userDestroy(&user);
    atomic_store(&client_clock_test, false);
}

typedef struct first_traffic_context_s
{
    user_t     *user;
    atomic_bool sampled, proceed;
} first_traffic_context_t;

static void testDiscountedFirstUseStartsBeforeWholeByteCharge(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 50000);
    user_t user;
    require(userCreate(&user, "discounted-first-use"), "discounted first-use fixture");
    user.timeinfo.expire_after_first_usage_ms = 100;
    userInstallClientClock(&user, 100000, 10000, 50000);
    bool push = true;
    require(! userAccountTrafficScaled(&user, 0, 0, kUserTrafficMultiplierScale / 2, 0, &push) && ! push &&
                ! user.client_time.observed,
            "zero raw traffic started discounted first use");
    require(! userAccountTrafficScaled(&user, 0, 1, kUserTrafficMultiplierScale / 2, 0, &push) && push &&
                user.stats.traffic.d == 0 && user.runtime.traffic_remainder_d == kUserTrafficMultiplierScale / 2 &&
                user.client_time.observed && user.client_time.first_local_ms == 50000 &&
                user.client_time.first_report_ms == 10000 && user.client_view_expires_at_ms == 50100,
            "discounted first traffic delayed first use until a whole byte was charged");
    user_accounting_snapshot_t snapshot;
    userGetAccountingSnapshot(&user, &snapshot);
    require(snapshot.traffic.u == 0 && snapshot.traffic.d == 0 && snapshot.observation_pending &&
                snapshot.first_usage_at_ms == 10000,
            "zero-charge first-use observation was missing from snapshot");
    require(! userRuntimeShouldClose(&user, 50099) && userRuntimeShouldClose(&user, 50100),
            "discounted first-use expiry did not enforce raw-traffic origin");
    userDestroy(&user);
    atomic_store(&client_clock_test, false);
}

static WTHREAD_ROUTINE(firstTrafficThread)
{
    first_traffic_context_t *context    = userdata;
    const uint64_t           old_sample = getHRTimeUs() / 1000ULL;
    atomic_store(&context->sampled, true);
    while (! atomic_load(&context->proceed))
        wwSleepMS(1);
    discard userAccountTraffic(context->user, 1, 0, old_sample, NULL);
    return 0;
}

static void testFirstUseRacesAndMigration(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 100);
    users_t old_users, new_users;
    user_t  source;
    require(usersCreate(&old_users) && usersCreate(&new_users) && userCreate(&source, "race-old"), "race fixture");
    userSetId(&source, 42);
    require(usersAddUser(&old_users, &source), "race old user");
    userDestroy(&source);
    require(userCreate(&source, "race-new"), "race changed credentials");
    userSetId(&source, 42);
    source.timeinfo.expire_after_first_usage_ms = 500;
    require(usersAddUser(&new_users, &source), "race new user");
    userDestroy(&source);
    user_t *user = usersLookupByIdentifier(&old_users, 42);
    userInstallClientClock(user, 10000, 5000, 100);
    first_traffic_context_t contexts[4];
    wthread_t               threads[4];
    for (unsigned i = 0; i < 4; ++i)
    {
        contexts[i].user = user;
        atomic_init(&contexts[i].sampled, false);
        atomic_init(&contexts[i].proceed, false);
        require(threadCreate(&threads[i], firstTrafficThread, &contexts[i]) == kWThreadErrorNone, "traffic thread");
    }
    for (unsigned i = 0; i < 4; ++i)
        while (! atomic_load(&contexts[i].sampled))
            wwSleepMS(1);
    atomic_store(&client_clock_ms, 200);
    userInstallClientClock(user, 10000, 9000, 200);
    for (unsigned i = 0; i < 4; ++i)
        atomic_store(&contexts[i].proceed, true);
    for (unsigned i = 0; i < 4; ++i)
        require(threadJoin(threads[i]) == 0, "traffic join");
    user_accounting_snapshot_t snapshot;
    userGetAccountingSnapshot(user, &snapshot);
    require(snapshot.traffic.u == 4 && snapshot.first_usage_at_ms == 9000 && snapshot.observation_pending &&
                user->client_time.first_local_ms == 200,
            "racing stale samples corrupted first origin");
    userAcknowledgeObservation(user, 8999);
    require(! user->client_time.observation_acked, "uncaptured observation acknowledged");
    userAcknowledgeObservation(user, 9000);
    require(userTryAdmitConnection(user, NULL, 200) == kUserAdmissionOk, "race reservation");
    require(usersMigrateRuntimeStateByIdentifier(&new_users, &old_users), "time migration");
    user_t *next = usersLookupByIdentifier(&new_users, 42);
    atomic_store(&client_clock_ms, 250);
    userInstallClientClock(next, 10000, 9020, 250);
    require(next->client_time.first_report_ms == 9000 && next->client_time.observation_acked &&
                next->client_view_expires_at_ms == 700 && next->runtime.active_cons_out == 1 &&
                ! user->client_time.observed && next->timeinfo.first_usage_at_ms == 0,
            "same-ID credential change lost runtime age/evidence or overwrote authoritative time");
    users_t other;
    require(usersCreate(&other) && userCreate(&source, "race-new"), "different ID fixture");
    userSetId(&source, 43);
    require(usersAddUser(&other, &source) && usersMigrateRuntimeStateByIdentifier(&other, &new_users),
            "different ID migration");
    require(! usersLookupByIdentifier(&other, 43)->client_time.observed, "different ID inherited evidence");
    userDestroy(&source);
    usersDestroy(&other);
    userReleaseConnection(next, NULL);
    usersDestroy(&new_users);
    usersDestroy(&old_users);
    atomic_store(&client_clock_test, false);
}
static void testStandaloneBandwidthExpiryClocks(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_wall_test, true);
    atomic_store(&client_clock_ms, 5000);
    atomic_store(&client_wall_ms, UINT64_C(1700000000000));
    user_t user;
    require(userCreate(&user, "standalone-clocks"), "standalone clock user");
    user.timeinfo.expire_at_ms = UINT64_C(1700000000100);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, 10, false).decision == kUserDeliveryForward,
            "unexpired standalone absolute expiry");
    atomic_store(&client_wall_ms, UINT64_C(1700000000100));
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, 10, false).decision == kUserDeliveryReject &&
                userCommitDelivery(&user, kUserBandwidthUpload, 0, 10, false, false, 1000) == kUserDeliveryReject &&
                user.stats.traffic.u == 0,
            "standalone absolute expiry used pacing clock or charged rejected bytes");
    user.timeinfo.expire_at_ms                = 0;
    user.timeinfo.first_usage_at_ms           = UINT64_C(1700000000000);
    user.timeinfo.expire_after_first_usage_ms = 200;
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryForward,
            "standalone first-use duration expired early");
    atomic_store(&client_wall_ms, UINT64_C(1700000000200));
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryReject,
            "standalone first-use duration ignored wall time");
    user.timeinfo.expire_after_first_usage_ms = 0;
    user.limit.bandwidth.u                    = 100;
    require(userCommitDelivery(&user, kUserBandwidthUpload, 0, 10, false, false, 1000) == kUserDeliveryForward,
            "no-expiry standalone initial credit");
    atomic_store(&client_wall_ms, UINT64_C(1900000000000));
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryWait,
            "forward wall jump minted pacing credit");
    atomic_store(&client_wall_ms, 1);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryWait,
            "backward wall jump minted pacing credit");
    atomic_store(&client_clock_ms, 5010);
    require(userCommitDelivery(&user, kUserBandwidthUpload, 0, 1, false, false, 1000) == kUserDeliveryForward,
            "fresh monotonic sample did not refill");
    userSetClientViewExpiry(&user, 5020, true);
    require(! user.client_time.clock_valid, "projection fixture unexpectedly has installed client clock");
    atomic_store(&client_clock_ms, 5020);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryReject,
            "explicit client expiry projection required client clock");
    userDestroy(&user);
    atomic_store(&client_wall_test, false);
    atomic_store(&client_clock_test, false);
}

static void testBandwidthSharedTurnsAndMigration(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 0);
    users_t old_users, new_users;
    user_t  source;
    require(usersCreate(&old_users) && usersCreate(&new_users) && userCreate(&source, "bandwidth-old"),
            "bandwidth fixture");
    userSetId(&source, 42);
    source.limit.bandwidth = (user_ud_t) {100, 200};
    require(usersAddUser(&old_users, &source), "bandwidth old user");
    userDestroy(&source);
    require(userCreate(&source, "bandwidth-new"), "bandwidth changed credentials");
    userSetId(&source, 42);
    source.limit.bandwidth = (user_ud_t) {100, 200};
    require(usersAddUser(&new_users, &source), "bandwidth new user");
    userDestroy(&source);
    user_t *user = usersLookupByIdentifier(&old_users, 42);
    userInstallClientClock(user, 10000, 5000, 0);
    bool push = false;
    require(! userObserveTraffic(user, 20, 0, 0, &push) && push, "arrival first use");
    require(user->stats.traffic.u == 0 && user->runtime.traffic_remainder_u == 0 && user->client_time.observed,
            "arrival charged queued bytes");
    user_bandwidth_result_t result = userBandwidthPreview(user, kUserBandwidthUpload, 0, 20, false);
    require(result.decision == kUserDeliveryForward && result.grant == 10 && result.limited, "100 ms initial credit");
    require(userCommitDelivery(user, kUserBandwidthUpload, 0, 10, false, false, 500) == kUserDeliveryForward,
            "initial delivery commit");
    require(user->stats.traffic.u == 5 &&
                userBandwidthPreview(user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryWait,
            "aggregate credit or multiplier");
    require(userBandwidthPreview(user, kUserBandwidthDownload, 0, 20, false).grant == 20, "directions share credit");
    require(userBandwidthRegister(user, kUserBandwidthUpload, 11) &&
                userBandwidthRegister(user, kUserBandwidthUpload, 22),
            "waiter registration");
    userBandwidthSetEligible(user, kUserBandwidthUpload, 11, true);
    userBandwidthSetEligible(user, kUserBandwidthUpload, 22, true);
    atomic_store(&client_clock_ms, 105);
    require(userBandwidthPreview(user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryWait,
            "new traffic bypassed eligible turn");
    require(userCommitDelivery(user, kUserBandwidthUpload, 11, 1, false, true, 1000) == kUserDeliveryForward,
            "first waiter turn");
    require(userBandwidthPreview(user, kUserBandwidthUpload, 11, 1, false).decision == kUserDeliveryWait &&
                userBandwidthPreview(user, kUserBandwidthUpload, 22, 1, false).decision == kUserDeliveryForward,
            "successful turn did not rotate");
    userBandwidthSetEligible(user, kUserBandwidthUpload, 22, false);
    buffer_budget_cost_t cost = {123, 256, 1};
    require(userBandwidthReserve(user, kUserBandwidthUpload, 11, cost), "queue reservation");
    uint64_t credit    = user->runtime.bandwidth[0].bucket.credit;
    uint16_t remainder = user->runtime.bandwidth[0].bucket.remainder;
    require(usersMigrateRuntimeStateByIdentifier(&new_users, &old_users), "bandwidth refresh migration");
    user_t *next = usersLookupByIdentifier(&new_users, 42);
    require(next->runtime.bandwidth[0].bucket.credit == credit &&
                next->runtime.bandwidth[0].bucket.remainder == remainder && next->runtime.bandwidth_waiter_count == 2 &&
                next->runtime.queued_cost.bytes == 123,
            "same ID refresh reset runtime or minted burst");
    require(userCommitDelivery(next, kUserBandwidthUpload, 11, 1, false, true, 1000) == kUserDeliveryForward,
            "paused ticket still occupied turn after migration");
    userBandwidthSetEligible(next, kUserBandwidthUpload, 22, true);
    require(userBandwidthPreview(next, kUserBandwidthUpload, 11, 1, false).decision == kUserDeliveryForward,
            "resume jumped ahead of existing eligible ticket");
    userBandwidthRelease(next, kUserBandwidthUpload, 11, cost);
    userBandwidthCancel(next, kUserBandwidthUpload, 11);
    userBandwidthCancel(next, kUserBandwidthUpload, 22);
    require(next->runtime.queued_cost.bytes == 0 && next->runtime.bandwidth_waiter_count == 0,
            "queue accounting leaked");
    usersDestroy(&new_users);
    usersDestroy(&old_users);
    atomic_store(&client_clock_test, false);
}

static void testBandwidthDatagramCreditAndRateChanges(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 0);
    user_t user;
    require(userCreate(&user, "datagram-budget"), "datagram fixture");
    user.limit.bandwidth.u = 1;
    require(userBandwidthRegister(&user, kUserBandwidthUpload, 1), "packet ticket");
    userBandwidthSetEligible(&user, kUserBandwidthUpload, 1, true);
    atomic_store(&client_clock_ms, 100000);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 1, 3, true).decision == kUserDeliveryWait,
            "preactivation idle minted whole-packet credit");
    atomic_store(&client_clock_ms, 101000);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 1, 3, true).decision == kUserDeliveryWait,
            "oversized packet released before earning credit");
    atomic_store(&client_clock_ms, 102000);
    require(userCommitDelivery(&user, kUserBandwidthUpload, 1, 3, true, true, 1000) == kUserDeliveryForward &&
                user.stats.traffic.u == 3,
            "1 byte/s packet did not make progress");
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 1, 4, true).decision == kUserDeliveryWait,
            "oversized head burst survived delivery");
    atomic_store(&client_clock_ms, 105000);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 1, 4, true).decision == kUserDeliveryWait,
            "packet gained credit early");
    userBandwidthSetEligible(&user, kUserBandwidthUpload, 1, false);
    require(user.runtime.bandwidth[0].bucket.credit == 1, "pause transferred oversized burst");
    userBandwidthSetEligible(&user, kUserBandwidthUpload, 1, true);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 1, 4, true).decision == kUserDeliveryWait,
            "resumed head skipped activation");
    rwlockWriteLock(&user.lock);
    rwlockWriteLock(&user.stats_lock);
    user.limit.bandwidth.u = 2;
    userBandwidthReconcileLocked(&user, 105000);
    rwlockWriteUnlock(&user.stats_lock);
    rwlockWriteUnlock(&user.lock);
    require(user.runtime.bandwidth[0].bucket.credit == 1 && user.runtime.bandwidth[0].oversized_ticket == 0,
            "rate change retained oversized credit");
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 1, 65536, true).decision == kUserDeliveryReject,
            "oversized datagram accepted");
    require(userCommitDelivery(&user, kUserBandwidthUpload, 1, 0, true, false, 1000) == kUserDeliveryForward &&
                user.stats.traffic.u == 3,
            "empty packet lost or charged");
    userBandwidthCancel(&user, kUserBandwidthUpload, 1);
    userDestroy(&user);
    atomic_store(&client_clock_test, false);
}

static void testBandwidthRateTransitions(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 0);
    users_t users;
    user_t  source;
    require(usersCreate(&users) && userCreate(&source, "rate-transitions"), "rate transition fixture");
    userSetId(&source, 42);
    source.limit.bandwidth.u = 15;
    require(usersAddUser(&users, &source), "rate transition user");
    userDestroy(&source);
    user_t *user = usersLookupByIdentifier(&users, 42);
    require(userCommitDelivery(user, kUserBandwidthUpload, 0, 2, false, false, 1000) == kUserDeliveryForward,
            "rate transition initial credit");
    atomic_store(&client_clock_ms, 50);
    require(userBandwidthPreview(user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryWait,
            "fraction rounded into early byte");
    user_config_patch_t patch = {.mask = kUserConfigBandwidthUp, .limit.bandwidth.u = 25};
    require(usersPatchConfigByIdentifier(&users, 42, &patch) == kUsersUpdateResultOk &&
                user->runtime.bandwidth[0].bucket.credit == 0 && user->runtime.bandwidth[0].bucket.remainder == 750,
            "rate change lost old-rate fraction or minted burst");
    atomic_store(&client_clock_ms, 60);
    require(userCommitDelivery(user, kUserBandwidthUpload, 0, 1, false, false, 1000) == kUserDeliveryForward,
            "fractional refill did not combine across rate change");
    patch.limit.bandwidth.u = 0;
    require(usersPatchConfigByIdentifier(&users, 42, &patch) == kUsersUpdateResultOk, "finite to unlimited");
    require(userBandwidthRegister(user, kUserBandwidthUpload, 99), "unlimited waiter");
    userBandwidthSetEligible(user, kUserBandwidthUpload, 99, true);
    require(userBandwidthPreview(user, kUserBandwidthUpload, 0, 128, false).decision == kUserDeliveryWait &&
                userBandwidthPreview(user, kUserBandwidthUpload, 99, 128, false).grant == 128,
            "finite to unlimited lost FIFO");
    userBandwidthCancel(user, kUserBandwidthUpload, 99);
    patch.limit.bandwidth.u = 100;
    require(usersPatchConfigByIdentifier(&users, 42, &patch) == kUsersUpdateResultOk &&
                userCommitDelivery(user, kUserBandwidthUpload, 0, 10, false, false, 1000) == kUserDeliveryForward,
            "unlimited to finite did not initialize defined burst");
    require(usersPatchConfigByIdentifier(&users, 42, &patch) == kUsersUpdateResultOk &&
                userBandwidthPreview(user, kUserBandwidthUpload, 0, 1, false).decision == kUserDeliveryWait,
            "unchanged refresh minted credit");
    usersDestroy(&users);
    atomic_store(&client_clock_test, false);
}

typedef struct bandwidth_race_context_s
{
    user_t      *user;
    atomic_uint *forwarded;
} bandwidth_race_context_t;
static WTHREAD_ROUTINE(bandwidthRaceThread)
{
    bandwidth_race_context_t *context = userdata;
    for (unsigned i = 0; i < 1000; ++i)
        if (userCommitDelivery(context->user, kUserBandwidthUpload, 0, 1, false, false, 1000) == kUserDeliveryForward)
            atomic_fetch_add(context->forwarded, 1);
    return 0;
}

static void testBandwidthConcurrentAndFinalQuota(void)
{
    atomic_store(&client_clock_test, true);
    atomic_store(&client_clock_ms, 0);
    user_t user;
    require(userCreate(&user, "bandwidth-race"), "bandwidth race fixture");
    user.limit.bandwidth.u             = 1000;
    atomic_uint              forwarded = 0;
    bandwidth_race_context_t context   = {&user, &forwarded};
    wthread_t                threads[2];
    for (unsigned i = 0; i < 2; ++i)
        require(threadCreate(&threads[i], bandwidthRaceThread, &context) == kWThreadErrorNone, "bandwidth thread");
    for (unsigned i = 0; i < 2; ++i)
        require(threadJoin(threads[i]) == 0, "bandwidth thread join");
    require(atomic_load(&forwarded) == 100 && user.stats.traffic.u == 100,
            "racing workers overspent shared initial credit");
    userDestroy(&user);
    require(userCreate(&user, "final-chunk"), "quota fixture");
    user.limit.traffic.total = 1;
    require(userCommitDelivery(&user, kUserBandwidthUpload, 0, 2, false, false, 1000) == kUserDeliveryForwardClose &&
                user.stats.traffic.u == 2,
            "final quota chunk was discarded or uncharged");
    require(userCommitDelivery(&user, kUserBandwidthUpload, 0, 1, false, false, 1000) == kUserDeliveryReject &&
                user.stats.traffic.u == 2,
            "exhausted quota charged another candidate");
    userDestroy(&user);
    require(userCreate(&user, "extreme-rate"), "extreme-rate fixture");
    user.limit.bandwidth.u           = UINT64_MAX;
    user_bandwidth_result_t preview  = userBandwidthPreview(&user, kUserBandwidthUpload, 0, UINT64_MAX, false);
    uint64_t                capacity = UINT64_MAX / 10 + 1;
    require(preview.grant == 16384 && user.runtime.bandwidth[0].bucket.credit == capacity,
            "full uint64 rate was clamped or stream turn was unbounded");
    require(userCommitDelivery(&user, kUserBandwidthUpload, 0, 16384, false, false, 1) == kUserDeliveryForward,
            "extreme-rate initial grant");
    atomic_store(&client_clock_ms, UINT64_MAX / 1000);
    require(userBandwidthPreview(&user, kUserBandwidthUpload, 0, capacity, false).grant == 16384 &&
                user.runtime.bandwidth[0].bucket.credit == capacity,
            "extreme-rate long idle overflow");
    userDestroy(&user);
    atomic_store(&client_clock_test, false);
}

#endif

int main(void)
{
    testCaseSet("users_runtime_migration_test");
    logger_t *test_logger = loggerCreate();
    require(test_logger != NULL, "failed to create users test logger");
    loggerSetHandler(test_logger, testLogCaptureHandler);
    setInternalLogger(test_logger);

    require(userTestRuntimeInitialize(), "crypto global initialization failed");
    testDuplicateCredentialLogsOmitCredentials();
    testCryptoFailureDoesNotPublishCredentials();
    testIdentifierLookupAndJsonRoundTrip();
    testSHA224LookupAndHashAlignment();
    testJsonFeedRejectsDuplicateKeysWithoutTerminating();
    testUUIDCredentialLookupAndDerivation();
    testUUIDLookupUpdatesOnPasswordChange();
    testWireGuardPublicKeyLookupAndDerivation();
    testWireGuardAllowedIpsJsonValidationAndLookup();
    testRuntimeMigrationPreservesActiveIpByIdentifier();
    testRuntimeMigrationPrefersIdentifierAcrossPasswordChange();
    testRuntimeMigrationHonorsPerUserStatsLocks();
    testIdentifierLookupSurvivesPasswordChange();
    testFirstUsageSetIfMissingKeepsServerValue();
    testEarliestFirstUseMerge();
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    testStandaloneBandwidthExpiryClocks();
    testBandwidthSharedTurnsAndMigration();
    testBandwidthDatagramCreditAndRateChanges();
    testBandwidthConcurrentAndFinalQuota();
    testBandwidthRateTransitions();
    testLocalFirstUseClockAndEdits();
    testRestoreRetainedFirstUse();
    testFirstUseRacesAndMigration();
    testDiscountedFirstUseStartsBeforeWholeByteCharge();
#endif
    testClientViewExpiryOverridesServerTimeFields();
    testZeroUserLimitsAreUnlimited();
    testTotalTrafficLimitCountsUploadAndDownload();
    testScaledTrafficArithmeticAndLimits();
    testScaledTrafficChunkingAndRuntimeMigration();
    testScaledTrafficConcurrentCarry();
    testFirstUsagePushRequestFlagIsOneShot();
    testTrafficStatsJsonUsesExactBytes();
    userTestRuntimeCleanup();
    internaloggerDestroy();
    return 0;
}
