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

static void deriveWireGuardPublicKey(const char *password, uint8_t out[USER_WIREGUARD_PUBLICKEY_SIZE])
{
    static const uint8_t basepoint[USER_WIREGUARD_PUBLICKEY_SIZE] = {9};
    sha256_hash_t        sha256 = {0};

    require(wCryptoSHA256(&sha256, (const unsigned char *) password, stringLength(password)) == 0,
            "failed to derive WireGuard private key seed");
    require(performX25519(out, sha256.bytes, basepoint) == 0, "failed to derive WireGuard public key");
    memoryZero(&sha256, sizeof(sha256));
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

static void testJsonFeedRejectsDuplicateKeysWithoutTerminating(void)
{
    static const char duplicate_sha_json[] =
        "{\"users\":["
        "{\"id\":5101,\"password\":\"json-duplicate-password\"},"
        "{\"id\":5102,\"password\":\"json-duplicate-password\"}"
        "]}";
    static const char duplicate_id_json[] =
        "{\"users\":["
        "{\"id\":5201,\"password\":\"json-duplicate-id-a\"},"
        "{\"id\":5201,\"password\":\"json-duplicate-id-b\"}"
        "]}";
    users_t users;
    user_t  seed;

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
    static const char canonical_uuid[] = "84949cc5-4701-4a84-895b-354c584a981b";
    static const char uppercase_uuid[] = "84949CC5-4701-4A84-895B-354C584A981B";
    static const char compact_uuid[]   = "84949cc547014a84895b354c584a981b";
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
    static const char uuid_a[]         = "11111111-1111-1111-1111-111111111111";
    static const char uuid_b[]         = "22222222-2222-2222-2222-222222222222";
    static const char uuid_c[]         = "33333333-3333-3333-3333-333333333333";
    static const char uuid_c_compact[] = "33333333333333333333333333333333";
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

    user_t *first = usersLookupByUUID(&users, uuid_a_bytes);
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
    require(usersLookupByUUID(&users, uuid_c_bytes) == second,
            "exact duplicate UUID change displaced existing owner");

    require(! usersChangePassword(&users, first, uuid_c_compact), "duplicate UUID password change unexpectedly worked");
    require(usersLookupByUUID(&users, uuid_b_bytes) == first, "duplicate UUID change displaced previous UUID key");
    require(usersLookupByUUID(&users, uuid_c_bytes) == second, "duplicate UUID change displaced existing owner");

    usersDestroy(&users);
}

static void testWireGuardPublicKeyLookupAndDerivation(void)
{
    static const char password_a[] = "wireguard-publickey-password-a";
    static const char password_b[] = "wireguard-publickey-password-b";
    static const char password_c[] = "wireguard-publickey-password-c";
    uint8_t           publickey_a[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    uint8_t           publickey_b[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    uint8_t           publickey_c[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    uint8_t           current_sha256[SHA256_DIGEST_SIZE] = {0};
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
    require(usersUpdateUserBySHA256(&users, current_sha256, &update) ==
                kUsersUpdateResultDuplicateWireGuardPublicKey,
            "duplicate WireGuard public key password update returned the wrong result");
    require(usersLookupByWireGuardPublicKey(&users, publickey_b) == first,
            "duplicate WireGuard public key update displaced previous key");
    require(usersLookupByWireGuardPublicKey(&users, publickey_c) == second,
            "duplicate WireGuard public key update displaced existing owner");

    usersDestroy(&users);
}

static void testRuntimeMigrationPreservesActiveIpByIdentifier(void)
{
    users_t old_users;
    users_t new_users;
    user_t  source_user;
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

    require(usersMigrateRuntimeStateByIdentifier(&new_users, &old_users), "runtime migration failed");

    old_user = usersLookupByIdentifier(&old_users, user_id);
    new_user = usersLookupByIdentifier(&new_users, user_id);
    require(old_user != NULL && new_user != NULL, "users disappeared after migration");
    require(old_user->runtime.active_cons_out == 0, "old user kept migrated active connection count");
    require(old_user->runtime.ip_usage_count == 0, "old user kept migrated IP usage entries");
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
    const uint64_t user_id = 5501;
    bool           needed  = false;

    memoryZero(&users, sizeof(users));
    memoryZero(&source_user, sizeof(source_user));

    require(usersCreate(&users), "failed to create first usage push users table");
    require(userCreate(&source_user, "first-usage-push-flag-password"),
            "failed to create first usage push flag user");
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

int main(void)
{
    initializeCryptoBackend();
    testIdentifierLookupAndJsonRoundTrip();
    testSHA224LookupAndHashAlignment();
    testJsonFeedRejectsDuplicateKeysWithoutTerminating();
    testUUIDCredentialLookupAndDerivation();
    testUUIDLookupUpdatesOnPasswordChange();
    testWireGuardPublicKeyLookupAndDerivation();
    testRuntimeMigrationPreservesActiveIpByIdentifier();
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
