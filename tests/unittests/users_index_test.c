/*
 * Focused correctness and instrumentation tests for the users_t lookup indexes.
 *
 * This file is grown alongside the users/performance work. Its first
 * responsibility (Phase 0/1) is to prove the plaintext-password hot path:
 *
 *   - a password hit derives SHA-256 exactly once and SHA-224 zero times
 *   - a password miss derives SHA-256 exactly once and SHA-224 zero times
 *   - candidate verification (userPasswordMatches) derives no SHA at all
 *   - neither hit nor miss performs a fallback scan over every user
 *   - a SHA-256 index collision fails closed (exact plaintext still decides)
 *
 * The SHA call counts and the fallback-scan visit counter are only available in
 * the linker-wrap / test-hook build configuration; the functional assertions run
 * unconditionally so the test is still meaningful on platforms without --wrap.
 */

#include "objects/users.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(WCRYPTO_TEST_LINKER_WRAP)
static size_t g_sha224_calls;
static size_t g_sha256_calls;
static size_t g_x25519_calls;

/* When enabled, every SHA-256 derivation returns this fixed value, which lets
 * the test synthesize an index collision between two distinct plaintexts. */
static bool    g_force_sha256_enabled;
static uint8_t g_force_sha256_value[SHA256_DIGEST_SIZE];

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
    g_sha224_calls += 1U;
    return __real_wCryptoSHA224(out, in, inlen);
}

wcrypto_status_t __wrap_wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    g_sha256_calls += 1U;
    if (g_force_sha256_enabled)
    {
        if (out != NULL)
        {
            memoryCopy(out->bytes, g_force_sha256_value, sizeof(out->bytes));
        }
        return kWCryptoOk;
    }
    return __real_wCryptoSHA256(out, in, inlen);
}

wcrypto_status_t __wrap_wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE])
{
    g_x25519_calls += 1U;
    return __real_wCryptoX25519(out, scalar, point);
}
#endif

#if defined(USERS_TEST_ALLOC_INJECTION)
/*
 * Deterministic allocation-fault injection. When the probe is armed, the Nth
 * heap allocation of the measured operation (N == g_alloc_fail_at) returns NULL;
 * every other allocation passes through to the real allocator. Sweeping N across
 * an operation and asserting the database stays consistent proves the mutation
 * paths are transactional: each fails cleanly before any irreversible change, or
 * completes fully. The wrappers cover the three allocation entry points the STC
 * maps and the user/users code actually use (memoryAllocateZero/Aligned funnel
 * through memoryAllocate, so wrapping it catches them too).
 */
static bool   g_alloc_probe_active = false;
static size_t g_alloc_calls        = 0;
static size_t g_alloc_fail_at      = 0; /* 0 disables failure; else fail the Nth call */

void *__real_memoryAllocate(size_t size);
void *__real_memoryReAllocate(void *ptr, size_t size);
void *__real_memoryCalloc(size_t count, size_t size);
void *__wrap_memoryAllocate(size_t size);
void *__wrap_memoryReAllocate(void *ptr, size_t size);
void *__wrap_memoryCalloc(size_t count, size_t size);

static bool allocInjectionShouldFail(void)
{
    if (! g_alloc_probe_active)
    {
        return false;
    }
    g_alloc_calls += 1U;
    return g_alloc_fail_at != 0U && g_alloc_calls == g_alloc_fail_at;
}

void *__wrap_memoryAllocate(size_t size)
{
    if (allocInjectionShouldFail())
    {
        return NULL;
    }
    return __real_memoryAllocate(size);
}

void *__wrap_memoryReAllocate(void *ptr, size_t size)
{
    if (allocInjectionShouldFail())
    {
        return NULL;
    }
    return __real_memoryReAllocate(ptr, size);
}

void *__wrap_memoryCalloc(size_t count, size_t size)
{
    if (allocInjectionShouldFail())
    {
        return NULL;
    }
    return __real_memoryCalloc(count, size);
}

/* Arms the probe so the `fail_at`-th subsequent allocation fails (0 = none). */
static void allocInjectionArm(size_t fail_at)
{
    g_alloc_calls        = 0;
    g_alloc_fail_at      = fail_at;
    g_alloc_probe_active = true;
}

/* Disarms the probe and returns how many allocations the operation performed. */
static size_t allocInjectionDisarm(void)
{
    g_alloc_probe_active = false;
    return g_alloc_calls;
}
#endif

#if defined(USERS_TEST_PASSWORD_LOOKUP_VISIT_COUNTER)
extern size_t users_test_password_lookup_visits;
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void resetCounters(void)
{
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    g_sha224_calls = 0;
    g_sha256_calls = 0;
    g_x25519_calls = 0;
#endif
#if defined(USERS_TEST_PASSWORD_LOOKUP_VISIT_COUNTER)
    users_test_password_lookup_visits = 0;
#endif
}

static void requireSingleSha256HotPath(const char *context)
{
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    char message[160];
    (void) snprintf(
        message, sizeof(message), "%s: expected exactly one SHA-256 derivation, got %zu", context, g_sha256_calls);
    require(g_sha256_calls == 1U, message);
    (void) snprintf(
        message, sizeof(message), "%s: expected zero SHA-224 derivations, got %zu", context, g_sha224_calls);
    require(g_sha224_calls == 0U, message);
#else
    (void) context;
#endif
}

static void requireNoFallbackScan(const char *context)
{
#if defined(USERS_TEST_PASSWORD_LOOKUP_VISIT_COUNTER)
    char message[160];
    (void) snprintf(message,
                    sizeof(message),
                    "%s: plaintext lookup examined %zu candidates; a fallback scan reappeared",
                    context,
                    users_test_password_lookup_visits);
    require(users_test_password_lookup_visits <= 1U, message);
#else
    (void) context;
#endif
}

/* Adds a distinct user identified by durable id, carrying the given password. */
static void addUser(users_t *users, uint64_t id, const char *password)
{
    user_t user;

    memoryZero(&user, sizeof(user));
    require(userCreate(&user, password), "failed to create test user");
    userSetId(&user, id);
    require(usersAddUser(users, &user), "failed to add test user");
    userDestroy(&user);
}

/* Adds a user and, when name is non-empty, names it through the database. */
static user_t *addNamedUser(users_t *users, uint64_t id, const char *password, const char *name)
{
    addUser(users, id, password);
    user_t *stored = usersLookupByIdentifier(users, id);
    require(stored != NULL, "stored user vanished before naming");
    if (name != NULL && name[0] != '\0')
    {
        require(usersSetUserName(users, stored, name), "failed to name test user");
    }
    return stored;
}

static void testPasswordHitSingleHash(void)
{
    users_t users;

    require(usersCreate(&users), "failed to create users table");
    addUser(&users, 1, "hit-password-first");
    addUser(&users, 2, "hit-password-middle");
    addUser(&users, 3, "hit-password-last");

    const char    *passwords[] = {"hit-password-first", "hit-password-middle", "hit-password-last"};
    const uint64_t ids[]       = {1, 2, 3};

    for (size_t i = 0; i < 3; ++i)
    {
        resetCounters();
        user_t *found = usersLookupByPassword(&users, passwords[i]);
        require(found != NULL, "password hit returned NULL");
        require(userGetId(found) == ids[i], "password hit returned the wrong user");
        requireSingleSha256HotPath("password hit");
        requireNoFallbackScan("password hit");
    }

    usersDestroy(&users);
}

static void testPasswordMissSingleHash(void)
{
    users_t empty;
    users_t populated;

    require(usersCreate(&empty), "failed to create empty users table");
    resetCounters();
    require(usersLookupByPassword(&empty, "no-such-password") == NULL, "empty-table miss returned a user");
    requireSingleSha256HotPath("empty-table miss");
    requireNoFallbackScan("empty-table miss");
    usersDestroy(&empty);

    require(usersCreate(&populated), "failed to create populated users table");
    for (uint64_t i = 0; i < 512; ++i)
    {
        char password[48];
        (void) snprintf(password, sizeof(password), "miss-password-%llu", (unsigned long long) i);
        addUser(&populated, i + 1U, password);
    }

    resetCounters();
    require(usersLookupByPassword(&populated, "definitely-not-present") == NULL, "large-table miss returned a user");
    requireSingleSha256HotPath("large-table miss");
    requireNoFallbackScan("large-table miss");

    /* A hit in a large table must still be single-hash and scan-free. */
    resetCounters();
    user_t *found = usersLookupByPassword(&populated, "miss-password-500");
    require(found != NULL, "expected hit in large table");
    require(userGetId(found) == 501U, "large-table hit returned the wrong user");
    requireSingleSha256HotPath("large-table hit");
    requireNoFallbackScan("large-table hit");

    usersDestroy(&populated);
}

static void testExactVerificationDerivesNoHash(void)
{
    users_t users;

    require(usersCreate(&users), "failed to create users table");
    addUser(&users, 42, "verify-password");
    user_t *stored = usersLookupByIdentifier(&users, 42);
    require(stored != NULL, "stored user vanished");

    resetCounters();
    require(userPasswordMatches(stored, "verify-password"), "exact verify rejected the correct password");
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    require(g_sha256_calls == 0U && g_sha224_calls == 0U && g_x25519_calls == 0U,
            "userPasswordMatches re-derived password hashes");
#endif

    resetCounters();
    require(! userPasswordMatches(stored, "verify-password-wrong"), "exact verify accepted a wrong password");
    require(! userPasswordMatches(stored, "verify-passwor"), "exact verify accepted a length-mismatched password");
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    require(g_sha256_calls == 0U && g_sha224_calls == 0U && g_x25519_calls == 0U,
            "userPasswordMatches re-derived password hashes on mismatch");
#endif

    usersDestroy(&users);
}

/*
 * Forces a SHA-256 index collision between two distinct plaintexts and verifies
 * the lookup fails closed: the SHA-256 table selects the collision candidate but
 * the exact plaintext comparison rejects the wrong password.
 */
static void testCollisionFailsClosed(void)
{
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    users_t users;

    require(usersCreate(&users), "failed to create users table");
    addUser(&users, 7, "real-password");

    user_t *stored = usersLookupByIdentifier(&users, 7);
    require(stored != NULL, "stored collision user vanished");
    memoryCopy(g_force_sha256_value, stored->sha256_pass.bytes, sizeof(g_force_sha256_value));

    resetCounters();
    g_force_sha256_enabled = true;
    user_t *found          = usersLookupByPassword(&users, "forged-collision-password");
    g_force_sha256_enabled = false;

    require(found == NULL, "SHA-256 collision with a wrong plaintext must fail closed");
    requireNoFallbackScan("collision fail-closed");

    /* The genuine password still resolves once forcing is disabled. */
    require(usersLookupByPassword(&users, "real-password") == stored, "genuine password stopped resolving");

    usersDestroy(&users);
#endif
}

static void testNameIndex(void)
{
    users_t users;

    require(usersCreate(&users), "failed to create users table");
    user_t *alice = addNamedUser(&users, 1, "name-pw-alice", "alice");
    user_t *bob   = addNamedUser(&users, 2, "name-pw-bob", "bob");
    require(alice != NULL && bob != NULL, "named users missing");
    require(usersValidate(&users), "validation failed after naming two users");

    /* Rename to a duplicate must fail and leave the old name and index intact. */
    require(! usersSetUserName(&users, bob, "alice"), "rename to duplicate name unexpectedly succeeded");
    require(usersLookupByIdentifier(&users, 2) == bob, "bob vanished after a rejected rename");
    require(usersValidate(&users), "validation failed after a rejected rename");

    /* Rename to an unused name succeeds. */
    require(usersSetUserName(&users, bob, "carol"), "rename to an unused name failed");
    require(usersValidate(&users), "validation failed after a successful rename");
    /* The freed name is reusable now. */
    require(usersSetUserName(&users, alice, "bob"), "reusing a freed name failed");
    require(usersValidate(&users), "validation failed after reusing a freed name");

    /* Rename to empty removes the index entry; unnamed users stay allowed. */
    require(usersSetUserName(&users, alice, ""), "rename to empty failed");
    require(usersValidate(&users), "validation failed after clearing a name");

    usersDestroy(&users);
}

static void testPointerIndexAndRemoval(void)
{
    users_t users;
    user_t  standalone;

    require(usersCreate(&users), "failed to create users table");
    for (uint64_t i = 1; i <= 5; ++i)
    {
        char password[48];
        (void) snprintf(password, sizeof(password), "pointer-pw-%llu", (unsigned long long) i);
        addUser(&users, i, password);
    }
    require(usersCount(&users) == 5, "unexpected user count");

    /* Membership: stored users are members, a standalone user is not. */
    memoryZero(&standalone, sizeof(standalone));
    require(userCreate(&standalone, "pointer-pw-standalone"), "failed to create standalone user");
    require(! usersContainsUser(&users, &standalone), "standalone user reported as a member");
    userDestroy(&standalone);
    for (uint64_t i = 1; i <= 5; ++i)
    {
        require(usersContainsUser(&users, usersLookupByIdentifier(&users, i)), "stored user not reported as a member");
    }
    require(usersValidate(&users), "validation failed on the full pointer table");

    /* Remove middle, then first, then last; every remaining user stays resolvable. */
    const uint64_t removal_order[] = {3, 1, 5};
    bool           present[6]      = {false, true, true, true, true, true};
    for (size_t r = 0; r < 3; ++r)
    {
        user_t *victim = usersLookupByIdentifier(&users, removal_order[r]);
        require(victim != NULL, "victim missing before removal");
        require(usersRemoveUser(&users, victim), "removal failed");
        present[removal_order[r]] = false;

        for (uint64_t i = 1; i <= 5; ++i)
        {
            user_t *found = usersLookupByIdentifier(&users, i);
            if (present[i])
            {
                require(found != NULL, "surviving user stopped resolving after a removal");
                require(usersContainsUser(&users, found), "surviving user lost pointer membership");
            }
            else
            {
                require(found == NULL, "removed user still resolves");
            }
        }
        require(usersValidate(&users), "validation failed after a removal");
    }
    require(usersCount(&users) == 2, "unexpected user count after removals");

    usersDestroy(&users);
}

static ip_addr_t parseIp(const char *text)
{
    ip_addr_t ip;
    memoryZero(&ip, sizeof(ip));
    require(parseIpAddress(text, &ip) != IPADDR_TYPE_ANY, "failed to parse test IP address");
    return ip;
}

static void addAllowedIpUser(users_t *users, uint64_t id, const char *password, const char *cidr)
{
    user_t user;
    memoryZero(&user, sizeof(user));
    require(userCreate(&user, password), "failed to create allowed-ip user");
    userSetId(&user, id);
    require(userSetWireGuardAllowedIps(&user, cidr), "failed to set allowed ips");
    require(usersAddUser(users, &user), "failed to add allowed-ip user");
    userDestroy(&user);
}

static user_t *addNamedAllowedIpUser(users_t *users, uint64_t id, const char *password, const char *name,
                                     const char *cidr)
{
    addAllowedIpUser(users, id, password, cidr);
    user_t *stored = usersLookupByIdentifier(users, id);
    require(stored != NULL, "stored allowed-ip user vanished before naming");
    require(usersSetUserName(users, stored, name), "failed to name allowed-ip user");
    return stored;
}

static users_add_result_t tryAddAllowedIpUser(users_t *users, uint64_t id, const char *password, const char *cidr)
{
    user_t user;
    memoryZero(&user, sizeof(user));
    require(userCreate(&user, password), "failed to create allowed-ip user");
    userSetId(&user, id);
    require(userSetWireGuardAllowedIps(&user, cidr), "failed to set allowed ips");
    users_add_result_t result = usersAddUserChecked(users, &user);
    userDestroy(&user);
    return result;
}

static void testAllowedIpIndex(void)
{
    users_t users;

    require(usersCreate(&users), "failed to create users table");
    addAllowedIpUser(&users, 1, "aip-pw-1", "10.44.0.0/24");
    addAllowedIpUser(&users, 2, "aip-pw-2", "fd00::/64");
    addAllowedIpUser(&users, 3, "aip-pw-3", "192.168.1.5/32");
    require(usersValidate(&users), "validation failed after building the allowed-ip table");

    user_t *u1 = usersLookupByIdentifier(&users, 1);
    user_t *u2 = usersLookupByIdentifier(&users, 2);
    user_t *u3 = usersLookupByIdentifier(&users, 3);

    /* IPv4 boundaries: first and last address of the /24, plus just outside. */
    ip_addr_t v4_first = parseIp("10.44.0.0");
    ip_addr_t v4_last  = parseIp("10.44.0.255");
    ip_addr_t v4_below = parseIp("10.43.255.255");
    ip_addr_t v4_above = parseIp("10.44.1.0");
    require(usersLookupByWireGuardAllowedIp(&users, &v4_first) == u1, "first /24 address did not match");
    require(usersLookupByWireGuardAllowedIp(&users, &v4_last) == u1, "last /24 address did not match");
    require(usersLookupByWireGuardAllowedIp(&users, &v4_below) == NULL, "address below the /24 matched");
    require(usersLookupByWireGuardAllowedIp(&users, &v4_above) == NULL, "address above the /24 matched");

    /* IPv4 /32 host route boundaries. */
    ip_addr_t host      = parseIp("192.168.1.5");
    ip_addr_t host_next = parseIp("192.168.1.6");
    require(usersLookupByWireGuardAllowedIp(&users, &host) == u3, "the /32 host address did not match");
    require(usersLookupByWireGuardAllowedIp(&users, &host_next) == NULL, "an address past the /32 matched");

    /* IPv6 boundaries: first and last address of the /64, plus outside. */
    ip_addr_t v6_first = parseIp("fd00::");
    ip_addr_t v6_last  = parseIp("fd00::ffff:ffff:ffff:ffff");
    ip_addr_t v6_out   = parseIp("fd00:0:0:1::");
    require(usersLookupByWireGuardAllowedIp(&users, &v6_first) == u2, "first /64 address did not match");
    require(usersLookupByWireGuardAllowedIp(&users, &v6_last) == u2, "last /64 address did not match");
    require(usersLookupByWireGuardAllowedIp(&users, &v6_out) == NULL, "address outside the /64 matched");

    /* Family separation: an IPv6 lookup must not match an IPv4 range. */
    ip_addr_t v6_probe_in_v4_numeric = parseIp("::a2c:0");
    require(usersLookupByWireGuardAllowedIp(&users, &v6_probe_in_v4_numeric) == NULL, "family separation failed");

    /* Overlap rejection in both containment directions and for an exact duplicate. */
    require(tryAddAllowedIpUser(&users, 10, "aip-pw-10", "10.44.0.128/25") ==
                kUsersAddResultDuplicateWireGuardAllowedIps,
            "an existing range containing the new one was not rejected");
    require(tryAddAllowedIpUser(&users, 11, "aip-pw-11", "10.44.0.0/16") == kUsersAddResultDuplicateWireGuardAllowedIps,
            "a new range containing an existing one was not rejected");
    require(tryAddAllowedIpUser(&users, 12, "aip-pw-12", "10.44.0.0/24") == kUsersAddResultDuplicateWireGuardAllowedIps,
            "an exact duplicate range was not rejected");
    require(usersValidate(&users), "validation failed after rejected overlaps");

    /* Adjacent, non-overlapping networks are accepted. */
    require(tryAddAllowedIpUser(&users, 13, "aip-pw-13", "10.44.1.0/24") == kUsersAddResultOk,
            "an adjacent /24 was rejected");
    require(usersValidate(&users), "validation failed after adding an adjacent range");
    ip_addr_t adjacent = parseIp("10.44.1.200");
    require(usersLookupByWireGuardAllowedIp(&users, &adjacent) == usersLookupByIdentifier(&users, 13),
            "adjacent range lookup failed");

    /* Update with self-ignore: shrinking a user's own range must not self-collide. */
    user_update_t shrink = {.mask = kUserUpdateWireGuardAllowedIps, .wireguard_allowed_ips = "10.44.0.0/25"};
    require(usersUpdateUser(&users, u1, &shrink), "self-ignoring range update failed");
    require(usersValidate(&users), "validation failed after a range update");
    ip_addr_t now_outside = parseIp("10.44.0.200");
    require(usersLookupByWireGuardAllowedIp(&users, &now_outside) == NULL, "old range still resolved after shrink");
    ip_addr_t still_inside = parseIp("10.44.0.100");
    require(usersLookupByWireGuardAllowedIp(&users, &still_inside) == u1, "new range did not resolve after shrink");

    /* Remove and reinsert: the freed range becomes available again. */
    require(usersRemoveUser(&users, usersLookupByIdentifier(&users, 3)), "failed to remove the /32 user");
    require(usersLookupByWireGuardAllowedIp(&users, &host) == NULL, "removed /32 still resolved");
    require(usersValidate(&users), "validation failed after removal");
    require(tryAddAllowedIpUser(&users, 14, "aip-pw-14", "192.168.1.5/32") == kUsersAddResultOk,
            "reusing a freed range was rejected");
    require(usersLookupByWireGuardAllowedIp(&users, &host) == usersLookupByIdentifier(&users, 14),
            "reinserted /32 did not resolve");
    require(usersValidate(&users), "validation failed after reinsertion");

    usersDestroy(&users);
}

static void testValidationAtScaleAndCorruption(void)
{
    users_t users;

    require(usersCreate(&users), "failed to create users table");
    for (uint64_t i = 1; i <= 400; ++i)
    {
        char password[48];
        (void) snprintf(password, sizeof(password), "validate-pw-%llu", (unsigned long long) i);
        addUser(&users, i, password);
    }
    /* A large valid table must validate without any pairwise user comparison. */
    require(usersValidate(&users), "large valid table failed validation");

    /*
     * Direct corruption of an indexed field (bypassing the public API) must be
     * caught: change a stored user's durable id out from under the id index and
     * confirm validation notices the index no longer resolves to it.
     */
    user_t *victim = usersLookupByIdentifier(&users, 200);
    require(victim != NULL, "victim user missing");
    uint64_t original_id = victim->id;
    victim->id           = 88888888ULL;
    require(! usersValidate(&users), "validation missed a directly corrupted id field");
    victim->id = original_id;
    require(usersValidate(&users), "validation failed after restoring the id field");

    usersDestroy(&users);
}

static void testIncrementalPasswordChange(void)
{
    users_t users;

    require(usersCreate(&users), "failed to create users table");
    addUser(&users, 1, "old-password-one");
    addUser(&users, 2, "other-password-two");
    user_t *u1 = usersLookupByIdentifier(&users, 1);
    user_t *u2 = usersLookupByIdentifier(&users, 2);
    require(u1 != NULL && u2 != NULL, "seed users missing");

    /* A plain password change: old key misses, new key resolves, id is stable. */
    require(usersChangePassword(&users, u1, "new-password-one"), "password change failed");
    require(usersLookupByPassword(&users, "old-password-one") == NULL, "old password still resolves after change");
    require(usersLookupByPassword(&users, "new-password-one") == u1, "new password does not resolve after change");
    require(usersLookupByIdentifier(&users, 1) == u1, "id index changed after a password change");
    require(usersValidate(&users), "validation failed after a password change");

    /* non-UUID -> UUID: the UUID credential index must gain an entry. */
    const char *uuid_pw = "12345678-1234-1234-1234-1234567890ab";
    uint8_t     uuid_bytes[kWwUuidBytesLen];
    require(wwUuidParseString(uuid_pw, uuid_bytes), "failed to parse test UUID");
    require(usersChangePassword(&users, u1, uuid_pw), "change to a UUID password failed");
    require(usersLookupByPassword(&users, uuid_pw) == u1, "UUID password does not resolve");
    require(usersLookupByUUID(&users, uuid_bytes) == u1, "UUID index was not updated on change to UUID");
    require(usersValidate(&users), "validation failed after a change to a UUID password");

    /* UUID -> non-UUID: the UUID index must drop the entry. */
    require(usersChangePassword(&users, u1, "back-to-plain-password"), "change back to a plain password failed");
    require(usersLookupByPassword(&users, "back-to-plain-password") == u1, "plain password does not resolve");
    require(usersLookupByUUID(&users, uuid_bytes) == NULL, "UUID index was not cleared on change away from UUID");
    require(usersValidate(&users), "validation failed after a change away from a UUID password");

    /* Duplicate change rollback: changing u1 to u2's password must be rejected
     * and leave both users' original keys working. */
    require(! usersChangePassword(&users, u1, "other-password-two"),
            "duplicate password change unexpectedly succeeded");
    require(usersLookupByPassword(&users, "back-to-plain-password") == u1, "u1 lost its key after a rejected change");
    require(usersLookupByPassword(&users, "other-password-two") == u2, "u2 lost its key after a rejected change on u1");
    require(usersValidate(&users), "validation failed after a rejected duplicate password change");

    usersDestroy(&users);
}

static user_ip_key_t testIpKey(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    user_ip_key_t key = {.type = 4};
    key.bytes[0]      = a;
    key.bytes[1]      = b;
    key.bytes[2]      = c;
    key.bytes[3]      = d;
    return key;
}

static void testNativeCopy(void)
{
    users_t src;
    users_t dest;

    require(usersCreate(&src), "failed to create src table");
    require(usersCreate(&dest), "failed to create dest table");

    addUser(&src, 1, "copy-pw-one");
    addNamedUser(&src, 2, "copy-pw-two", "named-two");
    addAllowedIpUser(&src, 3, "copy-pw-three", "10.9.0.0/24");
    require(usersValidate(&src), "src table failed validation");

    /* Give a src user some process-local runtime state that must NOT be copied. */
    user_ip_key_t ip_key = testIpKey(203, 0, 113, 7);
    require(usersTryAdmitConnectionByIdentifier(&src, 2, &ip_key, 1000) == kUserAdmissionOk, "failed to admit on src");

    /* Pre-populate dest so we prove the copy replaces prior contents. */
    addUser(&dest, 100, "dest-old-pw");

    require(usersCopy(&dest, &src), "copy failed");
    require(usersValidate(&dest), "dest table failed validation after copy");
    require(usersCount(&dest) == 3, "dest count wrong after copy");
    require(usersLookupByPassword(&dest, "dest-old-pw") == NULL, "dest old user survived the copy");

    /* Copied users are independent allocations resolving by every index. */
    user_t *src1 = usersLookupByPassword(&src, "copy-pw-one");
    user_t *dst1 = usersLookupByPassword(&dest, "copy-pw-one");
    require(src1 != NULL && dst1 != NULL && src1 != dst1, "copy shares user object pointers with the source");
    require(dst1->password != src1->password && stringCompare(dst1->password, src1->password) == 0,
            "copied password is not an independent allocation");
    require(usersLookupByIdentifier(&dest, 2) != NULL, "id index missing in copy");
    ip_addr_t probe = parseIp("10.9.0.100");
    require(usersLookupByWireGuardAllowedIp(&dest, &probe) == usersLookupByIdentifier(&dest, 3),
            "Allowed-IP index missing in copy");

    /* Runtime state was left behind: src still has it, dest's copy is empty. */
    user_t *src2 = usersLookupByIdentifier(&src, 2);
    user_t *dst2 = usersLookupByIdentifier(&dest, 2);
    require(src2->runtime.ip_usage_count == 1, "src lost its runtime state");
    require(dst2->runtime.ip_usage_count == 0, "runtime state leaked into the copy");

    /* Mutating src must not affect the independent dest. */
    require(usersRemoveUser(&src, src1), "failed to remove from src");
    require(usersLookupByPassword(&dest, "copy-pw-one") == dst1, "dest changed when src was mutated");
    require(usersValidate(&dest), "dest invalid after src mutation");

    /* Self-copy is a no-op success. */
    require(usersCopy(&dest, &dest), "self-copy failed");
    require(usersValidate(&dest), "dest invalid after self-copy");

    /* Copying an empty table clears a populated destination. */
    users_t empty;
    users_t into;
    require(usersCreate(&empty), "failed to create empty table");
    require(usersCreate(&into), "failed to create into table");
    addUser(&into, 7, "into-old-pw");
    require(usersCopy(&into, &empty), "empty copy failed");
    require(usersCount(&into) == 0, "empty copy did not clear the destination");
    require(usersValidate(&into), "into table invalid after empty copy");

    usersDestroy(&empty);
    usersDestroy(&into);
    usersDestroy(&src);
    usersDestroy(&dest);
}

static void requireZeroCountIndexesEmpty(users_t *users, const char *password, uint64_t id, const sha224_hash_t *sha224,
                                         const sha256_hash_t *sha256, const uint8_t uuid[kWwUuidBytesLen],
                                         const uint8_t    wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE],
                                         const ip_addr_t *allowed_ip)
{
    require(usersCount(users) == 0, "zero-count regression fixture is not empty");
    require(usersValidate(users), "zero-count users table failed validation");
    require(usersLookupByPassword(users, password) == NULL, "zero-count table retained a password lookup");
    require(usersLookupBySHA224(users, sha224->bytes) == NULL, "zero-count table retained a SHA-224 lookup");
    require(usersLookupBySHA256(users, sha256->bytes) == NULL, "zero-count table retained a SHA-256 lookup");
    require(usersLookupByUUID(users, uuid) == NULL, "zero-count table retained a UUID lookup");
    require(usersLookupByWireGuardPublicKey(users, wireguard_publickey) == NULL,
            "zero-count table retained a WireGuard public-key lookup");
    require(usersLookupByIdentifier(users, id) == NULL, "zero-count table retained an id lookup");
    require(usersLookupByWireGuardAllowedIp(users, allowed_ip) == NULL,
            "zero-count table retained an Allowed-IP lookup");
}

static void testZeroCountIndexesStayEmpty(void)
{
    static const char *password = "12345678-1234-1234-1234-1234567890ab";
    static const char *name     = "zero-count-stale-name";
    static const char *cidr     = "10.66.0.0/24";
    const uint64_t     id       = 424242U;

    users_t users;
    users_t empty;
    require(usersCreate(&users), "failed to create zero-count table");
    require(usersCreate(&empty), "failed to create empty zero-count source table");

    uint8_t uuid[kWwUuidBytesLen];
    require(wwUuidParseString(password, uuid), "failed to parse zero-count UUID password");

    user_t *stored = addNamedAllowedIpUser(&users, id, password, name, cidr);
    require(usersValidate(&users), "zero-count fixture invalid after setup");

    sha224_hash_t sha224 = stored->sha224_pass;
    sha256_hash_t sha256 = stored->sha256_pass;
    uint8_t       wireguard_publickey[USER_WIREGUARD_PUBLICKEY_SIZE];
    memoryCopy(wireguard_publickey, stored->wireguard_publickey, sizeof(wireguard_publickey));
    ip_addr_t allowed_probe = parseIp("10.66.0.7");

    require(usersRemoveUser(&users, stored), "failed to remove zero-count fixture user");
    requireZeroCountIndexesEmpty(&users, password, id, &sha224, &sha256, uuid, wireguard_publickey, &allowed_probe);

    /* Reusing every old key proves stale duplicate entries were actually gone. */
    stored = addNamedAllowedIpUser(&users, id, password, name, cidr);
    require(stored != NULL && usersValidate(&users), "zero-count key reuse after remove failed");

    require(usersClear(&users), "failed to clear zero-count fixture table");
    requireZeroCountIndexesEmpty(&users, password, id, &sha224, &sha256, uuid, wireguard_publickey, &allowed_probe);

    stored = addNamedAllowedIpUser(&users, id, password, name, cidr);
    require(stored != NULL && usersValidate(&users), "zero-count key reuse after clear failed");

    require(usersCopy(&users, &empty), "copying an empty table into a populated table failed");
    requireZeroCountIndexesEmpty(&users, password, id, &sha224, &sha256, uuid, wireguard_publickey, &allowed_probe);

    require(usersRebuildLookups(&users), "rebuilding lookups for an empty table failed");
    requireZeroCountIndexesEmpty(&users, password, id, &sha224, &sha256, uuid, wireguard_publickey, &allowed_probe);

    usersDestroy(&empty);
    usersDestroy(&users);
}

static user_ip_key_t adaptiveIp(int i)
{
    return testIpKey(10, 0, (uint8_t) (i >> 8), (uint8_t) (i & 0xFF));
}

static void testAdaptiveIpIndex(void)
{
    user_t user;

    memoryZero(&user, sizeof(user));
    require(userCreate(&user, "adaptive-ip-pw"), "failed to create adaptive-ip user");

    /* Small distinct-IP set stays on the allocation-free linear path. */
    for (int i = 0; i < 10; ++i)
    {
        user_ip_key_t key = adaptiveIp(i);
        require(userTryAdmitConnection(&user, &key, 1000) == kUserAdmissionOk, "admit below threshold failed");
    }
    require(user.runtime.ip_usage_count == 10, "distinct count wrong below threshold");
    require(user.runtime.ip_index == NULL, "adaptive index allocated below the promotion threshold");

    /* Crossing the threshold promotes the adaptive index. */
    for (int i = 10; i < 40; ++i)
    {
        user_ip_key_t key = adaptiveIp(i);
        require(userTryAdmitConnection(&user, &key, 1000) == kUserAdmissionOk, "admit above threshold failed");
    }
    require(user.runtime.ip_usage_count == 40, "distinct count wrong above threshold");
    require(user.runtime.ip_index != NULL, "adaptive index was not promoted above the threshold");

    /* Every admitted IP still resolves through the index (re-admit does not grow
     * the distinct set). */
    for (int i = 0; i < 40; ++i)
    {
        user_ip_key_t key = adaptiveIp(i);
        require(userTryAdmitConnection(&user, &key, 1000) == kUserAdmissionOk, "re-admit failed");
    }
    require(user.runtime.ip_usage_count == 40, "re-admitting existing IPs changed the distinct count");
    for (int i = 0; i < 40; ++i)
    {
        user_ip_key_t key = adaptiveIp(i);
        userReleaseConnection(&user, &key); /* back down to one ref each */
    }
    require(user.runtime.ip_usage_count == 40, "releasing an extra ref dropped a slot");

    /*
     * Swap-with-last removal must fix up the moved entry's index in the map:
     * drop IP 0 (its last ref), which moves IP 39 into slot 0. Re-admitting IP 39
     * must then find its existing slot instead of creating a duplicate.
     */
    user_ip_key_t ip0  = adaptiveIp(0);
    user_ip_key_t ip39 = adaptiveIp(39);
    userReleaseConnection(&user, &ip0);
    require(user.runtime.ip_usage_count == 39, "dropping the last ref did not shrink the set");
    require(userTryAdmitConnection(&user, &ip39, 1000) == kUserAdmissionOk, "re-admit of the moved IP failed");
    require(user.runtime.ip_usage_count == 39, "swap-with-last did not update the moved IP's index");

    /* Move the runtime state (as runtime migration does) and confirm the index
     * transfers exactly once: source cleared, destination carries it. */
    user_t moved;
    memoryZero(&moved, sizeof(moved));
    require(userCreate(&moved, "adaptive-ip-move-pw"), "failed to create move destination");
    size_t moved_count = user.runtime.ip_usage_count;
    userRuntimeStateMove(&moved.runtime, &user.runtime);
    require(user.runtime.ip_index == NULL && user.runtime.ip_usage_count == 0, "source runtime not cleared by move");
    require(moved.runtime.ip_index != NULL && moved.runtime.ip_usage_count == moved_count,
            "destination did not receive the moved runtime index");
    require(userTryAdmitConnection(&moved, &ip39, 1000) == kUserAdmissionOk, "moved index lookup failed");
    require(moved.runtime.ip_usage_count == moved_count, "moved index reported a stale distinct count");

    userDestroy(&moved);
    userDestroy(&user);
}

/*
 * userRuntimeStateMove(&x, &x) must be a no-op that preserves x. Without the
 * dest == src guard it would clear x (freeing its buffers) and then copy the
 * cleared state back over itself, losing the runtime IPs and double-freeing.
 */
static void testRuntimeStateSelfMove(void)
{
    user_t user;
    memoryZero(&user, sizeof(user));
    require(userCreate(&user, "self-move-pw"), "failed to create self-move user");

    for (int i = 0; i < 40; ++i)
    {
        user_ip_key_t key = adaptiveIp(i);
        require(userTryAdmitConnection(&user, &key, 1000) == kUserAdmissionOk, "self-move admit failed");
    }
    require(user.runtime.ip_usage_count == 40 && user.runtime.ip_index != NULL, "self-move setup wrong");

    userRuntimeStateMove(&user.runtime, &user.runtime);

    require(user.runtime.ip_usage_count == 40, "self-move lost the distinct-IP count");
    require(user.runtime.ip_index != NULL, "self-move dropped the adaptive index");
    user_ip_key_t probe = adaptiveIp(17);
    require(userTryAdmitConnection(&user, &probe, 1000) == kUserAdmissionOk, "self-move lost index lookups");
    require(user.runtime.ip_usage_count == 40, "self-move corrupted the distinct set");

    userDestroy(&user);
}

#if defined(USERS_TEST_ALLOC_INJECTION)
enum
{
    kAllocationFailureSweepSafetyLimit = 256
};

/*
 * Removal must not allocate: it only erases index entries, swaps the last active
 * pointer into the freed slot, rewrites one existing pointer-map value, and frees
 * the victim. Counting allocations across a removal proves the swap-with-last path
 * is allocation-free and therefore cannot fail after items[] has been mutated.
 */
static void testRemovalIsAllocationFree(void)
{
    users_t users;
    require(usersCreate(&users), "failed to create users table");
    for (uint64_t i = 1; i <= 16; ++i)
    {
        char password[48];
        (void) snprintf(password, sizeof(password), "remove-free-pw-%llu", (unsigned long long) i);
        addUser(&users, i, password);
    }

    /* Remove a middle user so the swap-with-last branch (moved != removed) runs. */
    user_t *victim = usersLookupByIdentifier(&users, 5);
    require(victim != NULL, "victim user missing");

    allocInjectionArm(0); /* count only; never fail */
    bool   ok          = usersRemoveUser(&users, victim);
    size_t allocations = allocInjectionDisarm();

    require(ok, "removal failed");
    require(allocations == 0, "removal performed a heap allocation; the swap-with-last path is not allocation-free");
    require(usersValidate(&users), "database invalid after allocation-free removal");
    require(usersCount(&users) == 15, "removal did not shrink the table");

    usersDestroy(&users);
}

/*
 * Fills the ordered Allowed-IP tree to its initial reserved capacity with
 * `ranged` users carrying distinct, non-overlapping /24 ranges (ids 1..ranged).
 * Because the tree's first reservation sizes it for 16 nodes, a fixture of 16
 * ranged users leaves the next range insertion (a 17th) forced to grow the tree,
 * which is an allocation made directly inside users.c and therefore observable to
 * (and failable by) the injection probe. String copies inside userChangePassword
 * route through libww and are deliberately not the allocation under test here.
 */
static void buildRangedFixture(users_t *users, uint64_t ranged)
{
    require(usersCreate(users), "failed to create users table");
    for (uint64_t i = 0; i < ranged; ++i)
    {
        char pw[40];
        char cidr[24];
        (void) snprintf(pw, sizeof(pw), "ranged-pw-%llu", (unsigned long long) i);
        (void) snprintf(cidr, sizeof(cidr), "10.0.%llu.0/24", (unsigned long long) i);
        addAllowedIpUser(users, i + 1U, pw, cidr);
    }
    require(usersValidate(users), "ranged fixture failed validation");
}

/* The Allowed-IP tree is reserved for this many nodes on first use; the (N+1)th
 * range insertion is the one that grows it. */
enum
{
    kAllowedIpInitialCapacity = 16
};

/*
 * Sweeps a single injected allocation failure across an update that adds a
 * brand-new Allowed-IP range (alongside a password change and a rename) to a
 * target user, where the tree is already full so the reinsert must grow it. At
 * every failure point the update must be atomic: it either fully commits or fully
 * rolls back, and the database stays valid with exactly one of the old/new
 * credential+range sets live. This exercises the incremental password reindex
 * (Finding 1) and, crucially, the reserve-before-mutation Allowed-IP path
 * (Finding 2): the growth is reserved before any field is published.
 */
static void testUpdateAllocationFailureIsTransactional(void)
{
    const ip_addr_t new_range_probe = parseIp("10.1.0.9");

    for (size_t fail_at = 1;; ++fail_at)
    {
        require(fail_at <= kAllocationFailureSweepSafetyLimit, "update allocation-failure sweep did not converge");

        users_t users;
        buildRangedFixture(&users, kAllowedIpInitialCapacity);
        /* A ranged tree at capacity, plus one target that has a name but no range. */
        user_t *target = addNamedUser(&users, 100, "txn-old-pw", "txn-name-old");
        require(target != NULL && usersValidate(&users), "update fixture setup failed");

        user_update_t update;
        memoryZero(&update, sizeof(update));
        update.mask                  = kUserUpdatePassword | kUserUpdateName | kUserUpdateWireGuardAllowedIps;
        update.password              = "txn-new-pw";
        update.name                  = "txn-name-new";
        update.wireguard_allowed_ips = "10.1.0.0/24"; /* non-overlapping 17th range */

        allocInjectionArm(fail_at);
        bool   ok          = usersUpdateUser(&users, target, &update);
        size_t allocations = allocInjectionDisarm();

        require(usersValidate(&users), "database corrupted by an injected allocation failure during update");
        ip_addr_t probe = new_range_probe;

        if (ok)
        {
            require(usersLookupByPassword(&users, "txn-new-pw") == target, "committed update lost the new password");
            require(usersLookupByPassword(&users, "txn-old-pw") == NULL, "old password survived a committed update");
            require(usersLookupByWireGuardAllowedIp(&users, &probe) == target,
                    "committed update did not index the new range");
        }
        else
        {
            require(usersLookupByPassword(&users, "txn-old-pw") == target, "rolled-back update lost the old password");
            require(usersLookupByPassword(&users, "txn-new-pw") == NULL,
                    "new password leaked from a rolled-back update");
            require(usersLookupByWireGuardAllowedIp(&users, &probe) == NULL,
                    "new range leaked from a rolled-back update");
        }

        usersDestroy(&users);

        /* Stop once an attempt completes without tripping the injected failure. */
        if (ok && allocations < fail_at)
        {
            break;
        }
    }
}

/*
 * Sweeps a single injected allocation failure across a checked add of a ranged
 * user into a tree that is already full (so the commit must grow it). At every
 * failure point the add must be atomic: it either fully commits (count grows by
 * one, the user resolves) or fully rolls back (count unchanged, the user is
 * absent) and reports the allocation failure distinctly, and the database stays
 * valid. This exercises the prevalidated commit path (Finding 5).
 */
static void testAddAllocationFailureIsTransactional(void)
{
    for (size_t fail_at = 1;; ++fail_at)
    {
        require(fail_at <= kAllocationFailureSweepSafetyLimit, "add allocation-failure sweep did not converge");

        users_t users;
        buildRangedFixture(&users, kAllowedIpInitialCapacity);
        const size_t base_count = usersCount(&users);

        user_t candidate;
        memoryZero(&candidate, sizeof(candidate));
        require(userCreate(&candidate, "txn-add-pw"), "failed to create add candidate");
        userSetId(&candidate, 100);
        require(userSetWireGuardAllowedIps(&candidate, "10.1.0.0/24"), "failed to set candidate range");

        allocInjectionArm(fail_at);
        users_add_result_t result      = usersAddUserChecked(&users, &candidate);
        size_t             allocations = allocInjectionDisarm();
        userDestroy(&candidate);

        require(usersValidate(&users), "database corrupted by an injected allocation failure during add");
        if (result == kUsersAddResultOk)
        {
            require(usersCount(&users) == base_count + 1, "committed add did not grow the table");
            require(usersLookupByPassword(&users, "txn-add-pw") != NULL, "committed add is not resolvable");
        }
        else
        {
            require(result == kUsersAddResultAllocationFailed,
                    "add failed for a non-allocation reason under injection");
            require(usersCount(&users) == base_count, "rolled-back add changed the table size");
            require(usersLookupByPassword(&users, "txn-add-pw") == NULL, "rolled-back add left a resolvable user");
        }

        usersDestroy(&users);

        if (result == kUsersAddResultOk && allocations < fail_at)
        {
            break;
        }
    }
}

static void testCopyAllocationFailureIsAtomic(void)
{
    for (size_t fail_at = 1;; ++fail_at)
    {
        require(fail_at <= kAllocationFailureSweepSafetyLimit, "copy allocation-failure sweep did not converge");

        users_t src;
        users_t dest;
        require(usersCreate(&src), "failed to create copy source table");
        require(usersCreate(&dest), "failed to create copy destination table");

        addNamedUser(&src, 1, "copy-fail-src-one", "copy-fail-name-one");
        addAllowedIpUser(&src, 2, "copy-fail-src-two", "10.77.0.0/24");
        addUser(&dest, 100, "copy-fail-dest-old");
        require(usersValidate(&src), "copy source fixture invalid");
        require(usersValidate(&dest), "copy destination fixture invalid");

        allocInjectionArm(fail_at);
        bool   ok          = usersCopy(&dest, &src);
        size_t allocations = allocInjectionDisarm();

        require(usersValidate(&src), "copy source corrupted by allocation injection");
        require(usersValidate(&dest), "copy destination corrupted by allocation injection");
        if (ok)
        {
            require(usersCount(&dest) == usersCount(&src), "committed copy produced the wrong destination count");
            require(usersLookupByPassword(&dest, "copy-fail-dest-old") == NULL,
                    "committed copy retained the old destination user");
            require(usersLookupByPassword(&dest, "copy-fail-src-one") != NULL, "committed copy lost source user one");
            ip_addr_t probe = parseIp("10.77.0.99");
            require(usersLookupByWireGuardAllowedIp(&dest, &probe) != NULL,
                    "committed copy lost source Allowed-IP index");
        }
        else
        {
            require(usersCount(&dest) == 1, "failed copy changed the destination count");
            require(usersLookupByPassword(&dest, "copy-fail-dest-old") != NULL,
                    "failed copy lost the old destination user");
            require(usersLookupByPassword(&dest, "copy-fail-src-one") == NULL,
                    "failed copy leaked a source user into the destination");
        }

        usersDestroy(&src);
        usersDestroy(&dest);

        if (ok && allocations < fail_at)
        {
            break;
        }
    }
}

static void testRebuildLookupAllocationFailureIsAtomic(void)
{
    for (size_t fail_at = 1;; ++fail_at)
    {
        require(fail_at <= kAllocationFailureSweepSafetyLimit, "rebuild allocation-failure sweep did not converge");

        users_t users;
        require(usersCreate(&users), "failed to create rebuild table");

        addNamedUser(&users, 1, "rebuild-fail-one", "rebuild-name-one");
        addAllowedIpUser(&users, 2, "rebuild-fail-two", "10.88.0.0/24");
        addUser(&users, 3, "rebuild-fail-three");
        require(usersValidate(&users), "rebuild fixture invalid before injection");

        allocInjectionArm(fail_at);
        bool   ok          = usersRebuildLookups(&users);
        size_t allocations = allocInjectionDisarm();

        require(usersValidate(&users), "lookup rebuild failure left the database with partial indexes");
        require(usersCount(&users) == 3, "lookup rebuild failure changed the user count");
        require(usersLookupByPassword(&users, "rebuild-fail-one") != NULL, "lookup rebuild lost password user one");
        require(usersLookupByPassword(&users, "rebuild-fail-two") != NULL, "lookup rebuild lost password user two");
        require(usersLookupByIdentifier(&users, 3) != NULL, "lookup rebuild lost identifier user three");
        ip_addr_t probe = parseIp("10.88.0.55");
        require(usersLookupByWireGuardAllowedIp(&users, &probe) != NULL, "lookup rebuild lost Allowed-IP user");

        usersDestroy(&users);

        if (ok && allocations < fail_at)
        {
            break;
        }
    }
}
#endif

int main(void)
{
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization failed");

    testNameIndex();
    testPointerIndexAndRemoval();
    testAllowedIpIndex();
    testValidationAtScaleAndCorruption();
    testIncrementalPasswordChange();
    testNativeCopy();
    testZeroCountIndexesStayEmpty();
    testAdaptiveIpIndex();
    testPasswordHitSingleHash();
    testPasswordMissSingleHash();
    testExactVerificationDerivesNoHash();
    testCollisionFailsClosed();
    testRuntimeStateSelfMove();
#if defined(USERS_TEST_ALLOC_INJECTION)
    testRemovalIsAllocationFree();
    testUpdateAllocationFailureIsTransactional();
    testAddAllocationFailureIsTransactional();
    testCopyAllocationFailureIsAtomic();
    testRebuildLookupAllocationFailureIsAtomic();
#endif

    printf("users_index_test: all checks passed\n");
    return 0;
}
