/*
 * Covers: users index; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Cases: testPasswordHitSingleHash, testPasswordMissSingleHash, testExactVerificationDerivesNoHash,
 * testCollisionFailsClosed, testNameIndex, testPointerIndexAndRemoval, testAllowedIpIndex,
 * testValidationAtScaleAndCorruption; the driver lists the remaining cases
 * Checks: Assertion labels include: stored user vanished before naming; password hit returned NULL;
 * password hit returned the wrong user; password hit
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.users_index_unit
 * Organization: Lookup, mutation, removal and copy check the users table indexes through
 * allocation counting and crypto seams. Invalid updates and crypto failures retain transactional checks.
 */
/*
 * Focused correctness and instrumentation tests for the users_t lookup indexes.
 *
 * This file is grown alongside the users/performance work. Its first
 * responsibility (Phase 0/1) is to prove the plaintext-password hot path:
 *
 *   - a password hit derives SHA-256 exactly once and SHA-224 zero times
 *   - a password miss derives SHA-256 exactly once and SHA-224 zero times
 *   - candidate verification (userPasswordMatches) derives no SHA at all
 *   - a SHA-256 index collision fails closed (exact plaintext still decides)
 *
 * The SHA call counts are only available in the linker-wrap build configuration;
 * the functional assertions run unconditionally so the test is still meaningful
 * on platforms without --wrap.
 */

#include "objects/user_index_geometry.h"
#include "objects/users_internal.h"

#if defined(OS_LINUX)
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include "wthread.h"
#include "wwapi.h"

#include "fixtures/user_runtime.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

/* Exact chosen home buckets exercise the dependency independently of the
 * production randomized hash. Low 32 bits distinguish keys sharing a home. */
static size_t collisionHomeHash(const uint64_t *key)
{
    return (size_t) (*key >> 32U);
}
#define i_type collision_map_t
#define i_key  uint64_t
#define i_val  uint64_t
#define i_hash collisionHomeHash
#include "stc/hmap.h"

static void testSaturatedHashDistances(void)
{
    collision_map_t map = {0};
    require(collision_map_t_reserve(&map, 4096), "collision map reserve failed");
    /* Existing short-distance entries must survive displacement by the long
     * cluster, including displacement after metadata saturation. */
    for (uint64_t i = 0; i < 128; ++i)
    {
        uint64_t key = ((1200U + i * 7U) << 32U) | 1U;
        require(collision_map_t_insert(&map, key, key).inserted, "sparse insert failed");
    }
    for (uint64_t i = 1; i <= 3000; ++i)
        require(collision_map_t_insert(&map, i, i).inserted, "colliding insertion refused or lost uniqueness");
    for (unsigned phase = 0; phase < 2; ++phase)
    {
        for (uint64_t i = 1; i <= 3000; ++i)
        {
            const collision_map_t_value *found = collision_map_t_get(&map, i);
            require(found != NULL && found->second == i, "saturated cluster lost a key");
            require(! collision_map_t_insert(&map, i, 0).inserted, "saturated cluster accepted duplicate");
        }
        for (uint64_t i = 0; i < 128; ++i)
        {
            uint64_t                     key   = ((1200U + i * 7U) << 32U) | 1U;
            const collision_map_t_value *found = collision_map_t_get(&map, key);
            require(found != NULL && found->second == key, "displacement lost another home bucket");
        }
        require(collision_map_t_reserve(&map, 10000), "collision rehash failed");
    }
    /* A second cluster crosses the physical end of the bucket array. */
    for (uint64_t i = 1; i <= 1400; ++i)
    {
        uint64_t key = (UINT64_C(16300) << 32U) | i;
        require(collision_map_t_insert(&map, key, i).inserted, "wrapped cluster insertion failed");
    }
    for (uint64_t i = 1; i <= 3000; ++i)
        require(collision_map_t_erase(&map, i) == 1, "backward shift lost colliding key");
    for (uint64_t i = 1400; i != 0; --i)
    {
        uint64_t key = (UINT64_C(16300) << 32U) | i;
        require(collision_map_t_erase(&map, key) == 1, "wrapped backward shift lost key");
    }
    require(collision_map_t_size(&map) == 128, "collision erase left phantom occupancy");
    for (uint64_t i = 0; i < 128; ++i)
    {
        uint64_t key = ((1200U + i * 7U) << 32U) | 1U;
        require(collision_map_t_erase(&map, key) == 1, "erase moved a key before its home");
    }
    require(collision_map_t_size(&map) == 0, "collision map did not drain");
    collision_map_t_drop(&map);
}

#if defined(WW_SYNC_INIT_TEST_SEAM)
static atomic_size_t g_native_init_calls, g_native_init_failure, g_native_resources;
bool                 wSyncInitTestShouldFail(void)
{
    size_t call = atomic_fetch_add(&g_native_init_calls, 1U) + 1U;
    return atomic_load(&g_native_init_failure) == call;
}
void wSyncInitTestResourceAcquired(void)
{
    atomic_fetch_add(&g_native_resources, 1U);
}
void wSyncInitTestResourceDestroyed(void)
{
    atomic_fetch_sub(&g_native_resources, 1U);
}
#endif

#if defined(WCRYPTO_TEST_LINKER_WRAP)
/* Deterministic monotonic cutoffs exercise pre-publication stages without
 * sleeping or changing the deadline contract in production. */
static uint64_t g_creation_clock_us;
static unsigned g_creation_clock_reads, g_creation_clock_expire_at;
uint64_t        __real_getHRTimeUs(void);
uint64_t        __wrap_getHRTimeUs(void);
uint64_t        __wrap_getHRTimeUs(void)
{
    if (g_creation_clock_us == 0)
        return __real_getHRTimeUs();
    ++g_creation_clock_reads;
    if (g_creation_clock_expire_at != 0 && g_creation_clock_reads >= g_creation_clock_expire_at)
        return g_creation_clock_us + UINT64_C(1000000);
    return g_creation_clock_us;
}

static size_t g_sha224_calls;
static size_t g_sha256_calls;
static size_t g_x25519_calls;

/*
 * Disabled-by-default "fail on call N" control. When g_shaXXX_fail_on_call is
 * non-zero, the Nth derivation of that primitive returns kWCryptoBackendFailed
 * instead of computing; every other call passes through. The password-change
 * path derives each primitive once in owned preparation. Failing that real
 * preparation exercises cleanup without retaining obsolete duplicate work.
 */
static size_t g_sha224_fail_on_call;
static size_t g_sha256_fail_on_call;
static size_t g_x25519_fail_on_call;

/* When enabled, every SHA-256 derivation returns this fixed value, which lets
 * the test synthesize an index collision between two distinct plaintexts. */
static bool     g_force_sha224_enabled, g_force_wireguard_enabled;
static uint8_t  g_force_sha224_value[SHA224_DIGEST_SIZE];
static uint8_t  g_force_wireguard_value[USER_WIREGUARD_PUBLICKEY_SIZE];
static users_t *g_password_derivation_users;
static user_t  *g_password_derivation_user;
static bool     g_force_sha256_enabled;
static uint8_t  g_force_sha256_value[SHA256_DIGEST_SIZE];

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

static void passwordDerivationLocksAvailable(void)
{
    if (g_password_derivation_users != NULL)
    {
        require(rwlockTryWriteLock(&g_password_derivation_users->lock), "password derived under collection lock");
        rwlockWriteUnlock(&g_password_derivation_users->lock);
        require(rwlockTryWriteLock(&g_password_derivation_user->lock), "password derived under target lock");
        rwlockWriteUnlock(&g_password_derivation_user->lock);
    }
}

wcrypto_status_t __wrap_wCryptoSHA224(sha224_hash_t *out, const unsigned char *in, size_t inlen)
{
    passwordDerivationLocksAvailable();
    if (g_password_derivation_users != NULL)
        require((uintptr_t) out % 32U == 0, "SHA-224 output lacks aligned staging");
    g_sha224_calls += 1U;
    if (g_sha224_fail_on_call != 0U && g_sha224_calls == g_sha224_fail_on_call)
    {
        return kWCryptoBackendFailed;
    }
    if (g_force_sha224_enabled)
    {
        memoryCopy(out->bytes, g_force_sha224_value, sizeof(out->bytes));
        return kWCryptoOk;
    }
    return __real_wCryptoSHA224(out, in, inlen);
}

wcrypto_status_t __wrap_wCryptoSHA256(sha256_hash_t *out, const unsigned char *in, size_t inlen)
{
    passwordDerivationLocksAvailable();
    if (g_password_derivation_users != NULL)
        require((uintptr_t) out % 32U == 0, "SHA-256 output lacks aligned staging");
    g_sha256_calls += 1U;
    if (g_sha256_fail_on_call != 0U && g_sha256_calls == g_sha256_fail_on_call)
    {
        return kWCryptoBackendFailed;
    }
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
    passwordDerivationLocksAvailable();
    g_x25519_calls += 1U;
    if (g_x25519_fail_on_call != 0U && g_x25519_calls == g_x25519_fail_on_call)
    {
        return kWCryptoBackendFailed;
    }
    if (g_force_wireguard_enabled)
    {
        memoryCopy(out, g_force_wireguard_value, USER_WIREGUARD_PUBLICKEY_SIZE);
        return kWCryptoOk;
    }
    return __real_wCryptoX25519(out, scalar, point);
}

#endif

#if defined(USERS_TEST_ALLOC_COUNTING)
/* Count core allocations without replacing their succeed-or-terminate contract. */
static bool   g_alloc_probe_active;
static size_t g_alloc_calls, g_alloc_bytes;
static void  *g_secret_free_watch;
static size_t g_secret_free_bytes, g_secret_wipes, g_secret_capture_bytes;

void __real_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr)
{
    if (ptr != NULL && ptr == g_secret_free_watch)
    {
        for (size_t i = 0; i < g_secret_free_bytes; ++i)
            require(((const uint8_t *) ptr)[i] == 0, "owned password freed without secure cleanup");
        ++g_secret_wipes;
        g_secret_free_watch = NULL;
    }
    __real_memoryFree(ptr);
}

void *__real_memoryAllocate(size_t size);
void *__real_memoryReAllocate(void *ptr, size_t size);
void *__real_memoryCalloc(size_t count, size_t size);
void *__wrap_memoryAllocate(size_t size);
void *__wrap_memoryReAllocate(void *ptr, size_t size);
void *__wrap_memoryCalloc(size_t count, size_t size);

static void countAllocation(size_t bytes)
{
    if (g_alloc_probe_active)
    {
        ++g_alloc_calls;
        g_alloc_bytes += bytes;
    }
}

void *__wrap_memoryAllocate(size_t size)
{
    countAllocation(size);
    void *ptr = __real_memoryAllocate(size);
    if (g_secret_capture_bytes == size)
    {
        g_secret_free_watch    = ptr;
        g_secret_free_bytes    = size;
        g_secret_capture_bytes = 0;
    }
    return ptr;
}

void *__wrap_memoryReAllocate(void *ptr, size_t size)
{
    countAllocation(size);
    return __real_memoryReAllocate(ptr, size);
}

void *__wrap_memoryCalloc(size_t count, size_t size)
{
    countAllocation(count * size);
    return __real_memoryCalloc(count, size);
}

static void allocationCountBegin(void)
{
    g_alloc_calls        = 0;
    g_alloc_bytes        = 0;
    g_alloc_probe_active = true;
}

static size_t allocationCountEnd(void)
{
    g_alloc_probe_active = false;
    return g_alloc_calls;
}
#endif

#if defined(USERS_TEST_CREDENTIAL_SNAPSHOT_WIPE_COUNTER)
extern size_t users_test_credential_snapshot_wipes;
#endif

static void resetCounters(void)
{
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    g_sha224_calls        = 0;
    g_sha256_calls        = 0;
    g_x25519_calls        = 0;
    g_sha224_fail_on_call = 0;
    g_sha256_fail_on_call = 0;
    g_x25519_fail_on_call = 0;
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

static void testLegacyInsertionOwnershipAndRefusals(void)
{
    users_t users;
    user_t  source = {0};
    cJSON  *json =
        cJSON_Parse("{\"id\":73,\"password\":\"legacy-insertion-password\","
                    "\"name\":\"legacy-source\",\"email\":\"source@example.test\",\"notes\":\"source notes\"}");
    require(usersCreate(&users) && userCreateFromJson(&source, json), "legacy insertion setup failed");
    cJSON_Delete(json);
    require(userSetWireGuardAllowedIps(&source, "10.73.0.0/24"), "legacy insertion routing setup failed");

#if defined(WW_SYNC_INIT_TEST_SEAM)
    const size_t resources = atomic_load(&g_native_resources);
    /* Both private-snapshot and destination-slot lock initializations remain
     * fallible; failure must leave the caller's value and every index intact. */
    for (size_t stage = 1; stage <= 4; ++stage)
    {
        atomic_store(&g_native_init_failure, atomic_load(&g_native_init_calls) + stage);
        require(! usersAddUser(&users, &source), "legacy insertion accepted failed native initialization");
        atomic_store(&g_native_init_failure, 0);
        require(atomic_load(&g_native_resources) == resources && usersCount(&users) == 0 && users.slot_count == 0 &&
                    usersLookupByPassword(&users, "legacy-insertion-password") == NULL && usersValidate(&users),
                "failed legacy insertion leaked locks, consumed a slot or changed indexes");
        require(userPasswordMatches(&source, "legacy-insertion-password") && strcmp(source.name, "legacy-source") == 0,
                "failed legacy insertion consumed the caller's value");
    }
#endif

    require(usersAddUser(&users, &source), "legacy insertion failed after native refusals");
    user_t *stored = usersLookupByIdentifier(&users, 73);
    require(stored != NULL && stored != &source && stored->password != source.password && stored->name != source.name &&
                stored->email != source.email && stored->notes != source.notes &&
                stored->wireguard_allowed_ips != source.wireguard_allowed_ips &&
                usersLookupByPassword(&users, "legacy-insertion-password") == stored && usersValidate(&users),
            "legacy insertion shares caller storage or failed to publish indexes");
    require(! usersAddUser(&users, &source) && usersCount(&users) == 1 && users.slot_count == 1 &&
                usersLookupByIdentifier(&users, 73) == stored && usersValidate(&users),
            "duplicate legacy insertion changed the existing account or indexes");
    require(userChangePassword(&source, "mutated-source-password") &&
                userSetWireGuardAllowedIps(&source, "10.74.0.0/24"),
            "legacy source mutation failed");
    userDestroy(&source);
    require(userPasswordMatches(stored, "legacy-insertion-password") &&
                strcmp(stored->wireguard_allowed_ips, "10.73.0.0/24") == 0 &&
                strcmp(stored->name, "legacy-source") == 0 && strcmp(stored->email, "source@example.test") == 0 &&
                strcmp(stored->notes, "source notes") == 0 && usersValidate(&users),
            "caller mutation/destruction changed the independently stored account");
    usersDestroy(&users);
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

    /* A hit in a large table must still use the single-hash lookup path. */
    resetCounters();
    user_t *found = usersLookupByPassword(&populated, "miss-password-500");
    require(found != NULL, "expected hit in large table");
    require(userGetId(found) == 501U, "large-table hit returned the wrong user");
    requireSingleSha256HotPath("large-table hit");

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

static void testStrictAllowedIps(void)
{
    static const char *invalid[] = {"10/8",
                                    "192.168.1/24",
                                    "010.0.0.1/32",
                                    "0x0a.0.0.1/32",
                                    "256.0.0.1/32",
                                    "12345::/16",
                                    "1:2:3:4:5:6:7:8zz/128",
                                    "10.0.0.1x/32",
                                    "10.0.0.1/33",
                                    "::1/129",
                                    "::1/-1",
                                    "::1/1/2",
                                    "10. 0.0.1/32",
                                    ":: 1/128",
                                    "10.0.0.1/ 32",
                                    "10.0.0.1/32,10.0.0.2/32"};
    static const char *valid[]   = {
        "0.0.0.0/0", "10.0.0.1/32", "::/0", "::1/128", "2001:db8:0:0:0:0:0:1/64", "::ffff:192.0.2.1/128"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
        require(userWireGuardAllowedIpsStringValid(valid[i]), "strict CIDR rejected valid address");
    users_t users;
    require(usersCreate(&users), "strict CIDR table creation failed");
    user_t *existing = addNamedAllowedIpUser(&users, 1, "strict-existing", "original", "10.7.8.9/24");
    require(strcmp(existing->wireguard_allowed_ips, "10.7.8.0/24") == 0, "CIDR host-bit normalization changed");
    char *normalized = NULL;
    require(userWireGuardAllowedIpsParse(" \t10.7.8.9/24\r\n", &normalized, NULL, NULL, NULL, NULL, NULL, NULL) &&
                strcmp(normalized, "10.7.8.0/24") == 0,
            "surrounding CIDR whitespace was not trimmed");
    memoryFree(normalized);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        require(! userWireGuardAllowedIpsStringValid(invalid[i]), "strict CIDR accepted malformed address");
        user_config_patch_t patch = {.mask                  = kUserConfigName | kUserConfigWireGuardAllowedIps,
                                     .name                  = "changed",
                                     .wireguard_allowed_ips = invalid[i]};
        require(usersPatchConfigByIdentifier(&users, 1, &patch) == kUsersUpdateResultInvalidWireGuardAllowedIps &&
                    strcmp(existing->name, "original") == 0 &&
                    strcmp(existing->wireguard_allowed_ips, "10.7.8.0/24") == 0,
                "invalid CIDR patch changed existing configuration");
        cJSON  *entry = cJSON_CreateObject();
        discard cJSON_AddNumberToObject(entry, "id", 2);
        discard cJSON_AddStringToObject(entry, "password", "strict-new");
        discard cJSON_AddStringToObject(entry, "wireguard-allowed-ips", invalid[i]);
        require(! usersFeedJson(&users, entry) && usersCount(&users) == 1 &&
                    usersLookupByIdentifier(&users, 2) == NULL && usersValidate(&users),
                "invalid CIDR import changed table or indexes");
        user_prepared_creation_t *prepared = NULL;
        require(usersPrepareNewUser(2, "strict-new", &patch, SIZE_MAX, 0, &prepared) ==
                        kUsersAddResultInvalidWireGuardAllowedIps &&
                    prepared == NULL,
                "fresh-account preparation accepted malformed CIDR");
        cJSON_Delete(entry);
    }
    ip_addr_t probe = parseIp("10.7.8.20");
    require(usersLookupByWireGuardAllowedIp(&users, &probe) == existing, "invalid CIDR changed range index");
    usersDestroy(&users);
}

static void testImportLayoutsAndReservation(void)
{
    static const char *layouts[] = {
        "{\"password\":{\"id\":1,\"password\":\"map-one\"}}",
        "{\"pass\":{\"id\":1,\"password\":\"map-one\"}}",
        "{\"password\":{\"id\":1,\"password\":\"map-one\"},\"pass\":{\"id\":2,\"pass\":\"map-two\"}}",
        "{\"ordinary\":{\"id\":1,\"password\":\"map-one\",\"name\":\"explicit\"}}",
        "{\"id\":1,\"password\":\"single\"}",
        "{\"id\":1,\"pass\":\"single\"}",
        "{\"users\":[{\"id\":1,\"password\":\"wrapped\"}],\"password\":{}}"};
    for (size_t i = 0; i < sizeof(layouts) / sizeof(layouts[0]); ++i)
    {
        users_t users;
        require(usersCreate(&users), "layout table creation failed");
        cJSON *json = cJSON_Parse(layouts[i]);
        require(json != NULL && usersFeedJson(&users, json) && usersValidate(&users), "user layout import failed");
        user_t *user = usersLookupByIdentifier(&users, 1);
        require(user != NULL && usersCount(&users) == (i == 2 ? 2U : 1U), "user map layout count mismatch");
        if (i < 3)
            require(strcmp(user->name, i == 1 ? "pass" : "password") == 0, "map key name hint lost");
        if (i == 3)
            require(strcmp(user->name, "explicit") == 0, "map hint overwrote explicit name");
        cJSON_Delete(json);
        usersDestroy(&users);
    }
    users_t malformed;
    require(usersCreate(&malformed), "malformed credential table creation failed");
    cJSON *bad = cJSON_Parse("{\"id\":1,\"password\":1,\"pass\":\"fallback-must-not-win\"}");
    require(bad != NULL && ! usersFeedJson(&malformed, bad) && usersCount(&malformed) == 0,
            "fallback credential bypassed malformed selected password");
    cJSON_Delete(bad);
    static const char *noop[] = {"null", "[]", "{}", "{\"users\":null}"};
    for (size_t i = 0; i < sizeof(noop) / sizeof(noop[0]); ++i)
    {
        cJSON *json = cJSON_Parse(noop[i]);
        require(json != NULL && usersFeedJson(&malformed, json) && usersCount(&malformed) == 0,
                "no-op import layout changed");
        cJSON_Delete(json);
    }
    usersDestroy(&malformed);
    for (unsigned kind = 0; kind < 6; ++kind)
    {
        cJSON *array = kind < 3 ? cJSON_CreateArray() : cJSON_CreateObject();
        for (unsigned i = 0; i < 4096; ++i)
        {
            cJSON  *entry = cJSON_CreateObject();
            discard cJSON_AddStringToObject(entry, "password", "repeated");
            if (kind % 3 == 2 && i == 0)
                discard cJSON_AddNumberToObject(entry, "wireguard-allowed-ips", 1);
            if (kind % 3 == 0 && i == 0)
                cJSON_ReplaceItemInObjectCaseSensitive(entry, "password", cJSON_CreateNumber(1));
            if (kind < 3)
                discard cJSON_AddItemToArray(array, entry);
            else
            {
                char key[32];
                snprintf(key, sizeof(key), "name-%u", i);
                discard cJSON_AddItemToObject(array, key, entry);
            }
        }
        users_t users;
        require(usersCreate(&users), "bounded import table creation failed");
        user_t *prior = addNamedAllowedIpUser(&users, 42, "prior", "prior", "10.2.0.0/24");
#if defined(USERS_TEST_ALLOC_COUNTING)
        allocationCountBegin();
#endif
        require(! usersFeedJson(&users, array), "invalid speculative tail imported");
#if defined(USERS_TEST_ALLOC_COUNTING)
        discard allocationCountEnd();
        require(g_alloc_bytes < 256U * 1024U, "invalid tail amplified speculative index allocation");
#endif
        require(users.slot_capacity <= 128 && users.capacity <= 128 && usersCount(&users) == 1 &&
                    usersLookupByIdentifier(&users, 42) == prior && usersValidate(&users),
                "invalid tail reserved excessive storage or broke rollback");
        usersDestroy(&users);
        cJSON_Delete(array);
    }
    users_t users;
    require(usersCreate(&users), "multi-block import table creation failed");
    cJSON *array = cJSON_CreateArray();
    for (unsigned i = 0; i < 193; ++i)
    {
        cJSON *entry = cJSON_CreateObject();
        char   password[32];
        snprintf(password, sizeof(password), "bulk-%u", i);
        discard cJSON_AddNumberToObject(entry, "id", i + 1);
        discard cJSON_AddStringToObject(entry, "password", password);
        discard cJSON_AddItemToArray(array, entry);
    }
    require(usersFeedJson(&users, array) && usersCount(&users) == 193 && usersValidate(&users),
            "bounded speculation prevented valid multi-block import");
    cJSON_Delete(array);
    usersDestroy(&users);
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

#if defined(WCRYPTO_TEST_LINKER_WRAP) && defined(USERS_TEST_CREDENTIAL_SNAPSHOT_WIPE_COUNTER)
/* The shared path derives once. Every backend refusal occurs before any
 * credential snapshot or mutation, while success wipes one retired snapshot. */
static void testChangePasswordPreparationFailureIsAtomic(void)
{
    users_t users;
    require(usersCreate(&users), "password preparation failure table failed");
    const char *old_uuid = "abcdef01-2345-6789-abcd-ef0123456789";
    addUser(&users, 1, old_uuid);
    user_t *target = usersLookupByIdentifier(&users, 1);
    for (unsigned stage = 0; stage < 3; ++stage)
    {
        resetCounters();
        if (stage == 0)
            g_sha224_fail_on_call = 1;
        if (stage == 1)
            g_sha256_fail_on_call = 1;
        if (stage == 2)
            g_x25519_fail_on_call = 1;
        users_test_credential_snapshot_wipes = 0;
        require(! usersChangePassword(&users, target, "proposed-new-password"), "failed password crypto committed");
        require(g_sha224_calls == 1 && g_sha256_calls == (stage >= 1) && g_x25519_calls == (stage >= 2),
                "password preparation repeated a primitive");
        require(users_test_credential_snapshot_wipes == 0, "preparation refusal captured retired credentials");
        resetCounters();
        require(usersLookupByPassword(&users, old_uuid) == target &&
                    usersLookupByUUID(&users, target->uuid_pass) == target &&
                    usersLookupByPassword(&users, "proposed-new-password") == NULL && usersValidate(&users),
                "crypto refusal changed credential state");
    }
    resetCounters();
    users_test_credential_snapshot_wipes = 0;
    require(usersChangePassword(&users, target, "proposed-new-password"), "prepared blocking change failed");
    require(g_sha224_calls == 1 && g_sha256_calls == 1 && g_x25519_calls == 1 &&
                users_test_credential_snapshot_wipes == 1,
            "blocking password change repeated crypto or missed snapshot wipe");
    require(usersValidate(&users), "shared blocking password commit corrupted indexes");
    usersDestroy(&users);
}
#endif

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
    user_t      *shaped = usersLookupByIdentifier(&src, 2);
    user_limit_t limits = shaped->limit;
    limits.bandwidth.u  = 100;
    require(usersSetUserLimit(&src, shaped, &limits), "copy bandwidth policy setup failed");
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
    require(dst2->runtime.bandwidth[kUserBandwidthUpload].policy_valid &&
                dst2->runtime.bandwidth[kUserBandwidthUpload].rate == 100,
            "copied user deferred initial bandwidth policy until first traffic");

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

#if defined(USERS_TEST_ALLOC_COUNTING)
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

    allocationCountBegin();
    bool   ok          = usersRemoveUser(&users, victim);
    size_t allocations = allocationCountEnd();

    require(ok, "removal failed");
    require(allocations == 0, "removal performed a heap allocation; the swap-with-last path is not allocation-free");
    require(usersValidate(&users), "database invalid after allocation-free removal");
    require(usersCount(&users) == 15, "removal did not shrink the table");

    usersDestroy(&users);
}

#endif

/* The seventeenth non-overlapping range grows the initially reserved tree. */
static void buildFullRangedFixture(users_t *users)
{
    require(usersCreate(users), "failed to create users table");
    for (uint64_t i = 0; i < 16; ++i)
    {
        char pw[40];
        char cidr[24];
        (void) snprintf(pw, sizeof(pw), "ranged-pw-%llu", (unsigned long long) i);
        (void) snprintf(cidr, sizeof(cidr), "10.0.%llu.0/24", (unsigned long long) i);
        addAllowedIpUser(users, i + 1U, pw, cidr);
    }
    require(usersValidate(users), "ranged fixture failed validation");
}

static void testUpdateGrowsAllowedIpIndex(void)
{
    users_t users;
    buildFullRangedFixture(&users);
    user_t *target = addNamedUser(&users, 100, "txn-old-pw", "txn-name-old");
    require(target != NULL && usersValidate(&users), "update fixture setup failed");

    user_update_t update = {.mask     = kUserUpdatePassword | kUserUpdateName | kUserUpdateWireGuardAllowedIps,
                            .password = "txn-new-pw",
                            .name     = "txn-name-new",
                            .wireguard_allowed_ips = "10.0.0.0/24"};
    require(! usersUpdateUser(&users, target, &update), "overlapping range update was accepted");
    require(usersValidate(&users), "rejected update corrupted the indexes");
    require(usersLookupByPassword(&users, "txn-old-pw") == target &&
                usersLookupByPassword(&users, "txn-new-pw") == NULL,
            "rejected update changed the password index");
    require(stringCompare(target->name, "txn-name-old") == 0 && ! target->wireguard_allowed_ips_valid,
            "rejected update changed the name or Allowed-IP state");

    update.wireguard_allowed_ips = "10.1.0.0/24";
    require(usersUpdateUser(&users, target, &update), "full-index update failed");
    require(usersValidate(&users), "committed update corrupted the indexes");
    require(usersLookupByPassword(&users, "txn-new-pw") == target &&
                usersLookupByPassword(&users, "txn-old-pw") == NULL,
            "committed update did not replace the password index");
    require(stringCompare(target->name, "txn-name-new") == 0, "committed update did not replace the name index");
    ip_addr_t probe = parseIp("10.1.0.9");
    require(usersLookupByWireGuardAllowedIp(&users, &probe) == target, "committed update did not index the new range");
    usersDestroy(&users);
}

static void testAddGrowsAllowedIpIndex(void)
{
    users_t users;
    buildFullRangedFixture(&users);
    const size_t base_count = usersCount(&users);

    user_t candidate;
    memoryZero(&candidate, sizeof(candidate));
    require(userCreate(&candidate, "txn-add-pw"), "failed to create add candidate");
    userSetId(&candidate, 100);
    require(userSetWireGuardAllowedIps(&candidate, "10.1.0.0/24"), "failed to set candidate range");
    require(usersAddUserChecked(&users, &candidate) == kUsersAddResultOk, "full-index add failed");
    userDestroy(&candidate);

    require(usersValidate(&users), "committed add corrupted the indexes");
    require(usersCount(&users) == base_count + 1, "committed add did not grow the table");
    user_t *added = usersLookupByPassword(&users, "txn-add-pw");
    require(added != NULL, "committed add is not resolvable");
    ip_addr_t probe = parseIp("10.1.0.9");
    require(usersLookupByWireGuardAllowedIp(&users, &probe) == added, "committed add did not index its range");
    usersDestroy(&users);
}

static void testRebuildLookups(void)
{
    users_t users;
    require(usersCreate(&users), "failed to create rebuild table");
    addNamedUser(&users, 1, "rebuild-one", "rebuild-name-one");
    addAllowedIpUser(&users, 2, "rebuild-two", "10.88.0.0/24");
    addUser(&users, 3, "rebuild-three");
    require(usersValidate(&users), "rebuild fixture invalid");

    require(usersRebuildLookups(&users), "lookup rebuild failed");
    require(usersValidate(&users), "lookup rebuild left partial indexes");
    require(usersCount(&users) == 3, "lookup rebuild changed the user count");
    require(usersLookupByPassword(&users, "rebuild-one") != NULL, "lookup rebuild lost password user one");
    require(usersLookupByPassword(&users, "rebuild-two") != NULL, "lookup rebuild lost password user two");
    require(usersLookupByIdentifier(&users, 3) != NULL, "lookup rebuild lost identifier user three");
    ip_addr_t probe = parseIp("10.88.0.55");
    require(usersLookupByWireGuardAllowedIp(&users, &probe) != NULL, "lookup rebuild lost Allowed-IP user");
    usersDestroy(&users);
}

static void testIndexGeometryRejection(void)
{
    require(userIndexHashCapacityIsRepresentable(0, 40, 2), "empty hash geometry was rejected");
    require(userIndexHashCapacityIsRepresentable(16, 40, 2), "initial hash geometry was rejected");
    require(! userIndexHashCapacityIsRepresentable(SIZE_MAX, 40, 2), "overflowing hash count was accepted");
    require(! userIndexHashCapacityIsRepresentable((size_t) PTRDIFF_MAX / 40U, 40, 2),
            "hash bucket rounding was omitted from the storage bound");

    size_t buckets, extent;
    require(userIndexHashGrowthGeometry(16, 0, 40, 2, &buckets, &extent) && buckets == 32 &&
                extent == 32U * 40U + 33U * 2U,
            "initial hash extent omitted value or metadata array");
    require(userIndexHashGrowthGeometry(25, 32, 40, 2, &buckets, &extent) && buckets == 32 && extent == 0,
            "hash geometry ignored STC's reserved-capacity early exit");
    require(userIndexHashGrowthGeometry(26, 32, 40, 2, &buckets, &extent) && buckets == 64 &&
                extent == 64U * 40U + 65U * 2U,
            "hash growth geometry charged net bytes or omitted bucket rounding");
    require(! userIndexHashGrowthGeometry(SIZE_MAX, 32, 40, 2, &buckets, &extent),
            "unrepresentable hash growth extent accepted");

    users_t users;
    require(usersCreate(&users), "failed to create capacity-refusal fixture");
    require(! usersReserve(&users, SIZE_MAX), "unrepresentable user storage was accepted");
    require(usersCount(&users) == 0 && usersValidate(&users), "capacity refusal changed the user database");
    usersDestroy(&users);
}

static void testConfigPatchIndexesAndOwnership(void)
{
    users_t users;
    buildFullRangedFixture(&users);
    user_t       *target  = addNamedUser(&users, 100, "patch-password", "patch-name");
    user_update_t initial = {.mask          = kUserUpdateTimeInfo | kUserUpdateStats | kUserUpdateLimit,
                             .timeinfo      = {11, 22, 33, 44},
                             .stats.traffic = {100, 200},
                             .limit         = {.traffic = {1, 2, 3}, .bandwidth = {4, 5}, .ips = 6}};
    require(usersUpdateUser(&users, target, &initial), "patch setup failed");
    user_ip_key_t key = testIpKey(192, 0, 2, 1);
    require(usersTryAdmitConnectionByIdentifier(&users, 100, &key, 0) == kUserAdmissionTrafficLimited,
            "setup limits were not active");
    user_config_patch_t patch = {.mask = kUserConfigName | kUserConfigWireGuardAllowedIps | kUserConfigTrafficTotal |
                                         kUserConfigExpireAfterFirstUsage,
                                 .name                        = "patch-new-name",
                                 .wireguard_allowed_ips       = "10.0.0.0/24",
                                 .limit.traffic.total         = 999,
                                 .expire_after_first_usage_ms = 888};
    require(usersPatchConfigByIdentifier(&users, 100, &patch) == kUsersUpdateResultDuplicateWireGuardAllowedIps,
            "overlapping patch was accepted");
    require(stringCompare(target->name, "patch-name") == 0 && target->limit.traffic.total == 3 &&
                target->timeinfo.expire_after_first_usage_ms == 44 && usersValidate(&users),
            "failed multi-field patch published values or indexes");
    patch.wireguard_allowed_ips = "10.1.0.0/24";
    require(usersPatchConfigByIdentifier(&users, 100, &patch) == kUsersUpdateResultOk,
            "patch failed to grow full Allowed-IP index");
    ip_addr_t address = parseIp("10.1.0.9");
    require(usersLookupByWireGuardAllowedIp(&users, &address) == target && usersValidate(&users),
            "patch did not commit its indexes");
    require(target->limit.traffic.u == 1 && target->limit.traffic.d == 2 && target->limit.traffic.total == 999 &&
                target->limit.bandwidth.u == 4 && target->limit.bandwidth.d == 5 && target->limit.ips == 6 &&
                target->timeinfo.created_at_ms == 11 && target->timeinfo.first_usage_at_ms == 22 &&
                target->timeinfo.expire_at_ms == 33 && target->timeinfo.expire_after_first_usage_ms == 888 &&
                target->stats.traffic.u == 100 && target->stats.traffic.d == 200,
            "leaf patch overwrote omitted configuration or accounting");
    patch.name                        = "";
    patch.wireguard_allowed_ips       = "";
    patch.limit.traffic.total         = 0;
    patch.expire_after_first_usage_ms = 0;
    require(usersPatchConfigByIdentifier(&users, 100, &patch) == kUsersUpdateResultOk &&
                ! target->wireguard_allowed_ips_valid && usersLookupByWireGuardAllowedIp(&users, &address) == NULL &&
                target->limit.traffic.total == 0 && target->timeinfo.expire_after_first_usage_ms == 0 &&
                usersValidate(&users),
            "explicit clears failed");
    usersDestroy(&users);
}

typedef struct patch_first_use_s
{
    users_t    *users;
    user_t     *user;
    atomic_bool go;
} patch_first_use_t;

static WTHREAD_ROUTINE(patchExpiryConcurrently)
{
    patch_first_use_t *context = userdata;
    while (! atomic_load(&context->go))
        wwSleepMS(1);
    user_config_patch_t patch = {.mask = kUserConfigExpireAt, .expire_at_ms = 999};
    for (unsigned i = 0; i < 1000; ++i)
        require(usersPatchConfigByIdentifier(context->users, 1, &patch) == kUsersUpdateResultOk,
                "concurrent expiry patch failed");
    return 0;
}

static WTHREAD_ROUTINE(markFirstUseConcurrently)
{
    patch_first_use_t *context = userdata;
    while (! atomic_load(&context->go))
        wwSleepMS(1);
    for (unsigned i = 0; i < 1000; ++i)
        userMarkFirstUsage(context->user, 777);
    return 0;
}

static void testConfigPatchFirstUseAndRuntime(void)
{
    users_t users;
    require(usersCreate(&users), "concurrent patch table failed");
    addUser(&users, 1, "patch-first-use");
    user_t       *user = usersLookupByIdentifier(&users, 1);
    user_ip_key_t key  = testIpKey(192, 0, 2, 1);
    require(usersTryAdmitConnectionByIdentifier(&users, 1, &key, 0) == kUserAdmissionOk, "runtime setup failed");
    patch_first_use_t context = {.users = &users, .user = user};
    atomic_init(&context.go, false);
    wthread_t threads[2];
    require(threadCreate(&threads[0], patchExpiryConcurrently, &context) == kWThreadErrorNone &&
                threadCreate(&threads[1], markFirstUseConcurrently, &context) == kWThreadErrorNone,
            "patch concurrency threads failed");
    atomic_store(&context.go, true);
    require(threadJoin(threads[0]) == 0 && threadJoin(threads[1]) == 0, "patch concurrency join failed");
    user_time_info_t time;
    userGetTimeInfo(user, &time);
    require(time.first_usage_at_ms == 777 && time.expire_at_ms == 999 && user->runtime.active_cons_out == 1 &&
                user->runtime.ip_usage_count == 1 && usersValidate(&users),
            "patch lost first usage or active reservations");
    usersReleaseConnectionByIdentifier(&users, 1, &key);
    require(user->runtime.active_cons_out == 0 && user->runtime.ip_usage_count == 0,
            "patched runtime reservation did not release");
    usersDestroy(&users);
}

/* Bounded configuration editing uses owned input and never waits behind an
 * acquired collection/configuration lock. Holder semaphores are the oracle. */
typedef struct config_lock_holder_s
{
    wrwlock_t  *lock;
    wsem_t      acquired, release;
    atomic_bool held;
    wthread_t   thread;
} config_lock_holder_t;

static WTHREAD_ROUTINE(configHoldWriter)
{
    config_lock_holder_t *holder = userdata;
    rwlockWriteLock(holder->lock);
    atomic_store(&holder->held, true);
    semaphorePost(&holder->acquired);
    require(semaphoreWait(&holder->release), "config writer release wait failed");
    atomic_store(&holder->held, false);
    rwlockWriteUnlock(holder->lock);
    return 0;
}

static void configHoldStart(config_lock_holder_t *holder, wrwlock_t *lock)
{
    memoryZero(holder, sizeof(*holder));
    holder->lock = lock;
    atomic_init(&holder->held, false);
    semaphoreInit(&holder->acquired, 0);
    semaphoreInit(&holder->release, 0);
    require(threadCreate(&holder->thread, configHoldWriter, holder) == kWThreadErrorNone,
            "config writer creation failed");
    require(semaphoreWait(&holder->acquired), "config writer acquisition failed");
}

static void configHoldFinish(config_lock_holder_t *holder)
{
    require(atomic_load(&holder->held), "config try-apply waited for lock release");
    semaphorePost(&holder->release);
    require(threadJoin(holder->thread) == 0, "config writer join failed");
    semaphoreDestroy(&holder->acquired);
    semaphoreDestroy(&holder->release);
}

static user_config_prepared_patch_t *prepareConfig(const user_config_patch_t *patch)
{
    user_config_prepared_patch_t *prepared = NULL;
    require(usersPrepareConfigPatch(patch, 64U * 1024U, 0, &prepared) == kUsersUpdateResultOk && prepared != NULL,
            "bounded preparation failed");
    require(usersPreparedConfigPatchOwnedBytes(prepared) <= usersPreparedConfigPatchPeakBytes(prepared) &&
                usersPreparedConfigPatchPeakBytes(prepared) <= 64U * 1024U,
            "prepared allocation accounting invalid");
    return prepared;
}

static bool configPrecommitRefuse(void *context)
{
    ++*(unsigned *) context;
    return false;
}

static void testPreparedConfigRefusalsAndLocks(void)
{
    users_t users;
    require(usersCreate(&users), "prepared config collection failed");
    user_t *target = addNamedAllowedIpUser(&users, 1, "prepared-secret", "before", "10.60.0.0/24");
    addNamedAllowedIpUser(&users, 2, "prepared-other", "occupied", "10.61.0.0/24");
    char                next_name[] = "after";
    user_config_patch_t patch = {.mask = kUserConfigName | kUserConfigWireGuardAllowedIps | kUserConfigTrafficTotal,
                                 .name = next_name,
                                 .wireguard_allowed_ips = "10.62.0.9/24",
                                 .limit.traffic.total   = 987};
    user_config_prepared_patch_t *prepared = prepareConfig(&patch);
    next_name[0]                           = 'X';
    size_t                        peak     = usersPreparedConfigPatchPeakBytes(prepared);
    user_config_prepared_patch_t *refused  = (void *) 1;
    require(usersPrepareConfigPatch(&patch, peak - 1U, 0, &refused) == kUsersUpdateResultResourceLimit &&
                refused == NULL,
            "preparation crossed allowance");
    require(usersPrepareConfigPatch(&patch, SIZE_MAX, 1, &refused) == kUsersUpdateResultTimeout && refused == NULL,
            "expired preparation accepted");
    unsigned callbacks = 0;
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, 0, 0, configPrecommitRefuse, &callbacks) ==
                    kUsersUpdateResultPrecommitRejected &&
                callbacks == 1,
            "precommit refusal committed values");
    require(stringCompare(target->name, "before") == 0 && target->limit.traffic.total == 0 && usersValidate(&users),
            "precommit refusal changed fields or indexes");
    require(usersTryApplyPreparedConfigByIdentifier(&users, 999, prepared, 0, 0, NULL, NULL) ==
                kUsersUpdateResultUserNotFound,
            "missing durable id accepted");
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, 0, 1, NULL, NULL) == kUsersUpdateResultTimeout,
            "expired precommit accepted");
    config_lock_holder_t holder;
    wrwlock_t           *locks[] = {&users.lock, &target->lock};
    for (size_t i = 0; i < 2; ++i)
    {
        configHoldStart(&holder, locks[i]);
        require(! rwlockTryWriteLock(locks[i]), "try-write acquired writer-held lock");
        require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, 0, 0, NULL, NULL) ==
                    kUsersUpdateResultBusy,
                "bounded config waited for writer-held lock");
        configHoldFinish(&holder);
        require(stringCompare(target->name, "before") == 0 && usersValidate(&users), "busy refusal changed indexes");
    }
    /* Configuration-only editing must remain independent of statistics locks. */
    configHoldStart(&holder, &target->stats_lock);
#if defined(USERS_TEST_ALLOC_COUNTING)
    allocationCountBegin();
#endif
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, 0, 0, NULL, NULL) == kUsersUpdateResultOk,
            "range-node reuse failed or config acquired stats lock");
#if defined(USERS_TEST_ALLOC_COUNTING)
    require(allocationCountEnd() == 0, "prepared range reuse or rename allocated during commit");
#endif
    configHoldFinish(&holder);
    require(prepared->consumed && prepared->patch.mask == 0 && prepared->update.mask == 0 &&
                prepared->patch.name == NULL && prepared->update.name == NULL &&
                prepared->patch.wireguard_allowed_ips == NULL && prepared->update.wireguard_allowed_ips == NULL &&
                prepared->name == NULL && prepared->allowed_ips.copy == NULL,
            "committed config preparation retained transferred aliases or masks");
    usersFreePreparedConfigPatch(prepared);
    require(stringCompare(target->name, "after") == 0 &&
                stringCompare(target->wireguard_allowed_ips, "10.62.0.0/24") == 0 &&
                target->limit.traffic.total == 987 && usersValidate(&users),
            "prepared normalized values were not committed");
    patch.name = "occupied";
    prepared   = prepareConfig(&patch);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                    kUsersUpdateResultDuplicateName &&
                stringCompare(target->name, "after") == 0 && usersValidate(&users),
            "duplicate prepared name was not atomic");
    usersFreePreparedConfigPatch(prepared);
    patch.name                  = "another";
    patch.wireguard_allowed_ips = "10.61.0.9/24";
    prepared                    = prepareConfig(&patch);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                    kUsersUpdateResultDuplicateWireGuardAllowedIps &&
                stringCompare(target->name, "after") == 0 && usersValidate(&users),
            "overlap prepared patch was not atomic");
    usersFreePreparedConfigPatch(prepared);
    patch.wireguard_allowed_ips = "invalid-range";
    require(usersPrepareConfigPatch(&patch, SIZE_MAX, 0, &refused) == kUsersUpdateResultInvalidWireGuardAllowedIps &&
                refused == NULL,
            "invalid range did not clean partial preparation");
    usersDestroy(&users);
}

static void testPreparedNameBoundsAndCapacity(void)
{
    users_t users;
    require(usersCreate(&users), "name-bound collection failed");
    for (uint64_t id = 1; id <= 65; ++id)
    {
        char password[48], name[48];
        snprintf(password, sizeof(password), "reserved-password-%" PRIu64, id);
        snprintf(name, sizeof(name), "reserved-name-%" PRIu64, id);
        user_t                       *target   = addNamedUser(&users, id, password, "");
        user_config_patch_t           patch    = {.mask = kUserConfigName, .name = name};
        user_config_prepared_patch_t *prepared = prepareConfig(&patch);
#if defined(USERS_TEST_ALLOC_COUNTING)
        allocationCountBegin();
#endif
        require(usersTryApplyPreparedConfigByIdentifier(&users, id, prepared, 0, 0, NULL, NULL) == kUsersUpdateResultOk,
                "unnamed-to-named at reserved boundary failed");
#if defined(USERS_TEST_ALLOC_COUNTING)
        require(allocationCountEnd() == 0, "bounded name insertion rehashed table");
#endif
        usersFreePreparedConfigPatch(prepared);
        patch.name = "";
        prepared   = prepareConfig(&patch);
#if defined(USERS_TEST_ALLOC_COUNTING)
        allocationCountBegin();
#endif
        require(usersTryApplyPreparedConfigByIdentifier(&users, id, prepared, 0, 0, NULL, NULL) == kUsersUpdateResultOk,
                "reserved name clear failed");
#if defined(USERS_TEST_ALLOC_COUNTING)
        require(allocationCountEnd() == 0, "bounded name clear allocated");
#endif
        usersFreePreparedConfigPatch(prepared);
        require(target->name[0] == '\0', "reserved clear not visible");
    }
    char *huge = memoryAllocate(32770U);
    memset(huge, 'x', 32769U);
    huge[32769U]   = '\0';
    user_t *target = usersLookupByIdentifier(&users, 1);
    require(usersSetUserName(&users, target, huge), "legacy long-name setup failed");
    memoryFree(huge);
    user_config_patch_t patch = {.mask = kUserConfigName | kUserConfigEnabled, .name = "short", .enabled = false};
    user_config_prepared_patch_t *prepared = prepareConfig(&patch);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, 0, 0, NULL, NULL) ==
                    kUsersUpdateResultResourceLimit &&
                target->enabled && stringLength(target->name) == 32769U,
            "long old name was scanned/edited outside inspection limit");
    usersFreePreparedConfigPatch(prepared);
    patch.mask = kUserConfigEnabled;
    prepared   = prepareConfig(&patch);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, 0, 0, NULL, NULL) == kUsersUpdateResultOk &&
                ! target->enabled,
            "non-name edit inspected unrelated huge stored name");
    usersFreePreparedConfigPatch(prepared);
    huge = memoryAllocate(32769U);
    memset(huge, 'x', 32768U);
    huge[32768U] = '\0';
    require(usersSetUserName(&users, target, huge), "maximum inspected name setup failed");
    memoryFree(huge);
    patch.mask = kUserConfigName;
    prepared   = prepareConfig(&patch);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 1, prepared, 0, 0, NULL, NULL) == kUsersUpdateResultOk &&
                stringCompare(target->name, "short") == 0,
            "exact old-name inspection allowance was refused");
    usersFreePreparedConfigPatch(prepared);
    require(usersValidate(&users), "bounded-name edits corrupted indexes");
    usersDestroy(&users);
}

static void testPreparedAllowedIpGrowthBounds(void)
{
    users_t users;
    buildFullRangedFixture(&users);
    user_t                       *target   = addNamedUser(&users, 100, "bounded-range", "range-before");
    user_config_patch_t           patch    = {.mask                  = kUserConfigName | kUserConfigWireGuardAllowedIps,
                                              .name                  = "range-after",
                                              .wireguard_allowed_ips = "10.90.0.0/24"};
    user_config_prepared_patch_t *prepared = prepareConfig(&patch);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 100, prepared, 0, 0, NULL, NULL) ==
                    kUsersUpdateResultResourceLimit &&
                stringCompare(target->name, "range-before") == 0 && ! target->wireguard_allowed_ips_valid &&
                usersValidate(&users),
            "range growth crossed remaining budget");
    unsigned callbacks = 0;
    require(usersTryApplyPreparedConfigByIdentifier(
                &users, 100, prepared, 1024U * 1024U, 0, configPrecommitRefuse, &callbacks) ==
                    kUsersUpdateResultPrecommitRejected &&
                callbacks == 1 && ! target->wireguard_allowed_ips_valid && usersValidate(&users),
            "private reserve refusal changed logical indexes");
    require(usersTryApplyPreparedConfigByIdentifier(&users, 100, prepared, 0, 0, NULL, NULL) == kUsersUpdateResultOk,
            "bounded reserved range insertion failed");
    usersFreePreparedConfigPatch(prepared);
    usersDestroy(&users);

    require(usersCreate(&users), "large range-bound collection failed");
    for (uint64_t id = 1; id <= 16384U; ++id)
    {
        char password[48], cidr[48];
        snprintf(password, sizeof(password), "range-capacity-%" PRIu64, id);
        snprintf(cidr,
                 sizeof(cidr),
                 "10.%u.%u.%u/32",
                 (unsigned) (id >> 16U),
                 (unsigned) ((id >> 8U) & 255U),
                 (unsigned) (id & 255U));
        addAllowedIpUser(&users, id, password, cidr);
    }
    target   = addNamedUser(&users, 20000, "large-growth-target", "large-before");
    prepared = prepareConfig(&patch);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 20000, prepared, SIZE_MAX, 0, NULL, NULL) ==
                    kUsersUpdateResultResourceLimit &&
                stringCompare(target->name, "large-before") == 0 && ! target->wireguard_allowed_ips_valid &&
                usersValidate(&users),
            "range edit exceeded hard one-MiB growth extent");
    usersFreePreparedConfigPatch(prepared);
    usersDestroy(&users);
}

static user_prepared_creation_t *prepareNew(uint64_t id, const char *password, const user_config_patch_t *config)
{
    user_prepared_creation_t *prepared = NULL;
    require(usersPrepareNewUser(id, password, config, 128U * 1024U, 0, &prepared) == kUsersAddResultOk && prepared,
            "fresh-account preparation failed");
    require(usersPreparedNewUserOwnedBytes(prepared) <= usersPreparedNewUserPeakBytes(prepared),
            "fresh-account accounting omitted retained storage");
    return prepared;
}

static bool createPrecommitCountAllocations(void *context)
{
    ++*(unsigned *) context;
#if defined(USERS_TEST_ALLOC_COUNTING)
    allocationCountBegin();
#endif
    return true;
}

static void testPreparedCreationDefaultsAndIndexes(void)
{
    users_t users;
    require(usersCreate(&users), "fresh-account table failed");
    user_prepared_creation_t *prepared  = prepareNew(UINT64_MAX, "new-default-password", NULL);
    const uint64_t            before    = getTimeOfDayMS();
    unsigned                  callbacks = 0;
    resetCounters();
    require(usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 0, createPrecommitCountAllocations, &callbacks) ==
                    kUsersAddResultOk &&
                callbacks == 1,
            "fresh-account insertion failed");
#if defined(USERS_TEST_ALLOC_COUNTING)
    require(allocationCountEnd() == 0, "reserved fresh-account publication allocated");
#endif
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    require(g_sha224_calls == 0 && g_sha256_calls == 0 && g_x25519_calls == 0,
            "creation repeated credential derivation under collection ownership");
#endif
    usersFreePreparedNewUser(prepared);
    user_t *user = usersLookupByIdentifier(&users, UINT64_MAX);
    require(user && ((uintptr_t) user % 32U == 0U) && user->enabled && user->gid == 0 &&
                user->record_stat_interval_ms == USER_DEFAULT_RECORD_STAT_INTERVAL_MS && user->name[0] == 0 &&
                user->email[0] == 0 && user->notes[0] == 0 && user->wireguard_allowed_ips[0] == 0 &&
                user->timeinfo.created_at_ms <= before && user->timeinfo.created_at_ms != 0 &&
                user->timeinfo.first_usage_at_ms == 0 && user->timeinfo.expire_at_ms == 0 &&
                user->stats.traffic.u == 0 && user->stats.traffic.d == 0 && user->runtime.active_cons_out == 0 &&
                user->runtime.ip_usage_count == 0 && ! user->client_time.clock_valid && ! user->uuid_pass_valid,
            "fresh-account defaults or alignment changed");
    require(usersLookupByPassword(&users, "new-default-password") == user &&
                usersLookupBySHA224(&users, user->sha224_pass.bytes) == user &&
                usersLookupBySHA256(&users, user->sha256_pass.bytes) == user &&
                usersLookupByWireGuardPublicKey(&users, user->wireguard_publickey) == user && usersValidate(&users),
            "fresh-account credential indexes incomplete");
    char name[] = "initial-name", email[] = "initial-email", notes[] = "initial-notes", range[] = "10.190.7.81/24";
    user_config_patch_t config = {
        .mask                    = (1U << 18U) - 1U,
        .name                    = name,
        .email                   = email,
        .notes                   = notes,
        .wireguard_allowed_ips   = range,
        .gid                     = UINT64_MAX,
        .enabled                 = false,
        .record_stat_interval_ms = INT_MAX,
        .limit = {.traffic = {1, 2, 3}, .bandwidth = {4, 5}, .ips = 6, .devices = 7, .cons_in = 8, .cons_out = 9},
        .expire_at_ms                = 10,
        .expire_after_first_usage_ms = 11};
    prepared = prepareNew(2, "00112233-4455-6677-8899-aabbccddeeff", &config);
    memoryZero(name, sizeof(name));
    memoryZero(email, sizeof(email));
    memoryZero(notes, sizeof(notes));
    memoryZero(range, sizeof(range));
    require(usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 0, NULL, NULL) == kUsersAddResultOk,
            "configured fresh-account insertion failed");
    usersFreePreparedNewUser(prepared);
    user_t   *configured = usersLookupByIdentifier(&users, 2);
    ip_addr_t address    = parseIp("10.190.7.250");
    require(configured && ! configured->enabled && configured->gid == UINT64_MAX &&
                configured->record_stat_interval_ms == INT_MAX &&
                stringCompare(configured->name, "initial-name") == 0 &&
                stringCompare(configured->email, "initial-email") == 0 &&
                stringCompare(configured->notes, "initial-notes") == 0 &&
                stringCompare(configured->wireguard_allowed_ips, "10.190.7.0/24") == 0 &&
                memoryCompare(&configured->limit, &config.limit, sizeof(config.limit)) == 0 &&
                configured->timeinfo.expire_at_ms == 10 && configured->timeinfo.expire_after_first_usage_ms == 11 &&
                configured->timeinfo.first_usage_at_ms == 0 && configured->uuid_pass_valid &&
                usersLookupByUUID(&users, configured->uuid_pass) == configured &&
                usersLookupByWireGuardAllowedIp(&users, &address) == configured &&
                usersLookupByIdentifier(&users, UINT64_MAX) == user && usersValidate(&users),
            "configured initial state, ownership, indexes or existing pointers changed");
    usersDestroy(&users);
}

static void testPreparedCreationRefusals(void)
{
    users_t users;
    require(usersCreate(&users), "creation-refusal table failed");
    user_t *existing =
        addNamedAllowedIpUser(&users, 1, "00112233-4455-6677-8899-aabbccddeeff", "occupied", "10.191.0.0/24");
    userAddTraffic(existing, 23, 41);
    user_config_patch_t       name     = {.mask = kUserConfigName, .name = "occupied"};
    user_prepared_creation_t *prepared = prepareNew(1, "00112233-4455-6677-8899-aabbccddeeff", &name);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultDuplicateId,
            "public fresh-account duplicate ID did not win");
    usersFreePreparedNewUser(prepared);
    user_t legacy;
    require(userCreate(&legacy, "00112233-4455-6677-8899-aabbccddeeff"), "legacy duplicate construction failed");
    userSetId(&legacy, 1);
    user_update_t update = {.mask = kUserUpdateName, .name = "occupied"};
    users_t       isolated;
    require(usersCreate(&isolated) && usersAddUser(&isolated, &legacy), "legacy-name setup failed");
    require(usersUpdateUser(&isolated, usersGetAt(&isolated, 0), &update), "legacy-name setup update failed");
    userDestroy(&legacy);
    require(userCopy(&legacy, usersGetAt(&isolated, 0)), "legacy duplicate copy failed");
    require(usersAddUserChecked(&users, &legacy) == kUsersAddResultDuplicateName,
            "legacy checked-add duplicate precedence changed");
    userDestroy(&legacy);
    usersDestroy(&isolated);
    prepared = prepareNew(2, "unique-created-password", &name);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultDuplicateName,
            "creation duplicate name accepted");
    usersFreePreparedNewUser(prepared);
    prepared = prepareNew(2, "00112233-4455-6677-8899-aabbccddeeff", NULL);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultDuplicateSHA224,
            "creation duplicate credential accepted");
    usersFreePreparedNewUser(prepared);
    prepared = prepareNew(2, "00112233-4455-6677-8899-AABBCCDDEEFF", NULL);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultDuplicateUUID,
            "different password spelling with duplicate UUID identity accepted");
    usersFreePreparedNewUser(prepared);
    user_config_patch_t overlap = {.mask = kUserConfigWireGuardAllowedIps, .wireguard_allowed_ips = "10.191.0.5/32"};
    prepared                    = prepareNew(2, "unique-created-password", &overlap);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) ==
                kUsersAddResultDuplicateWireGuardAllowedIps,
            "creation overlapping range accepted");
    usersFreePreparedNewUser(prepared);
    prepared = prepareNew(2, "unique-created-password", NULL);
    require(usersTryAddPreparedUser(&users, prepared, 0, 0, NULL, NULL) == kUsersAddResultResourceLimit,
            "creation skipped unpublished-slot aggregate charge");
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 1, NULL, NULL) == kUsersAddResultTimeout,
            "expired creation committed");
    config_lock_holder_t holder;
    configHoldStart(&holder, &users.lock);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultBusy,
            "creation waited for collection ownership");
    configHoldFinish(&holder);
    unsigned callbacks = 0;
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, configPrecommitRefuse, &callbacks) ==
                    kUsersAddResultPrecommitRejected &&
                callbacks == 1 && usersCount(&users) == 1 && usersValidate(&users),
            "precommit refusal published an account");
    /* No existing account lock is part of new-user publication. */
    configHoldStart(&holder, &existing->lock);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultOk,
            "creation acquired an existing account configuration lock");
    configHoldFinish(&holder);
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultDuplicateId,
            "repeated creation was treated as successful replay");
    usersFreePreparedNewUser(prepared);
    require(existing->stats.traffic.u == 23 && existing->stats.traffic.d == 41 && usersValidate(&users),
            "creation refusals changed existing usage");
    usersDestroy(&users);
}

static void testPreparedCreationGrowthAndNameWork(void)
{
    user_prepared_creation_t *prepared = prepareNew(1, "growth-created-password", NULL);
    size_t                    lower = 0, upper = 128U * 1024U;
    /* Fresh databases keep refusal capacity outside the next trial. */
    while (lower < upper)
    {
        size_t  budget = lower + (upper - lower) / 2U;
        users_t trial;
        require(usersCreate(&trial), "growth boundary table failed");
        unsigned           calls  = 0;
        users_add_result_t result = usersTryAddPreparedUser(&trial, prepared, budget, 0, configPrecommitRefuse, &calls);
        require(result == kUsersAddResultResourceLimit || result == kUsersAddResultPrecommitRejected,
                "growth admission returned unexpected result");
        require(usersCount(&trial) == 0 && trial.slot_count == 0 && usersValidate(&trial),
                "growth-boundary refusal consumed a stable slot");
        usersDestroy(&trial);
        if (result == kUsersAddResultResourceLimit)
            lower = budget + 1U;
        else
            upper = budget;
    }
    require(lower > sizeof(user_t) * 64U, "aggregate creation budget omitted capacity arrays or copy scratch");
    users_t users;
    require(usersCreate(&users), "exact growth table failed");
    require(usersTryAddPreparedUser(&users, prepared, lower - 1U, 0, NULL, NULL) == kUsersAddResultResourceLimit &&
                usersTryAddPreparedUser(&users, prepared, lower, 0, NULL, NULL) == kUsersAddResultOk,
            "exact aggregate creation budget boundary failed");
    usersFreePreparedNewUser(prepared);
    user_t *first = usersGetAt(&users, 0);
    /* Cross active pointers, block pointers, multiple fixed storage blocks,
     * complete hash extents and the Allowed-IP node array. */
    for (uint64_t id = 2; id <= 257; ++id)
    {
        char password[40], range[40];
        snprintf(password, sizeof(password), "growth-created-%" PRIu64, id);
        snprintf(range, sizeof(range), "10.192.%u.%u/32", (unsigned) (id / 256U), (unsigned) (id % 256U));
        user_config_patch_t initial = {.mask = kUserConfigWireGuardAllowedIps, .wireguard_allowed_ips = range};
        prepared                    = prepareNew(id, password, &initial);
        require(usersTryAddPreparedUser(&users, prepared, 256U * 1024U, 0, NULL, NULL) == kUsersAddResultOk,
                "multi-structure creation growth failed");
        usersFreePreparedNewUser(prepared);
    }
    require(usersLookupByIdentifier(&users, 1) == first && usersValidate(&users),
            "creation growth moved published accounts");
    user_config_patch_t           rename = {.mask = kUserConfigName, .name = "named-after-unnamed-growth"};
    user_config_prepared_patch_t *patch  = prepareConfig(&rename);
    require(usersTryApplyPreparedConfigByIdentifier(&users, 65, patch, 0, 0, NULL, NULL) == kUsersUpdateResultOk,
            "unnamed creations failed to reserve later name insertion");
    usersFreePreparedConfigPatch(patch);
    usersDestroy(&users);
    require(usersCreate(&users), "name-work table failed");
    char *huge = memoryAllocate(256U * 1024U + 1U);
    memset(huge, 'n', 256U * 1024U);
    huge[256U * 1024U] = 0;
    addNamedUser(&users, 1, "name-work-large", huge);
    memoryFree(huge);
    for (uint64_t id = 2; id <= 24; ++id)
    {
        char password[40];
        snprintf(password, sizeof(password), "name-work-%" PRIu64, id);
        addUser(&users, id, password);
    }
    prepared = prepareNew(25, "name-work-spare", NULL);
    require(usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 0, NULL, NULL) == kUsersAddResultOk,
            "spare name capacity unnecessarily scanned legacy names");
    usersFreePreparedNewUser(prepared);
    prepared = prepareNew(26, "name-work-needs-rehash", NULL);
    require(usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 0, NULL, NULL) == kUsersAddResultResourceLimit &&
                usersCount(&users) == 25 && usersValidate(&users),
            "name rehash escaped cumulative stored-name work bound");
    require(usersTryAddPreparedUser(&users, prepared, 512U * 1024U, 0, NULL, NULL) == kUsersAddResultOk,
            "admitted cumulative name rehash failed");
    usersFreePreparedNewUser(prepared);
    usersDestroy(&users);
}

#if defined(WCRYPTO_TEST_LINKER_WRAP) && defined(USERS_TEST_ALLOC_COUNTING)
static bool creationExpireAtPrecommit(void *context)
{
    ++*(unsigned *) context;
    g_creation_clock_expire_at = g_creation_clock_reads + 1U;
    return true;
}

static void creationClockStart(unsigned expire_at)
{
    g_creation_clock_us        = UINT64_C(1000000);
    g_creation_clock_reads     = 0;
    g_creation_clock_expire_at = expire_at;
}

static void creationClockStop(void)
{
    g_creation_clock_us        = 0;
    g_creation_clock_expire_at = 0;
}

static void testPreparedCreationDeadlines(void)
{
    users_t users;
    require(usersCreate(&users), "deadline creation table failed");
    user_prepared_creation_t *prepared  = prepareNew(1, "deadline-created-password", NULL);
    unsigned                  callbacks = 0;
    /* Entry, pre-items reserve, then post-items reserve. The new pointer
     * extent remains private, while no stable slot has even been reserved. */
    creationClockStart(3);
    users_add_result_t result =
        usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 1500, createPrecommitCountAllocations, &callbacks);
    creationClockStop();
    require(result == kUsersAddResultTimeout && callbacks == 0 && g_creation_clock_reads == 3 && users.capacity == 64 &&
                users.slot_capacity == 0 && usersCount(&users) == 0 && users.slot_count == 0 && usersValidate(&users),
            "post-reserve expiry published data or skipped admitted private growth");
    /* Every reserve and the initialized unpublished-slot copy has completed.
     * The callback advances only the next clock read, the final commit check. */
    creationClockStart(0);
    result = usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 1500, creationExpireAtPrecommit, &callbacks);
    creationClockStop();
    require(result == kUsersAddResultTimeout && callbacks == 1 && usersCount(&users) == 0 && users.slot_count == 0 &&
                users.slot_capacity == 64 && usersValidate(&users),
            "immediate precommit expiry retained an unpublished account or slot");
    require(usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 0, NULL, NULL) == kUsersAddResultOk &&
                usersCount(&users) == 1 && users.slot_count == 1 && usersValidate(&users),
            "deadline-refused unpublished slot was not reusable");
    usersFreePreparedNewUser(prepared);
    usersDestroy(&users);

    require(usersCreate(&users), "name-scan deadline table failed");
    char *name = memoryAllocate(4097);
    memset(name, 'n', 4096);
    name[4096] = '\0';
    addNamedUser(&users, 1, "deadline-long-name", name);
    memoryFree(name);
    for (uint64_t id = 2; id <= 25; ++id)
    {
        char password[40];
        snprintf(password, sizeof(password), "deadline-name-%" PRIu64, id);
        addUser(&users, id, password);
    }
    prepared  = prepareNew(26, "deadline-name-growth", NULL);
    callbacks = 0;
    /* Entry, first metadata bucket, then the first 1024-byte name chunk.
     * Name growth is mandatory at 26 active users with the initial 32 buckets. */
    creationClockStart(3);
    allocationCountBegin();
    result = usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 1500, createPrecommitCountAllocations, &callbacks);
    size_t allocations = allocationCountEnd();
    creationClockStop();
    require(result == kUsersAddResultTimeout && g_creation_clock_reads == 3 && allocations == 0 && callbacks == 0 &&
                usersCount(&users) == 25 && users.slot_count == 25 && usersValidate(&users),
            "stored-name chunk expiry did not refuse before rehash or changed active data");
    require(usersTryAddPreparedUser(&users, prepared, 128U * 1024U, 0, NULL, NULL) == kUsersAddResultOk &&
                usersValidate(&users),
            "name-scan timeout prevented a later admitted creation");
    usersFreePreparedNewUser(prepared);
    usersDestroy(&users);
}
#endif

static void testPreparedCreationFailureCleanup(void)
{
    user_prepared_creation_t *prepared = (void *) 1;
    require(usersPrepareNewUser(0, "valid", NULL, SIZE_MAX, 0, &prepared) == kUsersAddResultInvalidArgument &&
                ! prepared,
            "zero fresh account ID accepted");
    require(usersPrepareNewUser(1, "", NULL, SIZE_MAX, 0, &prepared) == kUsersAddResultInvalidArgument && ! prepared,
            "empty fresh account password accepted");
    require(usersPrepareNewUser(1, "valid", NULL, SIZE_MAX, 1, &prepared) == kUsersAddResultTimeout && ! prepared,
            "expired fresh preparation accepted");
    prepared    = prepareNew(1, "prepare-boundary", NULL);
    size_t peak = usersPreparedNewUserPeakBytes(prepared);
    usersFreePreparedNewUser(prepared);
    require(usersPrepareNewUser(1, "prepare-boundary", NULL, peak - 1U, 0, &prepared) == kUsersAddResultResourceLimit &&
                ! prepared && usersPrepareNewUser(1, "prepare-boundary", NULL, peak, 0, &prepared) == kUsersAddResultOk,
            "fresh preparation peak admission boundary incorrect");
    usersFreePreparedNewUser(prepared);
#if defined(WW_SYNC_INIT_TEST_SEAM)
    size_t resources = atomic_load(&g_native_resources);
    for (size_t stage = 1; stage <= 2; ++stage)
    {
        atomic_store(&g_native_init_failure, atomic_load(&g_native_init_calls) + stage);
        require(usersPrepareNewUser(1, "native-failed", NULL, SIZE_MAX, 0, &prepared) ==
                        kUsersAddResultCreationFailed &&
                    ! prepared && atomic_load(&g_native_resources) == resources,
                "private native-init failure leaked resources");
        atomic_store(&g_native_init_failure, 0);
    }
    users_t users;
    require(usersCreate(&users), "native failure table failed");
    prepared  = prepareNew(1, "native-slot-failed", NULL);
    resources = atomic_load(&g_native_resources);
    for (size_t stage = 1; stage <= 2; ++stage)
    {
        atomic_store(&g_native_init_failure, atomic_load(&g_native_init_calls) + stage);
        require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultCreationFailed &&
                    usersCount(&users) == 0 && users.slot_count == 0 && atomic_load(&g_native_resources) == resources &&
                    usersValidate(&users),
                "unpublished native-init failure leaked or consumed a slot");
        atomic_store(&g_native_init_failure, 0);
    }
    require(usersTryAddPreparedUser(&users, prepared, SIZE_MAX, 0, NULL, NULL) == kUsersAddResultOk,
            "private reserved capacity was not reusable after native refusal");
    usersFreePreparedNewUser(prepared);
    usersDestroy(&users);
#endif
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    for (unsigned stage = 0; stage < 3; ++stage)
    {
        resetCounters();
        if (stage == 0)
            g_sha224_fail_on_call = 1;
        if (stage == 1)
            g_sha256_fail_on_call = 1;
        if (stage == 2)
            g_x25519_fail_on_call = 1;
        require(usersPrepareNewUser(1, "crypto-failed", NULL, SIZE_MAX, 0, &prepared) ==
                        kUsersAddResultCreationFailed &&
                    ! prepared,
                "private crypto failure misclassified or retained a candidate");
    }
    resetCounters();
#endif
}

static user_prepared_password_change_t *preparePassword(const char *password)
{
    user_prepared_password_change_t *prepared = NULL;
    require(usersPreparePasswordChange(password, SIZE_MAX, 0, &prepared) == kUsersPasswordOk && prepared != NULL,
            "password preparation failed");
    require(usersPreparedPasswordChangeOwnedBytes(prepared) <= usersPreparedPasswordChangePeakBytes(prepared),
            "password preparation omitted retained storage");
    return prepared;
}

static void commitPasswordAndCheck(users_t *users, user_t *target, const char *password)
{
    sha224_hash_t old224 = target->sha224_pass;
    sha256_hash_t old256 = target->sha256_pass;
    uint8_t       old_uuid[kWwUuidBytesLen], old_wg[USER_WIREGUARD_PUBLICKEY_SIZE];
    bool          old_uuid_valid = target->uuid_pass_valid;
    memoryCopy(old_uuid, target->uuid_pass, sizeof(old_uuid));
    memoryCopy(old_wg, target->wireguard_publickey, sizeof(old_wg));
    resetCounters();
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    g_password_derivation_users = users;
    g_password_derivation_user  = target;
#endif
    user_prepared_password_change_t *prepared = preparePassword(password);
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    g_password_derivation_users = NULL;
    g_password_derivation_user  = NULL;
    require(g_sha224_calls == 1 && g_sha256_calls == 1 && g_x25519_calls == 1,
            "password preparation did not derive each primitive once");
#endif
    resetCounters();
#if defined(USERS_TEST_ALLOC_COUNTING)
    size_t wipes        = g_secret_wipes;
    g_secret_free_watch = target->password;
    g_secret_free_bytes = stringLength(target->password) + 1U;
    allocationCountBegin();
#endif
    require(usersTryChangePreparedPasswordByIdentifier(
                users, target->id, prepared, usersPreparedPasswordChangeCommitBytes(prepared), 0, NULL, NULL) ==
                kUsersPasswordOk,
            "prepared password commit failed");
#if defined(USERS_TEST_ALLOC_COUNTING)
    require(allocationCountEnd() == 0, "password replacement allocated or grew an index");
    require(g_secret_wipes == wipes + 1U && g_secret_free_watch == NULL, "retired plaintext was not wiped");
#endif
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    require(g_sha224_calls == 0 && g_sha256_calls == 0 && g_x25519_calls == 0,
            "password commit repeated crypto under shared ownership");
#endif
    usersFreePreparedPasswordChange(prepared);
    require(userPasswordMatches(target, password) && usersLookupByPassword(users, password) == target &&
                usersLookupBySHA224(users, target->sha224_pass.bytes) == target &&
                usersLookupBySHA256(users, target->sha256_pass.bytes) == target &&
                usersLookupByWireGuardPublicKey(users, target->wireguard_publickey) == target &&
                usersLookupByIdentifier(users, target->id) == target,
            "password replacement lost a new credential or the durable ID");
    if (memoryCompare(old224.bytes, target->sha224_pass.bytes, sizeof(old224.bytes)) != 0)
        require(usersLookupBySHA224(users, old224.bytes) == NULL, "changed old SHA-224 still resolves");
    if (memoryCompare(old256.bytes, target->sha256_pass.bytes, sizeof(old256.bytes)) != 0)
        require(usersLookupBySHA256(users, old256.bytes) == NULL, "changed old SHA-256 still resolves");
    if (memoryCompare(old_wg, target->wireguard_publickey, sizeof(old_wg)) != 0)
        require(usersLookupByWireGuardPublicKey(users, old_wg) == NULL,
                "changed old WireGuard identity still resolves");
    if (old_uuid_valid &&
        (! target->uuid_pass_valid || memoryCompare(old_uuid, target->uuid_pass, sizeof(old_uuid)) != 0))
        require(usersLookupByUUID(users, old_uuid) == NULL, "removed old UUID still resolves");
    if (target->uuid_pass_valid)
        require(usersLookupByUUID(users, target->uuid_pass) == target, "new UUID identity does not resolve");
    memorySecureZero(&old224, sizeof(old224));
    memorySecureZero(&old256, sizeof(old256));
    memorySecureZero(old_uuid, sizeof(old_uuid));
    require(usersValidate(users), "prepared password commit corrupted the collection");
}

static void testPreparedPasswordSemanticsAndPreservation(void)
{
    users_t users;
    require(usersCreate(&users), "password preservation table failed");
    user_t *target = addNamedAllowedIpUser(&users, 1, "password-old", "password-name", "10.210.0.0/24");
    addUser(&users, 2, "password-unrelated");
    user_ip_key_t key = testIpKey(192, 0, 2, 101);
    require(usersTryAdmitConnectionByIdentifier(&users, 1, &key, 1000) == kUserAdmissionOk,
            "password preservation admission failed");
    userAddTraffic(target, 123, 456);
    userAddSpeed(target, 12, 34);
    userSetIpCount(target, 9);
    userSetDeviceCount(target, 8);
    userSetEnabled(target, false);
    target->timeinfo.created_at_ms               = 700;
    target->timeinfo.first_usage_at_ms           = 800;
    target->timeinfo.expire_at_ms                = 900;
    target->timeinfo.expire_after_first_usage_ms = 100;
    target->limit.traffic.total                  = 1;
    target->client_time.accounting_anchor_ms     = 111;
    target->client_time.first_report_ms          = 222;
    target->client_time.observed                 = true;
    target->client_view_expiry_valid             = true;
    target->client_view_expires_at_ms            = 333;
    const user_stat_t         stats              = target->stats;
    const user_time_info_t    timeinfo           = target->timeinfo;
    const user_limit_t        limit              = target->limit;
    const user_runtime_stat_t runtime            = target->runtime;
    const user_client_time_t  client_time        = target->client_time;
    char *name = target->name, *email = target->email, *notes = target->notes, *range = target->wireguard_allowed_ips;
    const size_t count = users.count, slots = users.slot_count, capacity = users.capacity;
    user_t     **items = users.items, **blocks = users.blocks;
    void        *id_table = users.id_table, *pointer_table = users.pointer_table, *name_table = users.name_table;
    void        *allowed_table = users.allowed_ip_table;
    commitPasswordAndCheck(&users, target, "  exact-\xc3\xa9-password\t ");
    require(! userPasswordMatches(target, "password-old"), "different old plaintext still matches");
    commitPasswordAndCheck(&users, target, "abcdef01-2345-6789-abcd-ef0123456789");
    commitPasswordAndCheck(&users, target, "ABCDEF01-2345-6789-ABCD-EF0123456789");
    commitPasswordAndCheck(&users, target, "00112233-4455-6677-8899-aabbccddeeff");
    commitPasswordAndCheck(&users, target, "final-plain-password");
    commitPasswordAndCheck(&users, target, "final-plain-password");
    require(! target->enabled && target->name == name && target->email == email && target->notes == notes &&
                target->wireguard_allowed_ips == range && memoryEqual(&target->stats, &stats, sizeof(stats)) &&
                memoryEqual(&target->timeinfo, &timeinfo, sizeof(timeinfo)) &&
                memoryEqual(&target->limit, &limit, sizeof(limit)) &&
                memoryEqual(&target->runtime, &runtime, sizeof(runtime)) &&
                memoryEqual(&target->client_time, &client_time, sizeof(client_time)) &&
                target->client_view_expiry_valid && target->client_view_expires_at_ms == 333 && users.count == count &&
                users.slot_count == slots && users.capacity == capacity && users.items == items &&
                users.blocks == blocks && users.id_table == id_table && users.pointer_table == pointer_table &&
                users.name_table == name_table && users.allowed_ip_table == allowed_table,
            "password mutation changed noncredential state");
    ip_addr_t address = parseIp("10.210.0.99");
    require(usersLookupByWireGuardAllowedIp(&users, &address) == target, "password change lost Allowed-IP index");
    usersReleaseConnectionByIdentifier(&users, 1, &key);
    require(target->runtime.active_cons_out == 0 && target->runtime.ip_usage_count == 0,
            "password rotation lost the active reservation");
    usersDestroy(&users);
}

static void testPreparedPasswordRefusalsAndBounds(void)
{
    users_t users;
    require(usersCreate(&users), "password refusal table failed");
    addUser(&users, 1, "password-before-refusal");
    user_t                          *target    = usersLookupByIdentifier(&users, 1);
    char                             desired[] = "owned-password-after-refusal";
    user_prepared_password_change_t *prepared = preparePassword(desired), *refused = (void *) 1;
    size_t                           peak = usersPreparedPasswordChangePeakBytes(prepared);
    require(usersPreparePasswordChange(desired, peak - 1U, 0, &refused) == kUsersPasswordResourceLimit &&
                refused == NULL,
            "password preparation crossed exact allowance");
    require(usersPreparePasswordChange(desired, peak, 0, &refused) == kUsersPasswordOk && refused != NULL,
            "password preparation refused exact allowance");
    usersFreePreparedPasswordChange(refused);
    desired[0]         = 'X';
    unsigned callbacks = 0;
    require(usersTryChangePreparedPasswordByIdentifier(
                &users, 1, prepared, usersPreparedPasswordChangeCommitBytes(prepared) - 1U, 0, NULL, NULL) ==
                kUsersPasswordResourceLimit,
            "password commit crossed scratch allowance");
    require(usersTryChangePreparedPasswordByIdentifier(&users, 999, prepared, SIZE_MAX, 0, NULL, NULL) ==
                kUsersPasswordNotFound,
            "password commit accepted missing ID");
    require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 1, NULL, NULL) ==
                kUsersPasswordTimeout,
            "expired password commit succeeded");
    require(usersTryChangePreparedPasswordByIdentifier(
                &users, 1, prepared, SIZE_MAX, 0, configPrecommitRefuse, &callbacks) ==
                    kUsersPasswordPrecommitRejected &&
                callbacks == 1,
            "password precommit refusal mutated");
    config_lock_holder_t holder;
    wrwlock_t           *locks[] = {&users.lock, &target->lock};
    for (size_t i = 0; i < 2; ++i)
    {
        configHoldStart(&holder, locks[i]);
        require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                    kUsersPasswordBusy,
                "password mutation waited for a held lock");
        configHoldFinish(&holder);
    }
    require(userPasswordMatches(target, "password-before-refusal") && usersValidate(&users),
            "password refusal changed published state");
    configHoldStart(&holder, &target->stats_lock);
    require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                kUsersPasswordOk,
            "credentials-only transaction acquired stats lock");
    configHoldFinish(&holder);
    usersFreePreparedPasswordChange(prepared);
    require(userPasswordMatches(target, "owned-password-after-refusal"), "prepared password borrowed request bytes");

    /* Deliberately supply a full UUID map at its initial capacity boundary.
     * Refusal must precede erasure of any old credential membership. */
    users_t empty;
    require(usersCreate(&empty), "password capacity refusal fixture failed");
    for (uint64_t id = 1; id <= 25; ++id)
    {
        char uuid_password[64];
        snprintf(uuid_password, sizeof(uuid_password), "%08" PRIx64 "-2345-6789-abcd-ef0123456789", id);
        addUser(&empty, id, uuid_password);
    }
    prepared                          = preparePassword("00112233-4455-6677-8899-aabbccddeeff");
    users_uuid_table_t *reserved_uuid = users.uuid_table;
    users.uuid_table                  = empty.uuid_table;
    require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                kUsersPasswordResourceLimit,
            "password replacement grew an unreserved UUID map");
    users.uuid_table = reserved_uuid;
    usersFreePreparedPasswordChange(prepared);
    usersDestroy(&empty);
    require(userPasswordMatches(target, "owned-password-after-refusal") && usersValidate(&users),
            "reserved-capacity refusal changed credentials or indexes");

    char *huge = memoryAllocate(32770U);
    memset(huge, 'p', 32769U);
    huge[32769U] = '\0';
    require(usersChangePassword(&users, target, huge), "legacy imported large password refused");
    prepared = preparePassword("after-imported-password");
    require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                    kUsersPasswordResourceLimit &&
                userPasswordMatches(target, huge) && usersValidate(&users),
            "oversized old password was inspected or mutated");
    huge[32768U] = '\0';
    require(usersChangePassword(&users, target, huge), "legacy exact password bound setup failed");
    /* Unrelated imported strings must never be inspected by this path. */
    huge[32768U] = 'p';
    require(usersSetUserName(&users, target, huge) && usersSetUserNotes(&users, target, huge),
            "unrelated large text setup failed");
    require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                    kUsersPasswordOk &&
                userPasswordMatches(target, "after-imported-password") && usersValidate(&users),
            "exact old password bound refused or unrelated text scanned");
    usersFreePreparedPasswordChange(prepared);
    huge[32768U] = '\0';
    require(usersPreparePasswordChange(huge, SIZE_MAX, 0, &prepared) == kUsersPasswordOk,
            "maximum prepared password was refused");
    usersFreePreparedPasswordChange(prepared);
    huge[32768U] = 'p';
    require(usersPreparePasswordChange(huge, SIZE_MAX, 0, &prepared) == kUsersPasswordResourceLimit && prepared == NULL,
            "oversized prepared password was accepted");
    memorySecureZero(huge, 32770U);
    memoryFree(huge);
    usersDestroy(&users);
}

static void testPreparedPasswordDuplicatesAndCleanup(void)
{
    users_t users;
    require(usersCreate(&users), "password duplicate table failed");
    addUser(&users, 1, "password-duplicate-target");
    addUser(&users, 2, "abcdef01-2345-6789-abcd-ef0123456789");
    user_t *target = usersLookupByIdentifier(&users, 1), *other = usersLookupByIdentifier(&users, 2);
    for (unsigned kind = 0; kind < 5; ++kind)
    {
#if defined(WCRYPTO_TEST_LINKER_WRAP)
        if (kind == 2)
        {
            g_force_sha224_enabled = true;
            memoryCopy(g_force_sha224_value, other->sha224_pass.bytes, SHA224_DIGEST_SIZE);
        }
        if (kind == 3)
        {
            g_force_sha256_enabled = true;
            memoryCopy(g_force_sha256_value, other->sha256_pass.bytes, SHA256_DIGEST_SIZE);
            /* Keep WireGuard owned by the target so this refusal specifically
             * reaches the otherwise masked SHA-256 collision check. */
            g_force_wireguard_enabled = true;
            memoryCopy(g_force_wireguard_value, target->wireguard_publickey, USER_WIREGUARD_PUBLICKEY_SIZE);
        }
        if (kind == 4)
        {
            g_force_wireguard_enabled = true;
            memoryCopy(g_force_wireguard_value, other->wireguard_publickey, USER_WIREGUARD_PUBLICKEY_SIZE);
        }
#else
        if (kind >= 2)
            continue;
#endif
        user_prepared_password_change_t *prepared =
            preparePassword(kind == 0   ? other->password
                            : kind == 1 ? "ABCDEF01-2345-6789-ABCD-EF0123456789"
                                        : "forced-distinct-credential-collision");
#if defined(WCRYPTO_TEST_LINKER_WRAP)
        g_force_sha224_enabled = g_force_sha256_enabled = g_force_wireguard_enabled = false;
#endif
        require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                    kUsersPasswordCredentialsExist,
                "credential duplicate class was accepted");
        usersFreePreparedPasswordChange(prepared);
        require(userPasswordMatches(target, "password-duplicate-target") &&
                    usersLookupByPassword(&users, other->password) == other && usersValidate(&users),
                "duplicate password refusal changed an account");
    }
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    for (unsigned stage = 0; stage < 3; ++stage)
    {
        resetCounters();
        if (stage == 0)
            g_sha224_fail_on_call = 1;
        if (stage == 1)
            g_sha256_fail_on_call = 1;
        if (stage == 2)
            g_x25519_fail_on_call = 1;
#if defined(USERS_TEST_ALLOC_COUNTING)
        size_t wipes           = g_secret_wipes;
        g_secret_capture_bytes = sizeof("password-private-failed-preparation");
#endif
        user_prepared_password_change_t *prepared = (void *) 1;
        require(usersPreparePasswordChange("password-private-failed-preparation", SIZE_MAX, 0, &prepared) ==
                        kUsersPasswordPreparationFailed &&
                    prepared == NULL,
                "password backend failure retained preparation");
#if defined(USERS_TEST_ALLOC_COUNTING)
        require(g_secret_capture_bytes == 0 && g_secret_free_watch == NULL && g_secret_wipes == wipes + 1U,
                "failed prepared plaintext was not wiped");
#endif
    }
    resetCounters();
#endif
#if defined(USERS_TEST_ALLOC_COUNTING)
    size_t wipes                              = g_secret_wipes;
    g_secret_capture_bytes                    = sizeof("password-owned-refused-preparation");
    user_prepared_password_change_t *prepared = preparePassword("password-owned-refused-preparation");
    unsigned                         calls    = 0;
    require(usersTryChangePreparedPasswordByIdentifier(
                &users, 1, prepared, SIZE_MAX, 0, configPrecommitRefuse, &calls) == kUsersPasswordPrecommitRejected,
            "secret cleanup precommit refusal failed");
    usersFreePreparedPasswordChange(prepared);
    require(g_secret_capture_bytes == 0 && g_secret_free_watch == NULL && g_secret_wipes == wipes + 1U,
            "refused owned password was not wiped");
#endif
    usersDestroy(&users);
}

static void testPreparedPasswordReservedUuidCapacity(void)
{
    users_t users, copy, loaded;
    require(usersCreate(&users) && usersCreate(&copy) && usersCreate(&loaded), "password UUID boundary table failed");
    for (uint64_t id = 1; id <= 65; ++id)
    {
        char password[64];
        snprintf(password, sizeof(password), "uuid-reserved-plain-%" PRIu64, id);
        addUser(&users, id, password);
    }
    require(usersCopy(&copy, &users), "password UUID boundary native copy failed");
    cJSON *json = usersToJson(&users);
    require(json != NULL, "password UUID boundary serialization failed");
    require(usersFeedJson(&loaded, json), "password UUID boundary JSON feed failed");
    cJSON_Delete(json);
    users_t *tables[] = {&users, &copy, &loaded};
    for (size_t table = 0; table < 3; ++table)
        for (uint64_t id = 1; id <= 65; ++id)
        {
            char password[64];
            snprintf(password, sizeof(password), "%08" PRIx64 "-2345-6789-abcd-ef0123456789", id);
            user_prepared_password_change_t *prepared = preparePassword(password);
#if defined(USERS_TEST_ALLOC_COUNTING)
            allocationCountBegin();
#endif
            require(usersTryChangePreparedPasswordByIdentifier(tables[table], id, prepared, SIZE_MAX, 0, NULL, NULL) ==
                        kUsersPasswordOk,
                    "plain-to-UUID exceeded reserved credential capacity");
#if defined(USERS_TEST_ALLOC_COUNTING)
            require(allocationCountEnd() == 0, "plain-to-UUID rehashed after add/feed/copy");
#endif
            usersFreePreparedPasswordChange(prepared);
        }
    require(usersValidate(&users) && usersValidate(&copy) && usersValidate(&loaded),
            "UUID boundary rotation corrupted indexes");
    usersDestroy(&loaded);
    usersDestroy(&copy);
    usersDestroy(&users);
}

#if defined(WCRYPTO_TEST_LINKER_WRAP)
static bool passwordExpireAfterAck(void *context)
{
    ++*(unsigned *) context;
    g_creation_clock_expire_at = g_creation_clock_reads + 1U;
    return true;
}

static void testPreparedPasswordDeadlines(void)
{
    users_t users;
    require(usersCreate(&users), "password deadline table failed");
    char *long_password = memoryAllocate(32769U);
    memset(long_password, 'd', 32768U);
    long_password[32768U] = '\0';
    addUser(&users, 1, long_password);
    user_t                          *target   = usersLookupByIdentifier(&users, 1);
    user_prepared_password_change_t *prepared = preparePassword("password-after-deadline");
    for (unsigned stage = 0; stage < 2; ++stage)
    {
        unsigned callbacks         = 0;
        g_creation_clock_us        = UINT64_C(1000000);
        g_creation_clock_reads     = 0;
        g_creation_clock_expire_at = stage == 0 ? 3U : 0U;
        require(usersTryChangePreparedPasswordByIdentifier(
                    &users, 1, prepared, SIZE_MAX, 1500, passwordExpireAfterAck, &callbacks) == kUsersPasswordTimeout &&
                    callbacks == stage,
                "password deadline crossed bounded scan or final commit boundary");
        g_creation_clock_us        = 0;
        g_creation_clock_expire_at = 0;
        require(userPasswordMatches(target, long_password) && usersValidate(&users),
                "password deadline changed published credentials");
    }
    require(usersTryChangePreparedPasswordByIdentifier(&users, 1, prepared, SIZE_MAX, 0, NULL, NULL) ==
                kUsersPasswordOk,
            "deadline-refused preparation could not be reused");
    usersFreePreparedPasswordChange(prepared);
    memorySecureZero(long_password, 32769U);
    memoryFree(long_password);
    usersDestroy(&users);
}
#endif

static void testTrustedImportDerivationAndBoundedRows(void)
{
    users_t users, copied;
    require(usersCreate(&users) && usersCreate(&copied), "trusted import setup");
    cJSON *json = cJSON_Parse("[{\"id\":1,\"password\":\"trusted-first\",\"notes\":\"quote \\\" and \\n line\"},"
                              "{\"id\":2,\"password\":\"trusted-second\",\"wireguard-allowed-ips\":\"10.3.4.5/24\"}]");
    require(json != NULL, "trusted import JSON");
    /* Fresh import derives credentials once; trusted copies preserve them and
     * cached export charges, while explicit diagnostics still recompute. */
    resetCounters();
    require(usersFeedJsonRequiredIds(&users, json) && usersValidateStructure(&users), "trusted import failed");
    cJSON_Delete(json);
    require(usersCopy(&copied, &users), "trusted copy failed");
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    require(g_sha224_calls == 2 && g_sha256_calls == 2 && g_x25519_calls == 2,
            "import or trusted baseline copy rederived credentials");
#endif
    user_t *target = usersGetAt(&copied, 0);
    target->sha224_pass.bytes[0] ^= 1U;
    require(! usersValidate(&copied) && ! userPasswordDataValid(target), "full diagnostic accepted corrupt derivation");
    target->sha224_pass.bytes[0] ^= 1U;
    cJSON *row     = NULL;
    size_t encoded = 0;
    require(usersCopyFullUserJsonAt(&users, 0, SIZE_MAX, &row, &encoded) == kUserPublicOk, "bounded row export");
    char *printed = cJSON_PrintUnformatted(row);
    require(stringLength(printed) == encoded, "bounded row size disagrees with JSON escaping");
    cJSON_free(printed);
    cJSON_Delete(row);
    row          = NULL;
    size_t exact = encoded;
    require(usersCopyFullUserJsonAt(&users, 0, exact - 1U, &row, &encoded) == kUserPublicTooLarge && row == NULL &&
                encoded == 0,
            "bounded row crossed exact encoded allowance");
    require(usersCopyFullUserJsonAt(&users, 0, exact, &row, &encoded) == kUserPublicOk && encoded == exact,
            "bounded row refused exact allowance");
    cJSON_Delete(row);
    row = NULL;
    require(usersCopyFullUserJsonAt(&users, 2, SIZE_MAX, &row, &encoded) == kUserPublicOutOfRange && row == NULL &&
                encoded == 0,
            "bounded row end detection");
    target            = usersGetAt(&users, 0);
    char *saved_notes = target->notes;
    target->notes     = memoryAllocate(1024U * 1024U);
    memset(target->notes, 'x', 1024U * 1024U - 1U);
    target->notes[1024U * 1024U - 1U] = '\0';
#if defined(USERS_TEST_ALLOC_COUNTING)
    allocationCountBegin();
#endif
    require(usersCopyFullUserJsonAt(&users, 0, 256, &row, &encoded) == kUserPublicTooLarge && row == NULL,
            "oversized row was not refused before copying arbitrary strings");
#if defined(USERS_TEST_ALLOC_COUNTING)
    discard allocationCountEnd();
    require(g_alloc_bytes < 32768U, "bounded row allocated a copy of oversized notes");
#endif
    memoryFree(target->notes);
    char invalid_notes[] = "invalid-\xc0\xaf";
    target->notes        = invalid_notes;
    require(usersCopyFullUserJsonAt(&users, 0, 4096, &row, &encoded) == kUserPublicInvalidEncoding && row == NULL &&
                encoded == 0,
            "bounded row accepted malformed UTF-8");
    target->notes = saved_notes;
    json          = cJSON_Parse("{\"id\":3,\"password\":\"checked-import\",\"wireguard-allowed-ips\":\"10.5.6.9/24\"}");
    resetCounters();
    require(usersAddUserFromJsonChecked(&users, json) == kUsersAddResultOk, "trusted checked JSON add");
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    require(g_sha224_calls == 1 && g_sha256_calls == 1 && g_x25519_calls == 1,
            "fresh checked JSON add rederived credentials");
#endif
    cJSON_Delete(json);
    json = cJSON_Parse("[{\"id\":4,\"password\":\"append-page\"},{\"password\":\"missing-id\"}]");
    require(! usersFeedJsonRequiredIds(&users, json) && usersCount(&users) == 3 && usersValidateStructure(&users),
            "required-ID late-row refusal did not roll back just-appended rows");
    cJSON_Delete(json);
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    json = cJSON_Parse("{\"id\":5,\"password\":\"backend-refused-import\"}");
    resetCounters();
    g_sha256_fail_on_call = 1;
    require(! usersFeedJsonRequiredIds(&users, json) && usersCount(&users) == 3 && usersValidateStructure(&users),
            "crypto failure published an imported account");
    cJSON_Delete(json);
    resetCounters();
    /* A failed SHA must reject before a later derived-key comparison can happen
     * to match. The zero scalar reproduces that old false-positive diagnostic. */
    uint8_t saved_key[USER_WIREGUARD_PUBLICKEY_SIZE];
    memoryCopy(saved_key, target->wireguard_publickey, sizeof(saved_key));
    const uint8_t zero_scalar[USER_WIREGUARD_PUBLICKEY_SIZE] = {0};
    const uint8_t basepoint[USER_WIREGUARD_PUBLICKEY_SIZE]   = {9};
    require(__real_wCryptoX25519(target->wireguard_publickey, zero_scalar, basepoint) == kWCryptoOk,
            "diagnostic crypto refusal fixture");
    g_sha224_fail_on_call = 1;
    require(! userPasswordDataValid(target), "full diagnostic accepted a failed SHA backend");
    memoryCopy(target->wireguard_publickey, saved_key, sizeof(saved_key));
    memoryZero(saved_key, sizeof(saved_key));
    resetCounters();
#endif
    usersDestroy(&copied);
    usersDestroy(&users);
}

#if defined(OS_LINUX) && defined(USERS_TEST_ALLOC_COUNTING)
static bool    g_expect_corruption_abort;
_Noreturn void __real_abortProgramNow(int exit_code);
_Noreturn void __wrap_abortProgramNow(int exit_code);
_Noreturn void __wrap_abortProgramNow(int exit_code)
{
    if (g_expect_corruption_abort)
        _Exit(exit_code == 1 && g_alloc_calls == 0 ? 72 : 73);
    __real_abortProgramNow(exit_code);
}

static void testCorruptionIsFatalWithoutRepair(void)
{
    users_t users;
    require(usersCreate(&users), "fatal corruption setup");
    user_t                  *target      = addNamedUser(&users, 1, "fatal-old", "fatal-name");
    user_prepared_password_t replacement = {0};
    require(userPreparePassword(&replacement, "fatal-new", 9), "fatal password preparation");
    for (unsigned kind = 0; kind < 4; ++kind)
    {
        pid_t pid = fork();
        require(pid >= 0, "fork corruption child");
        if (pid == 0)
        {
            if (kind == 0)
                users.sha224_table = NULL;
            else if (kind == 1)
                users.sha224_table->map.size = 0;
            else if (kind == 2)
                users.name_table->map.size = users_name_map_t_capacity(&users.name_table->map);
            else
                users_sha224_map_t_clear(&users.sha224_table->map);
            g_expect_corruption_abort = true;
            allocationCountBegin();
            if (kind < 2)
                discard usersPasswordPreflightLocked(&users, target, &replacement);
            else if (kind == 2)
                discard usersNameTableInsertReservedLocked(&users, target);
            else
                discard usersRemoveUser(&users, target);
            _Exit(74);
        }
        int status = 0;
        require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 72,
                "corruption was recoverable or allocated/repaired before fatal exit");
    }
    userFreePreparedPassword(&replacement);
    usersDestroy(&users);
}
#endif

static void testPointerIndexAlignedKeys(void)
{
    /* Aligned block addresses share low bits. The old default integer hash
     * placed these in one cluster beyond STC's 10-bit probe-distance field. */
    users_pointer_map_t map   = {0};
    const size_t        count = 2048;
    require(users_pointer_map_t_reserve(&map, (isize) count), "aligned pointer map reserve failed");
    for (size_t i = 0; i < count; ++i)
    {
        uintptr_t key = (uintptr_t) (i + 1U) * UINT32_C(65536);
        require(users_pointer_map_t_insert_or_assign(&map, key, i).inserted,
                "aligned pointer key was misclassified as a duplicate");
    }
    for (size_t i = 0; i < count; ++i)
    {
        uintptr_t                key   = (uintptr_t) (i + 1U) * UINT32_C(65536);
        users_pointer_map_t_iter found = users_pointer_map_t_find(&map, key);
        require(found.ref != NULL && found.ref->second == i, "aligned pointer index lost a stored key");
    }
    users_pointer_map_t_drop(&map);
}

static void testExportLimitedTransactions(void)
{
    users_t users;
    require(usersCreate(&users), "export policy collection setup failed");
    const size_t notes_length = 6U * 1024U * 1024U;
    char        *notes        = memoryAllocate(notes_length + 1U);
    memset(notes, 'a', notes_length);
    notes[notes_length]              = '\0';
    user_config_patch_t       config = {.mask  = kUserConfigName | kUserConfigNotes | kUserConfigWireGuardAllowedIps,
                                        .name  = "export \"name",
                                        .notes = notes,
                                        .wireguard_allowed_ips = "10.70.5.255/24"};
    user_prepared_creation_t *creation;
    require(usersPrepareNewUser(500, "export-password", &config, SIZE_MAX, 0, &creation) == kUsersAddResultOk,
            "large valid export candidate preparation failed");
    memoryFree(notes);
    size_t allowance;
    require(userMeasureExportUpperBound(&creation->user, &allowance) == kUserPublicOk && allowance > notes_length,
            "large export candidate measurement failed");
    size_t callbacks = 0;
    require(usersTryAddPreparedUserWithExportLimit(
                &users, creation, SIZE_MAX, 0, 0, configPrecommitRefuse, &callbacks) == kUsersAddResultTooLarge &&
                usersCount(&users) == 0 && callbacks == 0,
            "zero export allowance was treated as unlimited");
    require(usersTryAddPreparedUserWithExportLimit(
                &users, creation, SIZE_MAX, allowance - 1U, 0, configPrecommitRefuse, &callbacks) ==
                    kUsersAddResultTooLarge &&
                usersCount(&users) == 0 && callbacks == 0,
            "one-byte-over candidate reached publication/precommit");
    require(usersTryAddPreparedUserWithExportLimit(&users, creation, SIZE_MAX, allowance, 0, NULL, NULL) ==
                kUsersAddResultOk,
            "exact export allowance refused valid six-MiB record");
    usersFreePreparedNewUser(creation);
    user_t *stored = usersLookupByIdentifier(&users, 500);
    require(stored != NULL && strcmp(stored->wireguard_allowed_ips, "10.70.5.0/24") == 0 &&
                stored->export_strings.notes.escaped_bytes == notes_length,
            "prepared creation lost normalized/cached fields");
    user_config_patch_t           patch = {.mask = kUserConfigEmail, .email = "x"};
    user_config_prepared_patch_t *prepared;
    require(usersPrepareConfigPatch(&patch, SIZE_MAX, 0, &prepared) == kUsersUpdateResultOk,
            "export patch preparation failed");
    require(usersTryApplyPreparedConfigByIdentifierWithExportLimit(
                &users, 500, prepared, SIZE_MAX, allowance, 0, configPrecommitRefuse, &callbacks) ==
                    kUsersUpdateResultTooLarge &&
                callbacks == 0 && stored->email[0] == '\0',
            "oversize patch mutated old fields or reached precommit");
    require(usersPatchConfigByIdentifierWithExportLimit(&users, 500, &patch, allowance) == kUsersUpdateResultTooLarge &&
                stored->email[0] == '\0',
            "blocking producer patch bypassed export policy");
    require(usersTryApplyPreparedConfigByIdentifierWithExportLimit(
                &users, 500, prepared, SIZE_MAX, allowance + 1U, 0, NULL, NULL) == kUsersUpdateResultOk &&
                stored->export_strings.email.escaped_bytes == 1,
            "refused patch was consumed or exact replacement charge lost");
    usersFreePreparedConfigPatch(prepared);
    patch.email = "";
    require(usersPatchConfigByIdentifier(&users, 500, &patch) == kUsersUpdateResultOk,
            "legacy unlimited patch wrapper failed");

    user_prepared_password_change_t *password;
    require(usersPreparePasswordChange("export-passwordX", SIZE_MAX, 0, &password) == kUsersPasswordOk,
            "export password preparation failed");
    require(usersTryChangePreparedPasswordByIdentifierWithExportLimit(
                &users, 500, password, SIZE_MAX, allowance, 0, configPrecommitRefuse, &callbacks) ==
                    kUsersPasswordTooLarge &&
                callbacks == 0 && usersLookupByPassword(&users, "export-password") == stored &&
                usersLookupByPassword(&users, "export-passwordX") == NULL,
            "oversize password changed credential indexes or reached precommit");

    /* Inaccessible interior pages prove that scalar edits and password checks
     * never rescan unchanged large text. This is a read-work assertion, without
     * a timing threshold or production instrumentation. */
#if defined(OS_LINUX)
    size_t    page_size       = (size_t) sysconf(_SC_PAGESIZE);
    uintptr_t protected_begin = ((uintptr_t) stored->notes + page_size - 1U) / page_size * page_size;
    void     *protected_text  = (void *) protected_begin;
    require(mprotect(protected_text, page_size * 2U, PROT_NONE) == 0, "large-text protection failed");
#endif
    patch = (user_config_patch_t) {.mask = kUserConfigEnabled, .enabled = false};
    require(usersPatchConfigByIdentifierWithExportLimit(&users, 500, &patch, allowance) == kUsersUpdateResultOk,
            "scalar-only patch read unchanged large text");
    size_t unchanged;
    require(userMeasureExportUpperBound(stored, &unchanged) == kUserPublicOk && unchanged == allowance,
            "scalar edit changed reserved export size");
    require(usersTryChangePreparedPasswordByIdentifierWithExportLimit(
                &users, 500, password, SIZE_MAX, allowance + 1U, 0, NULL, NULL) == kUsersPasswordOk,
            "password policy scanned unchanged large text");
#if defined(OS_LINUX)
    require(mprotect(protected_text, page_size * 2U, PROT_READ | PROT_WRITE) == 0,
            "large-text protection restoration failed");
#endif
    usersFreePreparedPasswordChange(password);
    require(usersLookupByPassword(&users, "export-password") == NULL &&
                usersLookupByPassword(&users, "export-passwordX") == stored,
            "accepted password did not publish indexes");
    allowance += 1U;
    userAddTraffic(stored, UINT64_MAX, UINT64_MAX);
    userMarkFirstUsage(stored, UINT64_MAX);
    require(userMeasureExportUpperBound(stored, &unchanged) == kUserPublicOk && unchanged == allowance,
            "traffic/first-use numeric growth changed the admission charge");
    cJSON *row = NULL;
    size_t exact;
    require(usersCopyFullUserJsonAt(&users, 0, allowance, &row, &exact) == kUserPublicOk && exact <= allowance,
            "admitted row stopped exporting after numeric growth");
    cJSON_Delete(row);
    users_t copied;
    require(usersCreate(&copied) && usersCopy(&copied, &users), "measured collection copy failed");
    require(userMeasureExportUpperBound(usersLookupByIdentifier(&copied, 500), &unchanged) == kUserPublicOk &&
                unchanged == allowance && usersValidate(&copied),
            "collection snapshot lost cached metadata");
    usersDestroy(&copied);
    require(usersValidate(&users), "export refusals corrupted lookup indexes");
    usersDestroy(&users);
}

static void testShiftedIdsAndCollidingNames(void)
{
    users_t users;
    require(usersCreate(&users), "shifted-ID collection setup failed");
    uint64_t candidate = 0;
    for (uint64_t i = 1; i <= 1100; ++i)
    {
        char             name[48], password[48];
        users_name_key_t key = {.name = name};
        do
            snprintf(name, sizeof(name), "collision-name-%" PRIu64, ++candidate);
        while ((usersNameKeyHash(&key) & 4095U) != 2030U);
        snprintf(password, sizeof(password), "shifted-ID-password-%" PRIu64, i);
        addNamedUser(&users, i << 12U, password, name);
    }
    for (uint64_t i = 1; i <= 1100; ++i)
    {
        user_t *found = usersLookupByIdentifier(&users, i << 12U);
        require(found != NULL && usersFindByNameLocked(&users, found->name, NULL) == found,
                "shifted ID or colliding name vanished");
    }
    cJSON *duplicate = cJSON_Parse("{\"id\":4194304,\"password\":\"duplicate-shifted-ID\"}");
    require(usersAddUserFromJsonChecked(&users, duplicate) == kUsersAddResultDuplicateId &&
                usersCount(&users) == 1100 && usersValidateStructure(&users),
            "lost shifted ID allowed duplicate insertion or corrupted collection");
    cJSON_Delete(duplicate);
    for (uint64_t i = 1100; i != 0; --i)
    {
        user_t *found = usersLookupByIdentifier(&users, i << 12U);
        require(found != NULL && usersRemoveUser(&users, found), "colliding collection removal failed");
    }
    require(usersCount(&users) == 0 && usersValidateStructure(&users), "colliding collection did not drain");
    usersDestroy(&users);
}

static void testCollidingIpChurn(void)
{
    enum
    {
        count = 1100
    };
    user_ip_key_t *keys      = memoryAllocate(count * sizeof(*keys));
    uint64_t       candidate = 0;
    for (size_t i = 0; i < count; ++i)
    {
        user_ip_key_t key = {.type = 6};
        uint8_t       encoded[1U + sizeof(key.bytes)];
        /* A single IPv6 /64 supplies all candidates. Use the same byte layout
         * as the production hash without exposing a hash-replacement seam. */
        key.bytes[0] = 0x20;
        key.bytes[1] = 0x01;
        key.bytes[2] = 0x0d;
        key.bytes[3] = 0xb8;
        do
        {
            ++candidate;
            memoryCopy(key.bytes + 8, &candidate, sizeof(candidate));
            encoded[0] = key.type;
            memoryCopy(encoded + 1, key.bytes, sizeof(key.bytes));
        } while ((userIndexHashBytes(encoded, sizeof(encoded)) & 4095U) != 2030U);
        keys[i] = key;
    }
    user_t user = {0};
    require(userCreate(&user, "colliding-active-ip-password"), "colliding IP user setup failed");
    for (unsigned round = 0; round < 4; ++round)
    {
        for (unsigned pass = 0; pass < 2; ++pass)
            for (size_t i = 0; i < count; ++i)
                require(userTryAdmitConnection(&user, &keys[i], 1000) == kUserAdmissionOk,
                        "colliding IP admission failed");
        require(user.runtime.ip_usage_count == count, "colliding live IP acquired a duplicate reservation");
        for (unsigned pass = 0; pass < 2; ++pass)
            for (size_t i = count; i != 0; --i)
                userReleaseConnection(&user, &keys[i - 1U]);
        require(user.runtime.ip_usage_count == 0 && user.runtime.active_cons_out == 0 && user.runtime.ip_index == NULL,
                "reverse release retained phantom active IPs");
    }
    userDestroy(&user);
    memoryFree(keys);
}

static void testImportDiagnostics(void)
{
    const char *inputs[] = {
        "[false]",
        "[{\"password\":\"missing-ID\"}]",
        "[{\"id\":4,\"password\":\"one\"},{\"id\":4,\"password\":\"two\"}]",
        "[{\"id\":7,\"password\":\"one\",\"name\":\"same\"},{\"id\":8,\"password\":\"two\",\"name\":\"same\"}]",
        "{\"users\":false}"};
    const char    *reasons[]   = {"invalid account object",
                                  "missing or invalid required durable id",
                                  "duplicate durable id",
                                  "duplicate username",
                                  "invalid accounts container"};
    const size_t   positions[] = {0, 0, 1, 1, SIZE_MAX};
    const uint64_t ids[]       = {0, 0, 4, 8, 0};
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
    {
        users_t users;
        require(usersCreate(&users), "diagnostic collection setup failed");
        cJSON                  *json = cJSON_Parse(inputs[i]);
        users_json_diagnostic_t diagnostic;
        require(usersFeedJsonRequiredIdsResultDetailed(&users, json, &diagnostic) == kUsersJsonInvalid &&
                    diagnostic.entry_index == positions[i] && diagnostic.id == ids[i] &&
                    strcmp(diagnostic.reason, reasons[i]) == 0 && usersCount(&users) == 0,
                "import diagnostic lost safe reason, identity, position or rollback");
        cJSON_Delete(json);
        usersDestroy(&users);
    }
    users_t users;
    require(usersCreate(&users), "resource diagnostic setup failed");
    cJSON *json = cJSON_Parse("{\"id\":9,\"password\":\"native-refusal\"}");
#if defined(WW_SYNC_INIT_TEST_SEAM)
    atomic_store(&g_native_init_failure, atomic_load(&g_native_init_calls) + 1U);
    require(usersAddUserFromJsonChecked(&users, json) == kUsersAddResultStorageUnavailable,
            "checked JSON add reported native refusal as invalid user");
    atomic_store(&g_native_init_failure, 0);
#endif
    users_json_diagnostic_t diagnostic;
    require(usersFeedJsonRequiredIdsResultDetailed(&users, json, &diagnostic) == kUsersJsonOk &&
                diagnostic.reason == NULL && diagnostic.entry_index == SIZE_MAX && diagnostic.id == 0,
            "successful import retained a failure diagnostic");
    cJSON_Delete(json);
    usersDestroy(&users);
}

static void testCredentialIndexWiping(void)
{
    users_t users;
    require(usersCreate(&users), "credential index wipe setup failed");
    addUser(&users, 1, "credential-storage-one");
    addUser(&users, 2, "credential-storage-two");
#if defined(USERS_TEST_ALLOC_COUNTING)
    size_t wipes        = g_secret_wipes;
    g_secret_free_watch = users.sha224_table->map.table;
    g_secret_free_bytes = (size_t) users.sha224_table->map.bucket_count * sizeof(*users.sha224_table->map.table);
    require(usersSHA224TableReserve(users.sha224_table, 4096), "credential rehash failed");
    require(g_secret_wipes == wipes + 1U, "credential rehash did not wipe retired array");
#endif
    user_t *first = usersLookupByIdentifier(&users, 1);
    require(first != NULL, "credential wipe account disappeared");
    users_sha224_key_t      key   = usersSHA224KeyFromBytes(first->sha224_pass.bytes);
    users_sha224_map_t_iter entry = users_sha224_map_t_find(&users.sha224_table->map, key);
    require(entry.ref != NULL, "credential wipe index entry disappeared");
    size_t hole = (size_t) (entry.ref - users.sha224_table->map.table);
    require(first != NULL && usersRemoveUser(&users, first), "credential wipe removal failed");
    while (users.sha224_table->map.meta[hole].dist != 0)
        hole = (hole + 1U) & ((size_t) users.sha224_table->map.bucket_count - 1U);
    const uint8_t *erased = (const uint8_t *) &users.sha224_table->map.table[hole];
    for (size_t i = 0; i < sizeof(*users.sha224_table->map.table); ++i)
        require(erased[i] == 0, "erasure retained an inactive credential copy");
    require(usersClear(&users), "credential wipe clear failed");
    const uint8_t *bytes  = (const uint8_t *) users.sha224_table->map.table;
    size_t         length = (size_t) users.sha224_table->map.bucket_count * sizeof(*users.sha224_table->map.table);
    for (size_t i = 0; i < length; ++i)
        require(bytes[i] == 0, "clear retained credential index bytes");
    usersDestroy(&users);
}

int main(void)
{
    testCaseSet("users_index_test");
    require(userTestRuntimeInitialize(), "crypto global initialization failed");
    const uint64_t first_seed = userIndexHashSeed();
    require(first_seed != 0 && userIndexHashSeed() == first_seed,
            "process hash seed changed or truncated after first initialization");

    testSaturatedHashDistances();
    testShiftedIdsAndCollidingNames();
    testCollidingIpChurn();
    testImportDiagnostics();
    testCredentialIndexWiping();

    testTrustedImportDerivationAndBoundedRows();
    testPointerIndexAlignedKeys();
    testExportLimitedTransactions();
#if defined(OS_LINUX) && defined(USERS_TEST_ALLOC_COUNTING)
    testCorruptionIsFatalWithoutRepair();
#endif
    testNameIndex();
    testPointerIndexAndRemoval();
    testStrictAllowedIps();
    testImportLayoutsAndReservation();
    testAllowedIpIndex();
    testValidationAtScaleAndCorruption();
    testIncrementalPasswordChange();
#if defined(WCRYPTO_TEST_LINKER_WRAP) && defined(USERS_TEST_CREDENTIAL_SNAPSHOT_WIPE_COUNTER)
    testChangePasswordPreparationFailureIsAtomic();
#endif
    testPreparedPasswordSemanticsAndPreservation();
    testPreparedPasswordRefusalsAndBounds();
    testPreparedPasswordDuplicatesAndCleanup();
    testPreparedPasswordReservedUuidCapacity();
#if defined(WCRYPTO_TEST_LINKER_WRAP)
    testPreparedPasswordDeadlines();
#endif
    testNativeCopy();
    testLegacyInsertionOwnershipAndRefusals();
    testZeroCountIndexesStayEmpty();
    testAdaptiveIpIndex();
    testPasswordHitSingleHash();
    testPasswordMissSingleHash();
    testExactVerificationDerivesNoHash();
    testCollisionFailsClosed();
    testRuntimeStateSelfMove();
#if defined(USERS_TEST_ALLOC_COUNTING)
    testRemovalIsAllocationFree();
#endif
    testUpdateGrowsAllowedIpIndex();
    testAddGrowsAllowedIpIndex();
    testRebuildLookups();
    testIndexGeometryRejection();
    testConfigPatchIndexesAndOwnership();
    testConfigPatchFirstUseAndRuntime();
    testPreparedConfigRefusalsAndLocks();
    testPreparedNameBoundsAndCapacity();
    testPreparedAllowedIpGrowthBounds();
    testPreparedCreationDefaultsAndIndexes();
    testPreparedCreationRefusals();
    testPreparedCreationGrowthAndNameWork();
    testPreparedCreationFailureCleanup();
#if defined(WCRYPTO_TEST_LINKER_WRAP) && defined(USERS_TEST_ALLOC_COUNTING)
    testPreparedCreationDeadlines();
#endif

#if defined(WW_SYNC_INIT_TEST_SEAM)
    require(atomic_load(&g_native_resources) == 0, "users index fixture leaked native resources");
#endif
    printf("users_index_test: all checks passed\n");
    userTestRuntimeCleanup();
    return 0;
}
