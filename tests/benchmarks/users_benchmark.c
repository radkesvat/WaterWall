/*
 * Non-gating micro-benchmark for the users_t data structure.
 *
 * This target is intentionally EXCLUDE_FROM_ALL and is never registered as a
 * CTest pass/fail case: it reports nanoseconds-per-operation so a human can
 * compare scaling ratios across machines and across the phases of the
 * users/performance work. It deliberately performs no logging inside timed
 * loops, pre-generates every input string outside them, and uses the same
 * cryptographic backend as the configured preset.
 *
 * Build (from the repository root):
 *
 *   cmake --preset linux
 *   cmake --build --preset linux --target users_benchmark
 *   ./build/linux/tests/benchmarks/Release/users_benchmark [N ...]
 *
 * With no arguments it runs a modest default set of user counts. Pass explicit
 * counts (e.g. `users_benchmark 1000 10000 100000`) to reproduce the plan's
 * baseline sizes.
 *
 * Reported operations (each should scale flat per-op with N now that the feed,
 * validation, and mutation paths are linear / incremental):
 *
 *   construct       bulk add of N users
 *   feed_json       bulk JSON feed of N users into a fresh table
 *   validate        one full usersValidate() sweep (per-user cost)
 *   password_hit    plaintext lookup that resolves
 *   password_miss   plaintext lookup that misses
 *   native_copy     usersCopy() deep copy (per source user)
 *   password_change usersChangePassword() incremental reindex
 *   remove          usersRemoveUser() swap-with-last + incremental erase
 *   allowed_hit     usersLookupByWireGuardAllowedIp() ordered-tree hit for M ranges
 *   allowed_miss    usersLookupByWireGuardAllowedIp() ordered-tree miss for M ranges
 *   allowed_overlap rejected Allowed-IP update that overlaps an existing range
 *   allowed_nonoverlap valid Allowed-IP update that does not overlap
 *   adaptive_admit  userTryAdmitConnection() for fixed distinct-IP K values
 *   adaptive_release userReleaseConnection() for those same fixed K values
 */

#include "objects/users.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

enum
{
    kBenchmarkWarmupIterations = 64
};

static uint64_t benchmarkNowNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static void benchmarkFatal(const char *message)
{
    fprintf(stderr, "users_benchmark: %s\n", message);
    exit(1);
}

/*
 * A pre-generated corpus of deterministic input strings. Building these up front,
 * outside every timed region, keeps snprintf() and its formatting cost out of the
 * measured loops so the numbers reflect only the users_t operation under test.
 */
typedef struct benchmark_corpus_s
{
    size_t count;
    char (*names)[64];         /* unique username of user i */
    char (*passwords)[64];     /* original password of user i */
    char (*rekeys)[64];        /* replacement password for the change benchmark */
    char (*probe_misses)[64];  /* guaranteed-miss password for probe i */
    char (*allowed_cidrs)[32]; /* distinct /32 CIDR for the Allowed-IP benchmark */
} benchmark_corpus_t;

static void benchmarkCorpusCreate(benchmark_corpus_t *corpus, size_t count)
{
    corpus->count         = count;
    corpus->names         = memoryAllocate(sizeof(corpus->names[0]) * count);
    corpus->passwords     = memoryAllocate(sizeof(corpus->passwords[0]) * count);
    corpus->rekeys        = memoryAllocate(sizeof(corpus->rekeys[0]) * count);
    corpus->probe_misses  = memoryAllocate(sizeof(corpus->probe_misses[0]) * count);
    corpus->allowed_cidrs = memoryAllocate(sizeof(corpus->allowed_cidrs[0]) * count);
    if (corpus->names == NULL || corpus->passwords == NULL || corpus->rekeys == NULL || corpus->probe_misses == NULL ||
        corpus->allowed_cidrs == NULL)
    {
        benchmarkFatal("corpus allocation failed");
    }

    for (size_t i = 0; i < count; ++i)
    {
        (void) snprintf(corpus->names[i], sizeof(corpus->names[i]), "benchmark-name-%020zu", i);
        (void) snprintf(corpus->passwords[i], sizeof(corpus->passwords[i]), "benchmark-password-%020zu", i);
        (void) snprintf(corpus->rekeys[i], sizeof(corpus->rekeys[i]), "benchmark-rekey-%020zu", i);
        (void) snprintf(corpus->probe_misses[i], sizeof(corpus->probe_misses[i]), "benchmark-miss-%020zu", i);
        /* 10.a.b.c/32 walks a distinct address per user for up to ~16M users. */
        (void) snprintf(corpus->allowed_cidrs[i],
                        sizeof(corpus->allowed_cidrs[i]),
                        "10.%zu.%zu.%zu/32",
                        (i >> 16) & 0xFFU,
                        (i >> 8) & 0xFFU,
                        i & 0xFFU);
    }
}

static void benchmarkCorpusDestroy(benchmark_corpus_t *corpus)
{
    memoryFree(corpus->names);
    memoryFree(corpus->passwords);
    memoryFree(corpus->rekeys);
    memoryFree(corpus->probe_misses);
    memoryFree(corpus->allowed_cidrs);
}

static void benchmarkAssignUserName(user_t *user, const char *name)
{
    char *copy = stringDuplicate(name);
    if (copy == NULL)
    {
        benchmarkFatal("username allocation failed");
    }
    memoryFree(user->name);
    user->name = copy;
}

/* Builds a users_t of `count` deterministic users. Returns construction ns. */
static uint64_t benchmarkBuild(users_t *users, const benchmark_corpus_t *corpus)
{
    const uint64_t start = benchmarkNowNs();

    for (size_t i = 0; i < corpus->count; ++i)
    {
        user_t user;
        memoryZero(&user, sizeof(user));
        if (! userCreate(&user, corpus->passwords[i]))
        {
            benchmarkFatal("userCreate failed");
        }
        benchmarkAssignUserName(&user, corpus->names[i]);
        userSetId(&user, (uint64_t) i + 1U);
        if (! usersAddUser(users, &user))
        {
            benchmarkFatal("usersAddUser failed");
        }
        userDestroy(&user);
    }

    return benchmarkNowNs() - start;
}

/*
 * Times a bulk JSON feed of `count` users into a fresh table. The JSON document is
 * assembled before the clock starts so only the feed path (parse + insert) is
 * measured. Returns feed ns, or 0 if the JSON could not be assembled.
 */
static uint64_t benchmarkFeed(const benchmark_corpus_t *corpus)
{
    cJSON *array = cJSON_CreateArray();
    if (array == NULL)
    {
        benchmarkFatal("feed JSON array allocation failed");
    }
    for (size_t i = 0; i < corpus->count; ++i)
    {
        cJSON *entry = cJSON_CreateObject();
        if (entry == NULL || cJSON_AddStringToObject(entry, "name", corpus->names[i]) == NULL ||
            cJSON_AddStringToObject(entry, "password", corpus->passwords[i]) == NULL)
        {
            benchmarkFatal("feed JSON entry allocation failed");
        }
        cJSON_AddItemToArray(array, entry);
    }

    users_t users;
    if (! usersCreate(&users))
    {
        benchmarkFatal("feed usersCreate failed");
    }

    const uint64_t start = benchmarkNowNs();
    const bool     ok    = usersFeedJson(&users, array);
    const uint64_t total = benchmarkNowNs() - start;

    if (! ok || usersCount(&users) != corpus->count)
    {
        benchmarkFatal("usersFeedJson failed");
    }

    usersDestroy(&users);
    cJSON_Delete(array);
    return total;
}

/* Times one full validation sweep. Returns ns. */
static uint64_t benchmarkValidate(const users_t *users)
{
    const uint64_t start = benchmarkNowNs();
    if (! usersValidate(users))
    {
        benchmarkFatal("usersValidate failed");
    }
    return benchmarkNowNs() - start;
}

/* Times `iterations` plaintext lookups. Passwords come from the pre-built corpus,
 * so no formatting happens inside the loop. Returns total ns. */
static uint64_t benchmarkLookup(users_t *users, const benchmark_corpus_t *corpus, size_t iterations, bool hit,
                                volatile size_t *sink)
{
    const size_t count = corpus->count;

    /* Warm up so first-touch page faults and cache misses are not timed. */
    for (size_t w = 0; w < kBenchmarkWarmupIterations && w < iterations; ++w)
    {
        const char *password = hit ? corpus->passwords[w % count] : corpus->probe_misses[w % count];
        if (usersLookupByPassword(users, password) != NULL)
        {
            *sink += 1U;
        }
    }

    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        const char *password = hit ? corpus->passwords[i % count] : corpus->probe_misses[i % count];
        if (usersLookupByPassword(users, password) != NULL)
        {
            *sink += 1U;
        }
    }
    return benchmarkNowNs() - start;
}

/* Times a full deep copy of `src` into a fresh table. Returns ns. */
static uint64_t benchmarkCopy(const users_t *src)
{
    users_t dest;
    if (! usersCreate(&dest))
    {
        benchmarkFatal("copy usersCreate failed");
    }

    const uint64_t start = benchmarkNowNs();
    const bool     ok    = usersCopy(&dest, src);
    const uint64_t total = benchmarkNowNs() - start;

    if (! ok)
    {
        benchmarkFatal("usersCopy failed");
    }
    usersDestroy(&dest);
    return total;
}

/* Times an incremental password change for every user. Returns total ns. */
static uint64_t benchmarkPasswordChange(users_t *users, const benchmark_corpus_t *corpus)
{
    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < corpus->count; ++i)
    {
        user_t *user = usersLookupByPassword(users, corpus->passwords[i]);
        if (user == NULL || ! usersChangePassword(users, user, corpus->rekeys[i]))
        {
            benchmarkFatal("usersChangePassword failed");
        }
    }
    return benchmarkNowNs() - start;
}

/* Times removal of every user (each a swap-with-last + incremental erase). The
 * table is emptied as a side effect. Returns total ns. */
static uint64_t benchmarkRemove(users_t *users)
{
    const uint64_t start = benchmarkNowNs();
    while (usersCount(users) > 0)
    {
        user_t *first = usersGetAt(users, 0);
        if (first == NULL || ! usersRemoveUser(users, first))
        {
            benchmarkFatal("usersRemoveUser failed");
        }
    }
    return benchmarkNowNs() - start;
}

static void benchmarkReport(const char *label, const char *dimension, size_t count, size_t operations,
                            uint64_t total_ns)
{
    const double ns_per_op = operations > 0 ? (double) total_ns / (double) operations : 0.0;
    printf("  %-18s %s=%-8zu ops=%-9zu ns/op=%10.1f\n", label, dimension, count, operations, ns_per_op);
}

static void benchmarkParseIpOrFatal(const char *text, ip_addr_t *out, const char *context)
{
    memoryZero(out, sizeof(*out));
    if (parseIpAddress(text, out) == IPADDR_TYPE_ANY)
    {
        benchmarkFatal(context);
    }
}

static uint64_t benchmarkAllowedIpLookup(users_t *users, const ip_addr_t *probes, size_t probe_count, size_t iterations,
                                         bool expect_hit, volatile size_t *sink)
{
    for (size_t w = 0; w < kBenchmarkWarmupIterations && w < iterations; ++w)
    {
        const bool found = usersLookupByWireGuardAllowedIp(users, &probes[w % probe_count]) != NULL;
        if (found != expect_hit)
        {
            benchmarkFatal(expect_hit ? "allowed-ip warm hit missed" : "allowed-ip warm miss hit");
        }
    }

    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        const bool found = usersLookupByWireGuardAllowedIp(users, &probes[i % probe_count]) != NULL;
        if (found != expect_hit)
        {
            benchmarkFatal(expect_hit ? "allowed-ip hit missed" : "allowed-ip miss hit");
        }
        if (found)
        {
            *sink += 1U;
        }
    }
    return benchmarkNowNs() - start;
}

static uint64_t benchmarkAllowedIpOverlapUpdate(users_t *users, user_t *target, const char *overlapping_cidr,
                                                size_t iterations)
{
    user_update_t update = {.mask = kUserUpdateWireGuardAllowedIps, .wireguard_allowed_ips = overlapping_cidr};

    for (size_t w = 0; w < kBenchmarkWarmupIterations && w < iterations; ++w)
    {
        if (usersUpdateUser(users, target, &update))
        {
            benchmarkFatal("allowed-ip warm overlapping update unexpectedly succeeded");
        }
    }

    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        if (usersUpdateUser(users, target, &update))
        {
            benchmarkFatal("allowed-ip overlapping update unexpectedly succeeded");
        }
    }
    return benchmarkNowNs() - start;
}

static uint64_t benchmarkAllowedIpNonOverlapUpdate(users_t *users, user_t *target, size_t iterations)
{
    static const char *nonoverlap_cidrs[] = {"11.255.255.254/32", "11.255.255.253/32"};
    user_update_t      updates[]          = {
        {.mask = kUserUpdateWireGuardAllowedIps, .wireguard_allowed_ips = nonoverlap_cidrs[0]},
        {.mask = kUserUpdateWireGuardAllowedIps, .wireguard_allowed_ips = nonoverlap_cidrs[1]},
    };

    for (size_t w = 0; w < kBenchmarkWarmupIterations && w < iterations; ++w)
    {
        if (! usersUpdateUser(users, target, &updates[w & 1U]))
        {
            benchmarkFatal("allowed-ip warm non-overlapping update failed");
        }
    }

    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        if (! usersUpdateUser(users, target, &updates[i & 1U]))
        {
            benchmarkFatal("allowed-ip non-overlapping update failed");
        }
    }
    return benchmarkNowNs() - start;
}

/* Builds `count` users each carrying a distinct /32 Allowed-IP range and times
 * hit, miss, overlap, and non-overlap paths against the ordered interval index. */
static void benchmarkAllowedIp(const benchmark_corpus_t *corpus, size_t iterations, volatile size_t *sink)
{
    users_t users;
    if (! usersCreate(&users))
    {
        benchmarkFatal("allowed-ip usersCreate failed");
    }

    size_t indexed = 0;
    for (size_t i = 0; i < corpus->count; ++i)
    {
        user_t user;
        memoryZero(&user, sizeof(user));
        if (! userCreate(&user, corpus->passwords[i]))
        {
            benchmarkFatal("allowed-ip userCreate failed");
        }
        benchmarkAssignUserName(&user, corpus->names[i]);
        userSetId(&user, (uint64_t) i + 1U);
        /* Distinct /32s never overlap, so every add is accepted. */
        if (userSetWireGuardAllowedIps(&user, corpus->allowed_cidrs[i]) && usersAddUser(&users, &user))
        {
            indexed += 1U;
        }
        userDestroy(&user);
    }
    if (indexed == 0)
    {
        usersDestroy(&users);
        return;
    }

    /* Resolve the string CIDRs to addresses before timing the lookups. */
    ip_addr_t *hit_probes  = memoryAllocate(sizeof(*hit_probes) * indexed);
    ip_addr_t *miss_probes = memoryAllocate(sizeof(*miss_probes) * indexed);
    if (hit_probes == NULL || miss_probes == NULL)
    {
        benchmarkFatal("allowed-ip probe allocation failed");
    }
    for (size_t i = 0; i < indexed; ++i)
    {
        char host[24];
        (void) snprintf(host, sizeof(host), "10.%zu.%zu.%zu", (i >> 16) & 0xFFU, (i >> 8) & 0xFFU, i & 0xFFU);
        benchmarkParseIpOrFatal(host, &hit_probes[i], "allowed-ip hit probe parse failed");
        (void) snprintf(host, sizeof(host), "11.%zu.%zu.%zu", (i >> 16) & 0xFFU, (i >> 8) & 0xFFU, i & 0xFFU);
        benchmarkParseIpOrFatal(host, &miss_probes[i], "allowed-ip miss probe parse failed");
    }

    const uint64_t hit_total = benchmarkAllowedIpLookup(&users, hit_probes, indexed, iterations, true, sink);
    benchmarkReport("allowed_hit", "M", indexed, iterations, hit_total);

    const uint64_t miss_total = benchmarkAllowedIpLookup(&users, miss_probes, indexed, iterations, false, sink);
    benchmarkReport("allowed_miss", "M", indexed, iterations, miss_total);

    user_t target;
    memoryZero(&target, sizeof(target));
    if (! userCreate(&target, "allowed-ip-update-target"))
    {
        benchmarkFatal("allowed-ip target userCreate failed");
    }
    benchmarkAssignUserName(&target, "benchmark-allowed-ip-update-target");
    userSetId(&target, (uint64_t) indexed + 1U);
    if (! usersAddUser(&users, &target))
    {
        benchmarkFatal("allowed-ip target add failed");
    }
    userDestroy(&target);
    user_t *stored_target = usersLookupByIdentifier(&users, (uint64_t) indexed + 1U);
    if (stored_target == NULL)
    {
        benchmarkFatal("allowed-ip target lookup failed");
    }

    const uint64_t overlap_total =
        benchmarkAllowedIpOverlapUpdate(&users, stored_target, corpus->allowed_cidrs[0], iterations);
    benchmarkReport("allowed_overlap", "M", indexed, iterations, overlap_total);

    const uint64_t nonoverlap_total = benchmarkAllowedIpNonOverlapUpdate(&users, stored_target, iterations);
    benchmarkReport("allowed_nonoverlap", "M", indexed, iterations, nonoverlap_total);

    memoryFree(hit_probes);
    memoryFree(miss_probes);
    usersDestroy(&users);
}

static user_ip_key_t benchmarkIpKey(size_t i)
{
    user_ip_key_t key = {.type = 4};
    key.bytes[0]      = 10;
    key.bytes[1]      = (uint8_t) ((i >> 16) & 0xFFU);
    key.bytes[2]      = (uint8_t) ((i >> 8) & 0xFFU);
    key.bytes[3]      = (uint8_t) (i & 0xFFU);
    return key;
}

static void benchmarkAdaptiveIpWarmup(const user_ip_key_t *keys, size_t distinct)
{
    user_t user;

    memoryZero(&user, sizeof(user));
    if (! userCreate(&user, "adaptive-ip-warmup"))
    {
        benchmarkFatal("adaptive-ip warmup userCreate failed");
    }
    for (size_t i = 0; i < distinct; ++i)
    {
        if (userTryAdmitConnection(&user, &keys[i], 1000) != kUserAdmissionOk)
        {
            benchmarkFatal("adaptive-ip warmup admission failed");
        }
    }
    for (size_t i = 0; i < distinct; ++i)
    {
        userReleaseConnection(&user, &keys[i]);
    }
    userDestroy(&user);
}

/* Admits and releases a fixed matrix of distinct source IP counts. */
static void benchmarkAdaptiveIpOne(size_t distinct)
{
    user_t         user;
    user_ip_key_t *keys = memoryAllocate(sizeof(*keys) * distinct);
    if (keys == NULL)
    {
        benchmarkFatal("adaptive-ip key allocation failed");
    }
    for (size_t i = 0; i < distinct; ++i)
    {
        keys[i] = benchmarkIpKey(i);
    }

    benchmarkAdaptiveIpWarmup(keys, distinct);

    memoryZero(&user, sizeof(user));
    if (! userCreate(&user, "adaptive-ip-benchmark"))
    {
        benchmarkFatal("adaptive-ip userCreate failed");
    }

    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < distinct; ++i)
    {
        if (userTryAdmitConnection(&user, &keys[i], 1000) != kUserAdmissionOk)
        {
            benchmarkFatal("adaptive-ip admission failed");
        }
    }
    const uint64_t admit_total = benchmarkNowNs() - start;
    benchmarkReport("adaptive_admit", "K", distinct, distinct, admit_total);

    const uint64_t release_start = benchmarkNowNs();
    for (size_t i = 0; i < distinct; ++i)
    {
        userReleaseConnection(&user, &keys[i]);
    }
    const uint64_t release_total = benchmarkNowNs() - release_start;
    benchmarkReport("adaptive_release", "K", distinct, distinct, release_total);

    userDestroy(&user);
    memoryFree(keys);
}

static void benchmarkAdaptiveIp(void)
{
    static const size_t distinct_matrix[] = {1, 8, 32, 256, 4096};

    for (size_t i = 0; i < sizeof(distinct_matrix) / sizeof(distinct_matrix[0]); ++i)
    {
        benchmarkAdaptiveIpOne(distinct_matrix[i]);
    }
}

static void benchmarkRun(size_t count)
{
    users_t         users;
    volatile size_t sink       = 0;
    const size_t    iterations = count < 100000U ? 100000U : count;

    benchmark_corpus_t corpus;
    benchmarkCorpusCreate(&corpus, count);

    if (! usersCreate(&users))
    {
        benchmarkFatal("usersCreate failed");
    }

    printf("N=%zu\n", count);

    const uint64_t construct_ns = benchmarkBuild(&users, &corpus);
    benchmarkReport("construct", "N", count, count, construct_ns);

    const uint64_t feed_ns = benchmarkFeed(&corpus);
    benchmarkReport("feed_json", "N", count, count, feed_ns);

    const uint64_t validate_ns = benchmarkValidate(&users);
    benchmarkReport("validate", "N", count, count, validate_ns);

    const uint64_t hit_ns = benchmarkLookup(&users, &corpus, iterations, true, &sink);
    benchmarkReport("password_hit", "N", count, iterations, hit_ns);

    const uint64_t miss_ns = benchmarkLookup(&users, &corpus, iterations, false, &sink);
    benchmarkReport("password_miss", "N", count, iterations, miss_ns);

    const uint64_t copy_ns = benchmarkCopy(&users);
    benchmarkReport("native_copy", "N", count, count, copy_ns);

    const uint64_t change_ns = benchmarkPasswordChange(&users, &corpus);
    benchmarkReport("password_change", "N", count, count, change_ns);

    /* Removal empties the table, so it runs last on the primary set. */
    const uint64_t remove_ns = benchmarkRemove(&users);
    benchmarkReport("remove", "N", count, count, remove_ns);

    usersDestroy(&users);

    benchmarkAllowedIp(&corpus, iterations, &sink);
    benchmarkAdaptiveIp();

    benchmarkCorpusDestroy(&corpus);

    /* Consume the sink so the optimizer cannot elide the timed lookups. */
    if (sink == SIZE_MAX)
    {
        printf("sink=%zu\n", (size_t) sink);
    }
}

int main(int argc, char **argv)
{
    static const size_t default_sizes[] = {1000, 10000};

    if (wCryptoGlobalInit() != kWCryptoOk)
    {
        benchmarkFatal("crypto global initialization failed");
    }

    if (argc > 1)
    {
        for (int i = 1; i < argc; ++i)
        {
            const long long parsed = atoll(argv[i]);
            if (parsed <= 0)
            {
                benchmarkFatal("user count arguments must be positive");
            }
            benchmarkRun((size_t) parsed);
        }
    }
    else
    {
        for (size_t i = 0; i < sizeof(default_sizes) / sizeof(default_sizes[0]); ++i)
        {
            benchmarkRun(default_sizes[i]);
        }
    }

    return 0;
}
