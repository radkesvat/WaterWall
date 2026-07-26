#include "managers/socket_manager_iptables_recovery.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#if defined(SOCKET_MANAGER_IPTABLES_ALLOC_FAILURE_TEST)
static size_t realloc_failure_min_size = SIZE_MAX;

void *__real_memoryReAllocate(void *ptr, size_t size);
void *__wrap_memoryReAllocate(void *ptr, size_t size);

void *__wrap_memoryReAllocate(void *ptr, size_t size)
{
    if (size >= realloc_failure_min_size)
    {
        realloc_failure_min_size = SIZE_MAX;
        return NULL;
    }
    return __real_memoryReAllocate(ptr, size);
}
#endif

#if defined(__linux__)
// Disabled-by-default close() fault injection. When armed, the next close() still
// releases the descriptor (so the test never leaks one) but then reports EIO,
// modeling a close() that fails during cleanup of a failed bind(). This proves
// bindAbstractSocketName() preserves the original bind() errno across cleanup.
static bool fail_next_close = false;

int __real_close(int fd);
int __wrap_close(int fd);

int __wrap_close(int fd)
{
    if (fail_next_close)
    {
        fail_next_close = false;
        (void) __real_close(fd); // release the descriptor first so nothing leaks
        errno = EIO;
        return -1;
    }
    return __real_close(fd);
}
#endif

typedef struct probe_state_s
{
    uint64_t active_tokens[8];
    size_t   active_count;
    uint64_t error_tokens[8];
    size_t   error_count;
    uint64_t seen_tokens[16];
    size_t   seen_count;
} probe_state_t;

typedef struct cleanup_runner_state_s
{
    socket_manager_iptables_cleanup_action_t actions[16];
    size_t                                   call_count;
    size_t                                   fail_call;
} cleanup_runner_state_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireEqStr(const char *got, const char *expected, const char *message)
{
    if (strcmp(got, expected) != 0)
    {
        fprintf(stderr, "%s\n  expected: %s\n  got     : %s\n", message, expected, got);
        exit(1);
    }
}

static bool tokenIn(const uint64_t *tokens, size_t count, uint64_t token)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (tokens[i] == token)
        {
            return true;
        }
    }
    return false;
}

static socket_manager_iptables_lease_probe_result_t fakeProbe(uint64_t token, int *held_fd, void *userdata)
{
    probe_state_t *state = userdata;
    require(state->seen_count < sizeof(state->seen_tokens) / sizeof(state->seen_tokens[0]), "too many probe calls");
    state->seen_tokens[state->seen_count++] = token;
    *held_fd                                = -1;
    if (tokenIn(state->error_tokens, state->error_count, token))
    {
        return kSocketManagerIptablesLeaseError;
    }
    if (tokenIn(state->active_tokens, state->active_count, token))
    {
        return kSocketManagerIptablesLeaseInUse;
    }
    return kSocketManagerIptablesLeaseAcquired;
}

static bool fakeCleanupRunner(const socket_manager_iptables_cleanup_op_t *op, void *userdata)
{
    cleanup_runner_state_t *state = userdata;
    require(state->call_count < sizeof(state->actions) / sizeof(state->actions[0]), "too many cleanup calls");
    const size_t call    = state->call_count++;
    state->actions[call] = op->action;
    return call != state->fail_call;
}

static void testNameFormattingAndParsing(void)
{
    char chain[32];
    require(socketManagerIptablesFormatChainName(0x0123456789ABCDEFULL, 4, chain, sizeof(chain)),
            "format v4 chain failed");
    requireEqStr(chain, "WW2_0123456789ABCDEF_4", "v4 chain format mismatch");

    uint64_t token  = 0;
    int      family = 0;
    require(socketManagerIptablesParseChainName(chain, &token, &family), "formatted chain should parse");
    require(token == 0x0123456789ABCDEFULL, "parsed token mismatch");
    require(family == 4, "parsed family mismatch");

    require(socketManagerIptablesFormatChainName(0xFEDCBA9876543210ULL, 6, chain, sizeof(chain)),
            "format v6 chain failed");
    requireEqStr(chain, "WW2_FEDCBA9876543210_6", "v6 chain format mismatch");
}

static void testStrictNameRejection(void)
{
    static const char *const invalid[] = {"WW_00000001_00000002_4",
                                          "ww2_0123456789ABCDEF_4",
                                          "WW2_0123456789abcdef_4",
                                          "WW2_0123456789ABCDE_4",
                                          "WW2_0123456789ABCDEFG_4",
                                          "WW2_0123456789ABCDEF_5",
                                          "WW2_0123456789ABCDEF_4_EXTRA",
                                          " WW2_0123456789ABCDEF_4",
                                          "WW2_0123456789ABCDEF_4 ",
                                          "WW2_0123456789ABCDEG_4"};

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        require(! socketManagerIptablesParseChainName(invalid[i], NULL, NULL), "invalid chain name parsed");
    }
}

static void testLegacyNameParsing(void)
{
    int family = 0;
    require(socketManagerIptablesParseLegacyChainName("WW_00000001_00000002_4", &family),
            "legacy v4 name should parse");
    require(family == 4, "legacy v4 family mismatch");

    family = 0;
    require(socketManagerIptablesParseLegacyChainName("WW_DEADBEEF_0BADF00D_6", &family),
            "legacy v6 name should parse");
    require(family == 6, "legacy v6 family mismatch");

    // The legacy parser and the v2 parser are strictly separate ownership classes.
    require(! socketManagerIptablesParseChainName("WW_00000001_00000002_4", NULL, NULL),
            "legacy name must not parse as a v2 chain");
    require(! socketManagerIptablesParseLegacyChainName("WW2_0123456789ABCDEF_4", NULL),
            "v2 name must not parse as a legacy chain");
}

static void testLegacyNameRejection(void)
{
    static const char *const invalid[] = {"ww_00000001_00000002_4",       // lowercase prefix
                                          "WW_0000000a_00000002_4",       // lowercase hex pid
                                          "WW_00000001_0000000b_4",       // lowercase hex nonce
                                          "WW_0000001_00000002_4",        // short pid
                                          "WW_000000001_00000002_4",      // long pid
                                          "WW_00000001_0000002_4",        // short nonce
                                          "WW_00000001_000000002_4",      // long nonce
                                          "WW_00000001-00000002_4",       // bad separator
                                          "WW_00000001_00000002-4",       // bad family separator
                                          "WW_00000001_00000002_5",       // bad family
                                          "WW_0000000G_00000002_4",       // non-hex pid
                                          "WW_00000001_0000000G_4",       // non-hex nonce
                                          "WW_00000001_00000002_4_EXTRA", // suffix
                                          " WW_00000001_00000002_4",      // leading whitespace
                                          "WW_00000001_00000002_4 ",      // trailing whitespace
                                          "WW2_0123456789ABCDEF_4"};      // v2 name

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        require(! socketManagerIptablesParseLegacyChainName(invalid[i], NULL), "invalid legacy chain name parsed");
    }
}

static void requirePlan(const char *v4, bool include_v4, const char *v6, bool include_v6, probe_state_t *probe,
                        socket_manager_iptables_cleanup_plan_t *plan, bool expected_result, bool expected_v4,
                        bool expected_v6)
{
    bool v4_ok = false;
    bool v6_ok = false;
    socketManagerIptablesCleanupPlanInit(plan);
    bool result =
        socketManagerIptablesBuildCleanupPlan(v4, include_v4, v6, include_v6, fakeProbe, probe, plan, &v4_ok, &v6_ok);
    require(result == expected_result, "cleanup plan result mismatch");
    require(v4_ok == expected_v4, "cleanup plan v4 result mismatch");
    require(v6_ok == expected_v6, "cleanup plan v6 result mismatch");
}

static void testOneStaleIpv4Chain(void)
{
    const char                            *snapshot = "-P PREROUTING ACCEPT\n"
                                                      "-N WW2_0123456789ABCDEF_4\n"
                                                      "-A PREROUTING -j WW2_0123456789ABCDEF_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, true, true, true);
    require(probe.seen_count == 1, "stale token should be probed once");
    require(plan.count == 3, "stale chain should schedule jump deletion, flush, delete");
    require(plan.ops[0].family == 4 && plan.ops[0].action == kSocketManagerIptablesCleanupDeleteJump,
            "first stale op should delete jump");
    require(plan.ops[1].action == kSocketManagerIptablesCleanupFlushChain, "second stale op should flush chain");
    require(plan.ops[2].action == kSocketManagerIptablesCleanupDeleteChain, "third stale op should delete chain");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testPairedActiveTokenPreservesBothFamilies(void)
{
    const char                            *v4 = "-N WW2_1111111111111111_4\n-A PREROUTING -j WW2_1111111111111111_4\n";
    const char                            *v6 = "-N WW2_1111111111111111_6\n-A PREROUTING -j WW2_1111111111111111_6\n";
    probe_state_t                          probe = {.active_tokens = {0x1111111111111111ULL}, .active_count = 1};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(v4, true, v6, true, &probe, &plan, true, true, true);
    require(probe.seen_count == 1, "paired token should use one liveness decision");
    require(plan.count == 0, "active owner must preserve both chains");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testDuplicateJumpsAndOrphanChain(void)
{
    const char                            *snapshot = "-N WW2_2222222222222222_4\n"
                                                      "-A PREROUTING -j WW2_2222222222222222_4\n"
                                                      "-A PREROUTING -j WW2_2222222222222222_4\n"
                                                      "-N WW2_3333333333333333_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, true, true, true);
    require(plan.count == 6, "duplicate jumps and orphan chain should both be cleaned");
    require(plan.ops[0].action == kSocketManagerIptablesCleanupDeleteJump, "first duplicate jump missing");
    require(plan.ops[1].action == kSocketManagerIptablesCleanupDeleteJump, "second duplicate jump missing");
    require(plan.ops[2].action == kSocketManagerIptablesCleanupFlushChain, "duplicate chain flush missing");
    require(plan.ops[3].action == kSocketManagerIptablesCleanupDeleteChain, "duplicate chain delete missing");
    require(plan.ops[4].action == kSocketManagerIptablesCleanupFlushChain, "orphan chain flush missing");
    require(plan.ops[5].action == kSocketManagerIptablesCleanupDeleteChain, "orphan chain delete missing");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testUnexpectedReferencesBlockCandidate(void)
{
    const char                            *snapshot = "-N WW2_4444444444444444_4\n"
                                                      "-A PREROUTING -p TCP -j WW2_4444444444444444_4\n"
                                                      "-N WW2_5555555555555555_4\n"
                                                      "-A OTHER -j WW2_5555555555555555_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(plan.count == 0, "unexpected references must not schedule cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testAllJumpAndGotoReferencesAreDetected(void)
{
    const char                            *snapshot = "-N WW2_1010101010101010_4\n"
                                                      "-N WW2_2020202020202020_4\n"
                                                      "-N WW2_3030303030303030_4\n"
                                                      "-N WW2_4040404040404040_4\n"
                                                      "-A OTHER --jump WW2_1010101010101010_4\n"
                                                      "-A OTHER -g WW2_2020202020202020_4\n"
                                                      "-A OTHER --goto WW2_3030303030303030_4\n"
                                                      "-A PREROUTING --jump WW2_4040404040404040_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(probe.seen_count == 4, "each referenced owner should be probed");
    require(plan.count == 0, "non-exact jump and goto references must block cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testIgnoresUnrelatedAndLookalikes(void)
{
    const char                            *snapshot = "-N WW_00000001_00000002_4\n"
                                                      "-N WW2_6666666666666666_6\n"
                                                      "-A PREROUTING -j WW2_6666666666666666_6\n"
                                                      "-A PREROUTING -m comment --comment WW2_7777777777777777_4 -j ACCEPT\n"
                                                      "-A PREROUTING -j WW2_8888888888888888_4_SUFFIX\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, true, true, true);
    require(probe.seen_count == 0, "legacy or wrong-family chains must be ignored");
    require(plan.count == 0, "unrelated chains must not be scheduled");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testCrossFamilyChainNameCollisionIsolated(void)
{
    // A stale IPv4 V2 chain with its exact PREROUTING jump, alongside an IPv6
    // snapshot that declares and *conditionally* references the exact same textual
    // _4 chain name. iptables and ip6tables have separate namespaces, so the
    // wrong-family IPv6 declaration and reference must be ignored and the IPv4
    // candidate must still be cleaned up normally. Before family isolation the
    // IPv6 conditional reference corrupted the IPv4 candidate and blocked its
    // cleanup (result == false, v4_ok == false, empty plan).
    const char                            *v4    = "-P PREROUTING ACCEPT\n"
                                                   "-N WW2_0123456789ABCDEF_4\n"
                                                   "-A PREROUTING -j WW2_0123456789ABCDEF_4\n";
    const char                            *v6    = "-N WW2_0123456789ABCDEF_4\n"
                                                   "-A PREROUTING -p tcp -j WW2_0123456789ABCDEF_4\n";
    probe_state_t                          probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(v4, true, v6, true, &probe, &plan, true, true, true);
    require(probe.seen_count == 1, "the shared owner token should be probed exactly once");
    require(probe.seen_tokens[0] == 0x0123456789ABCDEFULL, "the probed token must be the IPv4 owner token");
    require(plan.count == 3, "the IPv4 chain should still receive its full three-operation cleanup");
    for (size_t i = 0; i < plan.count; ++i)
    {
        require(plan.ops[i].family == 4, "cross-family collision must not schedule an IPv6 operation");
        requireEqStr(plan.ops[i].chain_name, "WW2_0123456789ABCDEF_4", "cleanup op must target only the IPv4 chain");
    }
    require(plan.ops[0].action == kSocketManagerIptablesCleanupDeleteJump, "IPv4 jump deletion missing");
    require(plan.ops[1].action == kSocketManagerIptablesCleanupFlushChain, "IPv4 flush missing");
    require(plan.ops[2].action == kSocketManagerIptablesCleanupDeleteChain, "IPv4 delete missing");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testOverlongIpv6RuleContainedToFamily(void)
{
    // A normal stale IPv4 chain and a normal stale IPv6 chain, plus an IPv6 rule
    // with more than 128 whitespace-delimited tokens. Tokenization overflow is
    // handled conservatively by marking candidates unexpected, but that must be
    // contained to the overflowing rule's own (IPv6) family: the IPv4 chain still
    // gets its full cleanup. Before family isolation the overflow blocked both
    // families.
    const char *v4 = "-N WW2_1111111111111111_4\n-A PREROUTING -j WW2_1111111111111111_4\n";

    char v6[2400];
    snprintf(v6, sizeof(v6), "-N WW2_2222222222222222_6\n-A PREROUTING -j WW2_2222222222222222_6\n-A PREROUTING");
    for (int i = 0; i < 200; ++i)
    {
        strcat(v6, " x");
    }
    strcat(v6, "\n");

    probe_state_t                          probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(v4, true, v6, true, &probe, &plan, false, true, false);
    require(plan.count == 3, "conservative IPv6 failure must not remove the valid IPv4 cleanup plan");
    for (size_t i = 0; i < plan.count; ++i)
    {
        require(plan.ops[i].family == 4, "overlong IPv6 rule must neither schedule nor block IPv4 cleanup");
        requireEqStr(plan.ops[i].chain_name, "WW2_1111111111111111_4", "cleanup op must target only the IPv4 chain");
    }
    require(plan.ops[0].action == kSocketManagerIptablesCleanupDeleteJump, "IPv4 jump deletion missing");
    require(plan.ops[1].action == kSocketManagerIptablesCleanupFlushChain, "IPv4 flush missing");
    require(plan.ops[2].action == kSocketManagerIptablesCleanupDeleteChain, "IPv4 delete missing");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testIncompleteSnapshotRejected(void)
{
    const char   *snapshot = "-N WW2_9999999999999999_4\n-A PREROUTING -j WW2_9999999999999999_4";
    probe_state_t probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(plan.count == 0, "incomplete snapshot must not schedule cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLargeSnapshotBeyondOldFixedBuffer(void)
{
    const size_t filler_lines = 260;
    const char  *tail         = "-N WW2_AAAAAAAAAAAAAAAA_4\n-A PREROUTING -j WW2_AAAAAAAAAAAAAAAA_4\n";
    size_t       cap          = filler_lines * 48U + strlen(tail) + 1U;
    char        *snapshot     = malloc(cap);
    require(snapshot != NULL, "malloc failed");
    snapshot[0] = '\0';
    for (size_t i = 0; i < filler_lines; ++i)
    {
        strcat(snapshot, "-A PREROUTING -j ACCEPT\n");
    }
    strcat(snapshot, tail);
    require(strlen(snapshot) > 2048, "test snapshot should exceed old fixed buffer");

    probe_state_t                          probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, true, true, true);
    require(plan.count == 3, "large complete snapshot should be parsed fully");
    socketManagerIptablesCleanupPlanDrop(&plan);
    free(snapshot);
}

static void testLeaseProbeErrorFailsFamily(void)
{
    const char                            *snapshot = "-N WW2_ABABABABABABABAB_4\n";
    probe_state_t                          probe    = {.error_tokens = {0xABABABABABABABABULL}, .error_count = 1};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(plan.count == 0, "unknown ownership must not schedule cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLinkedLegacyIpv4Blocks(void)
{
    const char                            *snapshot = "-P PREROUTING ACCEPT\n"
                                                      "-N WW_00000001_00000002_4\n"
                                                      "-A WW_00000001_00000002_4 -j REDIRECT --to-ports 41000\n"
                                                      "-A PREROUTING -j WW_00000001_00000002_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(probe.seen_count == 0, "legacy chain must never trigger a v2 owner-lease probe");
    require(plan.count == 0, "legacy chain must never receive a cleanup operation");
    require(plan.blocker_count == 1, "linked legacy chain should produce exactly one blocker");
    requireEqStr(plan.blockers[0].chain_name, "WW_00000001_00000002_4", "legacy blocker name mismatch");
    require(plan.blockers[0].family == 4, "legacy blocker family mismatch");
    require(plan.blockers[0].prerouting_jumps == 1, "legacy blocker jump count mismatch");
    require(! plan.blockers[0].unexpected_reference, "exact PREROUTING jump must not be flagged unexpected");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLinkedLegacyIpv6Blocks(void)
{
    const char                            *snapshot = "-N WW_AABBCCDD_11223344_6\n"
                                                      "-A PREROUTING -j WW_AABBCCDD_11223344_6\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(NULL, false, snapshot, true, &probe, &plan, false, true, false);
    require(plan.blocker_count == 1, "linked legacy v6 chain should produce one blocker");
    require(plan.blockers[0].family == 6, "legacy v6 blocker family mismatch");
    require(plan.count == 0, "legacy v6 chain must receive no cleanup operation");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testOrphanLegacyIgnored(void)
{
    const char                            *snapshot = "-N WW_00000001_00000002_4\n"
                                                      "-A WW_00000001_00000002_4 -j RETURN\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, true, true, true);
    require(plan.blocker_count == 0, "orphan legacy chain must not produce a blocker");
    require(plan.count == 0, "orphan legacy chain must not be cleaned up");
    require(probe.seen_count == 0, "orphan legacy chain must not be probed");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testDuplicateLegacyJumps(void)
{
    const char                            *snapshot = "-N WW_0000000A_0000000B_4\n"
                                                      "-A PREROUTING -j WW_0000000A_0000000B_4\n"
                                                      "-A PREROUTING -j WW_0000000A_0000000B_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(plan.blocker_count == 1, "duplicate exact jumps must collapse into a single blocker");
    require(plan.blockers[0].prerouting_jumps == 2, "duplicate legacy jump count mismatch");
    require(! plan.blockers[0].unexpected_reference, "duplicate exact jumps are not unexpected");
    require(plan.count == 0, "legacy chain must receive no cleanup operation");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLegacyUnexpectedReferences(void)
{
    const char                            *snapshot = "-N WW_10000000_20000000_4\n"
                                                      "-N WW_30000000_40000000_4\n"
                                                      "-N WW_50000000_60000000_4\n"
                                                      "-A PREROUTING --jump WW_10000000_20000000_4\n"
                                                      "-A OTHER -g WW_30000000_40000000_4\n"
                                                      "-A PREROUTING -p tcp -j WW_50000000_60000000_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(probe.seen_count == 0, "legacy chains must never be probed");
    require(plan.count == 0, "legacy chains must never be cleaned up");
    require(plan.blocker_count == 3, "each unexpectedly referenced legacy chain should block");
    for (size_t i = 0; i < plan.blocker_count; ++i)
    {
        require(plan.blockers[i].unexpected_reference, "conditional/long-form/indirect references must be unexpected");
        require(plan.blockers[i].prerouting_jumps == 0, "no exact jump expected for these references");
    }
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLegacyBlockerCoexistsWithStaleV2(void)
{
    const char                            *snapshot = "-N WW_00000001_00000002_4\n"
                                                      "-A PREROUTING -j WW_00000001_00000002_4\n"
                                                      "-N WW2_0123456789ABCDEF_4\n"
                                                      "-A PREROUTING -j WW2_0123456789ABCDEF_4\n";
    probe_state_t                          probe    = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(probe.seen_count == 1, "only the stale v2 chain should be probed");
    require(probe.seen_tokens[0] == 0x0123456789ABCDEFULL, "the probed token must be the v2 owner token");
    require(plan.blocker_count == 1, "the legacy chain should produce one blocker");
    requireEqStr(plan.blockers[0].chain_name, "WW_00000001_00000002_4", "legacy blocker name mismatch");
    require(plan.count == 3, "the safely owned stale v2 chain should still get its full cleanup plan");
    for (size_t i = 0; i < plan.count; ++i)
    {
        requireEqStr(plan.ops[i].chain_name, "WW2_0123456789ABCDEF_4", "cleanup op must target only the v2 chain");
    }
    require(plan.ops[0].action == kSocketManagerIptablesCleanupDeleteJump, "v2 jump deletion missing");
    require(plan.ops[1].action == kSocketManagerIptablesCleanupFlushChain, "v2 flush missing");
    require(plan.ops[2].action == kSocketManagerIptablesCleanupDeleteChain, "v2 delete missing");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLegacyBlockerAllocationFailureIsAtomic(void)
{
#if defined(SOCKET_MANAGER_IPTABLES_ALLOC_FAILURE_TEST)
    char snapshot[2048];
    snprintf(snapshot,
             sizeof(snapshot),
             "-N WW_00000001_00000002_4\n"
             "-A PREROUTING -j WW_00000001_00000002_4\n"
             "-N WW2_ACACACACACACACAC_4\n");
    for (size_t i = 0; i < 15; ++i)
    {
        strcat(snapshot, "-A PREROUTING -j WW2_ACACACACACACACAC_4\n");
    }

    probe_state_t                          probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    socketManagerIptablesCleanupPlanInit(&plan);
    bool v4_ok               = true;
    bool v6_ok               = true;
    realloc_failure_min_size = 1024;
    require(! socketManagerIptablesBuildCleanupPlan(snapshot, true, "", true, fakeProbe, &probe, &plan, &v4_ok, &v6_ok),
            "injected planning allocation failure should be reported");
    require(! v4_ok && ! v6_ok, "internal planning failure must fail every included family");
    require(plan.count == 0 && plan.ops == NULL, "internal planning failure must discard the partial cleanup plan");
    require(plan.blocker_count == 0 && plan.blockers == NULL,
            "internal planning failure must discard partially built blocker diagnostics");
    socketManagerIptablesCleanupPlanDrop(&plan);
#endif
}

static void testCleanupFailureOrdering(void)
{
    const char                            *duplicate_snapshot = "-N WW2_CDCDCDCDCDCDCDCD_4\n"
                                                                "-A PREROUTING -j WW2_CDCDCDCDCDCDCDCD_4\n"
                                                                "-A PREROUTING -j WW2_CDCDCDCDCDCDCDCD_4\n";
    probe_state_t                          probe              = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(duplicate_snapshot, true, NULL, false, &probe, &plan, true, true, true);

    cleanup_runner_state_t jump_failure = {.fail_call = 0};
    bool                   v4_ok        = true;
    bool                   v6_ok        = true;
    require(! socketManagerIptablesExecuteCleanupPlan(&plan, fakeCleanupRunner, &jump_failure, &v4_ok, &v6_ok),
            "jump deletion failure should fail cleanup");
    require(jump_failure.call_count == 2, "all jump deletions should be attempted before stopping the chain");
    require(jump_failure.actions[0] == kSocketManagerIptablesCleanupDeleteJump &&
                jump_failure.actions[1] == kSocketManagerIptablesCleanupDeleteJump,
            "flush and delete must be skipped after a jump deletion failure");
    require(! v4_ok && v6_ok, "jump deletion failure should fail only its family");

    cleanup_runner_state_t retry = {.fail_call = SIZE_MAX};
    v4_ok                        = true;
    v6_ok                        = true;
    require(socketManagerIptablesExecuteCleanupPlan(&plan, fakeCleanupRunner, &retry, &v4_ok, &v6_ok),
            "a later cleanup attempt should be able to retry the complete chain plan");
    require(retry.call_count == 4 && retry.actions[2] == kSocketManagerIptablesCleanupFlushChain &&
                retry.actions[3] == kSocketManagerIptablesCleanupDeleteChain,
            "retry did not run both unlink operations before flush and delete");
    require(v4_ok && v6_ok, "successful retry should preserve family reconciliation state");
    socketManagerIptablesCleanupPlanDrop(&plan);

    const char *single_snapshot = "-N WW2_EFEFEFEFEFEFEFEF_4\n"
                                  "-A PREROUTING -j WW2_EFEFEFEFEFEFEFEF_4\n";
    probe                       = (probe_state_t) {0};
    requirePlan(single_snapshot, true, NULL, false, &probe, &plan, true, true, true);
    cleanup_runner_state_t flush_failure = {.fail_call = 1};
    v4_ok                                = true;
    v6_ok                                = true;
    require(! socketManagerIptablesExecuteCleanupPlan(&plan, fakeCleanupRunner, &flush_failure, &v4_ok, &v6_ok),
            "flush failure should fail cleanup");
    require(flush_failure.call_count == 2, "chain deletion must be skipped after a flush failure");
    require(flush_failure.actions[0] == kSocketManagerIptablesCleanupDeleteJump &&
                flush_failure.actions[1] == kSocketManagerIptablesCleanupFlushChain,
            "cleanup operations ran out of order");
    require(! v4_ok && v6_ok, "flush failure should fail only its family");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLockAndOwnerLeaseContention(void)
{
#if defined(__linux__)
    int first_lock  = -1;
    int second_lock = -1;
    require(socketManagerIptablesAcquireReconcileLock(&first_lock, 0), "could not acquire reconciliation lock");
    require(! socketManagerIptablesAcquireReconcileLock(&second_lock, 0),
            "contending reconciliation lock should time out");
    socketManagerIptablesReleaseLease(&first_lock);
    require(socketManagerIptablesAcquireReconcileLock(&second_lock, 0),
            "reconciliation lock should be reusable after release");
    socketManagerIptablesReleaseLease(&second_lock);

    const uint64_t token        = 0xF0E1D2C3B4A59687ULL;
    int            first_owner  = -1;
    int            second_owner = -1;
    require(socketManagerIptablesAcquireOwnerLease(token, &first_owner) == kSocketManagerIptablesLeaseAcquired,
            "could not acquire owner lease");
    require(socketManagerIptablesAcquireOwnerLease(token, &second_owner) == kSocketManagerIptablesLeaseInUse,
            "contending owner lease should report active ownership");

    // A cleanup close() that fails after a contended bind() must not overwrite the
    // bind() EADDRINUSE: the contention must still be classified as LeaseInUse and
    // not as LeaseError, so reconciliation-lock retry decisions still see the busy
    // name.
    fail_next_close = true;
    errno           = 0;
    socket_manager_iptables_lease_probe_result_t contended =
        socketManagerIptablesAcquireOwnerLease(token, &second_owner);
    const int  contended_errno    = errno;
    const bool injection_consumed = ! fail_next_close;
    fail_next_close               = false;
    require(contended == kSocketManagerIptablesLeaseInUse,
            "a live owner lease must stay LeaseInUse even when the cleanup close() fails");
    require(injection_consumed, "the injected close failure was not consumed by lease cleanup");
    require(contended_errno == EADDRINUSE, "the bind() EADDRINUSE must survive a failing cleanup close()");
    require(second_owner == -1, "a contended lease must not hand back a descriptor");

    socketManagerIptablesReleaseLease(&first_owner);
    require(socketManagerIptablesAcquireOwnerLease(token, &second_owner) == kSocketManagerIptablesLeaseAcquired,
            "owner lease should be reusable after release");
    socketManagerIptablesReleaseLease(&second_owner);
#endif
}

static void testInternalPlanningFailureIsAtomic(void)
{
#if defined(SOCKET_MANAGER_IPTABLES_ALLOC_FAILURE_TEST)
    char snapshot[2048];
    snprintf(snapshot, sizeof(snapshot), "-N WW2_ACACACACACACACAC_4\n");
    for (size_t i = 0; i < 15; ++i)
    {
        strcat(snapshot, "-A PREROUTING -j WW2_ACACACACACACACAC_4\n");
    }

    probe_state_t                          probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    socketManagerIptablesCleanupPlanInit(&plan);
    bool v4_ok               = true;
    bool v6_ok               = true;
    realloc_failure_min_size = 1024;
    require(! socketManagerIptablesBuildCleanupPlan(snapshot, true, "", true, fakeProbe, &probe, &plan, &v4_ok, &v6_ok),
            "injected planning allocation failure should be reported");
    require(! v4_ok && ! v6_ok, "internal planning failure must fail every included family");
    require(plan.count == 0 && plan.ops == NULL, "internal planning failure must discard the partial plan");
    socketManagerIptablesCleanupPlanDrop(&plan);
#endif
}

#if defined(__linux__)
// Wrapper-level coverage only: the generic deadline, process-group termination,
// SIGKILL escalation, output cap, and child-reaping mechanics live in
// wproc_deadline_test.c. What is manager-owned and tested here is the argv the
// inspection wrapper builds, the trailing-newline snapshot rule, and the correct
// transfer of the generic result's ownership and status into
// socket_manager_iptables_cmd_output_t.
enum
{
    kWrapperDeadlineMs   = 5000,
    kShortDeadlineMs     = 300,
    kTimeoutUpperBoundMs = 8000
};

static uint64_t monotonicMs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t) ts.tv_sec * 1000U) + ((uint64_t) ts.tv_nsec / 1000000U);
}

// Create an executable temporary script whose body is @p body. The chosen path
// is written into @p path_out (must be at least 64 bytes). Aborts on failure.
static void writeTempTool(char *path_out, size_t path_len, const char *body)
{
    snprintf(path_out, path_len, "/tmp/waterwall-iptables-test-XXXXXX");
    int fd = mkstemp(path_out);
    require(fd >= 0, "could not create fake tool");
    const size_t len = strlen(body);
    require(write(fd, body, len) == (ssize_t) len, "could not write fake tool");
    require(close(fd) == 0, "could not close fake tool");
    require(chmod(path_out, 0700) == 0, "could not make fake tool executable");
}

// A wrapper must never leave a child behind: after it returns, this process must
// have no reapable children left.
static void requireNoChildren(const char *message)
{
    errno = 0;
    require(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD, message);
}

static void testInspectBuildsTheExpectedArgv(void)
{
    char tool[64];
    // Echo the received arguments so the constructed argv can be asserted
    // exactly. A trailing newline keeps the snapshot complete.
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nprintf '%s\\n' \"$*\"\nexit 0\n");

    socket_manager_iptables_cmd_output_t out;
    require(socketManagerIptablesRunInspectCommand(tool, kWrapperDeadlineMs, &out),
            "the inspection wrapper must run the tool successfully");
    requireEqStr(out.output, "-w 5 -t nat -S\n", "inspection must execute `<tool> -w 5 -t nat -S`");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("a successful inspection left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testInspectSuccessAcceptsCompleteSnapshot(void)
{
    char tool[64];
    writeTempTool(tool,
                  sizeof(tool),
                  "#!/bin/sh\n"
                  "printf -- '-P PREROUTING ACCEPT\\n-N WW2_0123456789ABCDEF_4\\n'\n"
                  "exit 0\n");

    socket_manager_iptables_cmd_output_t out;
    require(socketManagerIptablesRunInspectCommand(tool, kWrapperDeadlineMs, &out),
            "a complete snapshot must be accepted");
    require(! out.timed_out, "a successful inspection must not be marked timed out");
    require(! out.spawn_failed && ! out.output_too_large && ! out.incomplete_final_line,
            "a successful inspection must have clean flags");
    require(out.exit_code == 0, "a successful inspection must record a zero exit code");
    require(out.output != NULL && strstr(out.output, "WW2_0123456789ABCDEF_4") != NULL,
            "the captured snapshot must contain the emitted chain declaration");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("a successful inspection left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testInspectRejectsIncompleteFinalLine(void)
{
    char tool[64];
    // A clean zero exit whose final captured byte is not a newline: the command
    // itself succeeded, but the snapshot is truncated and must be rejected.
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nprintf -- '-N WW2_0123456789ABCDEF_4'\nexit 0\n");

    socket_manager_iptables_cmd_output_t out;
    require(! socketManagerIptablesRunInspectCommand(tool, kWrapperDeadlineMs, &out),
            "an incomplete final inspection line must fail even after a clean exit");
    require(out.incomplete_final_line, "the truncated snapshot must be flagged");
    require(out.exit_code == 0, "the tool's clean exit code must still be recorded verbatim");
    require(! out.timed_out && ! out.spawn_failed, "a truncated snapshot is neither a timeout nor a spawn failure");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("a rejected snapshot left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testInspectRejectsEmptySnapshot(void)
{
    char tool[64];
    // A clean zero exit that printed nothing. `iptables -S -t nat` always emits
    // the built-in chain policies, so an empty capture means the output was lost
    // and must not be mistaken for an empty nat table.
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexit 0\n");

    socket_manager_iptables_cmd_output_t out;
    require(! socketManagerIptablesRunInspectCommand(tool, kWrapperDeadlineMs, &out),
            "an empty snapshot must be rejected even after a clean exit");
    require(out.len == 0, "the empty snapshot must be recorded as zero length");
    require(! out.incomplete_final_line, "an empty snapshot is not an incomplete final line");
    require(out.exit_code == 0, "the tool's clean exit code must still be recorded verbatim");
    require(! out.timed_out && ! out.spawn_failed, "an empty snapshot is neither a timeout nor a spawn failure");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("a rejected empty snapshot left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testShellCommandSucceedsWithoutTrailingNewline(void)
{
    // Mutation commands succeed on a clean zero exit; the trailing-newline
    // requirement is specific to inspection snapshots and must not reject them.
    socket_manager_iptables_cmd_output_t out;
    require(socketManagerIptablesRunShellCommand("printf 'no newline'", kWrapperDeadlineMs, &out),
            "a clean zero-exit shell command must succeed even without a trailing newline");
    require(out.exit_code == 0, "the shell command must record a zero exit code");
    require(out.incomplete_final_line, "the missing trailing newline must still be recorded in the result");
    require(! out.timed_out && ! out.spawn_failed, "a clean shell command must not report a timeout or spawn failure");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("a clean shell command left an unreaped child");
}

static void testNonzeroExitStatusIsTransferred(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nprintf -- 'partial\\n'\nexit 3\n");

    socket_manager_iptables_cmd_output_t out;
    require(! socketManagerIptablesRunInspectCommand(tool, kWrapperDeadlineMs, &out),
            "a nonzero exit must fail inspection");
    require(! out.timed_out, "a nonzero exit must not be reported as a timeout");
    require(! out.spawn_failed, "a nonzero exit is not a spawn failure");
    require(out.exit_code == 3, "the child's nonzero exit code must be transferred verbatim");
    requireEqStr(out.output, "partial\n", "the captured output must be transferred, not copied away");
    require(out.len == strlen("partial\n"), "the captured length must be transferred");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("a nonzero-exit inspection left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testTimeoutStatusIsTransferredAndDropIsIdempotent(void)
{
    char tool[64];
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec sleep 30\n");

    socket_manager_iptables_cmd_output_t out;
    const uint64_t                       start = monotonicMs();
    require(! socketManagerIptablesRunInspectCommand(tool, kShortDeadlineMs, &out),
            "a blocking tool must fail inspection");
    const uint64_t elapsed = monotonicMs() - start;
    require(out.timed_out, "the generic timeout status must be transferred to the manager result");
    require(! out.spawn_failed && ! out.output_too_large, "a timeout must not be confused with the other statuses");
    require(elapsed < kTimeoutUpperBoundMs, "the wrapper must honour the caller-provided deadline");

    socketManagerIptablesCmdOutputDrop(&out);
    require(out.output == NULL && out.len == 0, "drop must release and zero the captured output");
    require(! out.timed_out && ! out.spawn_failed && ! out.output_too_large && ! out.incomplete_final_line,
            "drop must clear every result flag, including timed_out");
    // A second drop on a now-zeroed result must be safe.
    socketManagerIptablesCmdOutputDrop(&out);
    require(out.output == NULL && out.len == 0, "a repeated drop must remain safe and idempotent");
    socketManagerIptablesCmdOutputDrop(NULL);

    requireNoChildren("a timed-out inspection left an unreaped child");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testOversizedOutputStatusIsTransferred(void)
{
    char tool[64];
    // yes(1) produces output far beyond the one-megabyte inspection cap.
    writeTempTool(tool, sizeof(tool), "#!/bin/sh\nexec yes WW2padding\n");

    socket_manager_iptables_cmd_output_t out;
    require(! socketManagerIptablesRunInspectCommand(tool, kWrapperDeadlineMs, &out),
            "oversized output must fail inspection");
    require(out.output_too_large, "the generic output_too_large status must be transferred");
    require(! out.timed_out, "oversized output is a size failure, not a timeout");
    require(out.len <= kSocketManagerIptablesInspectionMaxOutput,
            "the transferred capture must stay within the inspection cap");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("an oversized-output inspection left an unreaped producer");
    require(unlink(tool) == 0, "could not remove fake tool");
}

static void testSpawnFailureStatusIsTransferred(void)
{
    // A missing executable makes execvp fail in the child, which is reported as
    // exit status 127 rather than a parent-side spawn failure. A zero-length tool
    // name, in contrast, cannot even be resolved and must not be a timeout.
    socket_manager_iptables_cmd_output_t out;
    require(! socketManagerIptablesRunInspectCommand("waterwall-no-such-iptables", kWrapperDeadlineMs, &out),
            "a missing inspection tool must fail");
    require(out.exit_code == 127, "a failed execvp must surface as child exit status 127");
    require(! out.spawn_failed && ! out.timed_out, "a failed execvp is neither a spawn failure nor a timeout");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("a failed execvp left an unreaped child");
}

// The production deadline must stay strictly longer than the numeric xtables
// lock wait so a normal lock timeout can exit and be reaped without racing the
// supervisor, and it must be usable end to end by the production callers in
// socket_manager.c, which all pass kSocketManagerIptablesCommandTimeoutMs.
static void testProductionTimeoutConstantsAreUsable(void)
{
    require(kSocketManagerIptablesCommandTimeoutMs > kSocketManagerIptablesLockWaitSeconds * 1000,
            "the parent deadline must stay strictly longer than the numeric xtables wait");
    require(kSocketManagerIptablesTerminateGraceMs > 0, "the termination grace must be nonzero");

    socket_manager_iptables_cmd_output_t out;
    require(socketManagerIptablesRunShellCommand("exit 0", kSocketManagerIptablesCommandTimeoutMs, &out),
            "the production command deadline must run a trivial command successfully");
    require(out.exit_code == 0, "the production deadline must not alter a clean exit");
    socketManagerIptablesCmdOutputDrop(&out);
    requireNoChildren("the production-deadline check left an unreaped child");
}
#endif // defined(__linux__)

int main(void)
{
    testNameFormattingAndParsing();
    testStrictNameRejection();
    testLegacyNameParsing();
    testLegacyNameRejection();
    testOneStaleIpv4Chain();
    testPairedActiveTokenPreservesBothFamilies();
    testDuplicateJumpsAndOrphanChain();
    testUnexpectedReferencesBlockCandidate();
    testAllJumpAndGotoReferencesAreDetected();
    testIgnoresUnrelatedAndLookalikes();
    testCrossFamilyChainNameCollisionIsolated();
    testOverlongIpv6RuleContainedToFamily();
    testIncompleteSnapshotRejected();
    testLargeSnapshotBeyondOldFixedBuffer();
    testLeaseProbeErrorFailsFamily();
    testLinkedLegacyIpv4Blocks();
    testLinkedLegacyIpv6Blocks();
    testOrphanLegacyIgnored();
    testDuplicateLegacyJumps();
    testLegacyUnexpectedReferences();
    testLegacyBlockerCoexistsWithStaleV2();
    testLegacyBlockerAllocationFailureIsAtomic();
    testCleanupFailureOrdering();
    testLockAndOwnerLeaseContention();
    testInternalPlanningFailureIsAtomic();
#if defined(__linux__)
    testInspectBuildsTheExpectedArgv();
    testInspectSuccessAcceptsCompleteSnapshot();
    testInspectRejectsIncompleteFinalLine();
    testInspectRejectsEmptySnapshot();
    testShellCommandSucceedsWithoutTrailingNewline();
    testNonzeroExitStatusIsTransferred();
    testTimeoutStatusIsTransferredAndDropIsIdempotent();
    testOversizedOutputStatusIsTransferred();
    testSpawnFailureStatusIsTransferred();
    testProductionTimeoutConstantsAreUsable();
#endif

    printf("socket_manager_iptables_recovery_test: all tests passed\n");
    return 0;
}
