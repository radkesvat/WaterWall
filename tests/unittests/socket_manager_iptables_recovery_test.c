#include "managers/socket_manager_iptables_recovery.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(SOCKET_MANAGER_IPTABLES_ALLOC_FAILURE_TEST)
static bool   fail_next_allocation     = false;
static size_t realloc_failure_min_size = SIZE_MAX;

void *__real_memoryAllocate(size_t size);
void *__wrap_memoryAllocate(size_t size);
void *__real_memoryReAllocate(void *ptr, size_t size);
void *__wrap_memoryReAllocate(void *ptr, size_t size);

void *__wrap_memoryAllocate(size_t size)
{
    if (fail_next_allocation)
    {
        fail_next_allocation = false;
        return NULL;
    }
    return __real_memoryAllocate(size);
}

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
    size_t                                    call_count;
    size_t                                    fail_call;
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
    *held_fd = -1;
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
    const size_t call = state->call_count++;
    state->actions[call] = op->action;
    return call != state->fail_call;
}

static void testNameFormattingAndParsing(void)
{
    char chain[32];
    require(socketManagerIptablesFormatChainName(0x0123456789ABCDEFULL, 4, chain, sizeof(chain)),
            "format v4 chain failed");
    requireEqStr(chain, "WW2_0123456789ABCDEF_4", "v4 chain format mismatch");

    uint64_t token = 0;
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
    static const char *const invalid[] = {
        "WW_00000001_00000002_4",
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

static void requirePlan(const char *v4, bool include_v4, const char *v6, bool include_v6,
                        probe_state_t *probe, socket_manager_iptables_cleanup_plan_t *plan,
                        bool expected_result, bool expected_v4, bool expected_v6)
{
    bool v4_ok = false;
    bool v6_ok = false;
    socketManagerIptablesCleanupPlanInit(plan);
    bool result = socketManagerIptablesBuildCleanupPlan(v4, include_v4, v6, include_v6, fakeProbe, probe, plan,
                                                        &v4_ok, &v6_ok);
    require(result == expected_result, "cleanup plan result mismatch");
    require(v4_ok == expected_v4, "cleanup plan v4 result mismatch");
    require(v6_ok == expected_v6, "cleanup plan v6 result mismatch");
}

static void testOneStaleIpv4Chain(void)
{
    const char *snapshot = "-P PREROUTING ACCEPT\n"
                           "-N WW2_0123456789ABCDEF_4\n"
                           "-A PREROUTING -j WW2_0123456789ABCDEF_4\n";
    probe_state_t probe = {0};
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
    const char *v4 = "-N WW2_1111111111111111_4\n-A PREROUTING -j WW2_1111111111111111_4\n";
    const char *v6 = "-N WW2_1111111111111111_6\n-A PREROUTING -j WW2_1111111111111111_6\n";
    probe_state_t probe = {.active_tokens = {0x1111111111111111ULL}, .active_count = 1};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(v4, true, v6, true, &probe, &plan, true, true, true);
    require(probe.seen_count == 1, "paired token should use one liveness decision");
    require(plan.count == 0, "active owner must preserve both chains");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testDuplicateJumpsAndOrphanChain(void)
{
    const char *snapshot = "-N WW2_2222222222222222_4\n"
                           "-A PREROUTING -j WW2_2222222222222222_4\n"
                           "-A PREROUTING -j WW2_2222222222222222_4\n"
                           "-N WW2_3333333333333333_4\n";
    probe_state_t probe = {0};
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
    const char *snapshot = "-N WW2_4444444444444444_4\n"
                           "-A PREROUTING -p TCP -j WW2_4444444444444444_4\n"
                           "-N WW2_5555555555555555_4\n"
                           "-A OTHER -j WW2_5555555555555555_4\n";
    probe_state_t probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(plan.count == 0, "unexpected references must not schedule cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testAllJumpAndGotoReferencesAreDetected(void)
{
    const char *snapshot = "-N WW2_1010101010101010_4\n"
                           "-N WW2_2020202020202020_4\n"
                           "-N WW2_3030303030303030_4\n"
                           "-N WW2_4040404040404040_4\n"
                           "-A OTHER --jump WW2_1010101010101010_4\n"
                           "-A OTHER -g WW2_2020202020202020_4\n"
                           "-A OTHER --goto WW2_3030303030303030_4\n"
                           "-A PREROUTING --jump WW2_4040404040404040_4\n";
    probe_state_t probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(probe.seen_count == 4, "each referenced owner should be probed");
    require(plan.count == 0, "non-exact jump and goto references must block cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testIgnoresUnrelatedAndLookalikes(void)
{
    const char *snapshot = "-N WW_00000001_00000002_4\n"
                           "-N WW2_6666666666666666_6\n"
                           "-A PREROUTING -j WW2_6666666666666666_6\n"
                           "-A PREROUTING -m comment --comment WW2_7777777777777777_4 -j ACCEPT\n"
                           "-A PREROUTING -j WW2_8888888888888888_4_SUFFIX\n";
    probe_state_t probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, true, true, true);
    require(probe.seen_count == 0, "legacy or wrong-family chains must be ignored");
    require(plan.count == 0, "unrelated chains must not be scheduled");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testIncompleteSnapshotRejected(void)
{
    const char *snapshot = "-N WW2_9999999999999999_4\n-A PREROUTING -j WW2_9999999999999999_4";
    probe_state_t probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(plan.count == 0, "incomplete snapshot must not schedule cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testLargeSnapshotBeyondOldFixedBuffer(void)
{
    const size_t filler_lines = 260;
    const char  *tail = "-N WW2_AAAAAAAAAAAAAAAA_4\n-A PREROUTING -j WW2_AAAAAAAAAAAAAAAA_4\n";
    size_t       cap  = filler_lines * 48U + strlen(tail) + 1U;
    char        *snapshot = malloc(cap);
    require(snapshot != NULL, "malloc failed");
    snapshot[0] = '\0';
    for (size_t i = 0; i < filler_lines; ++i)
    {
        strcat(snapshot, "-A PREROUTING -j ACCEPT\n");
    }
    strcat(snapshot, tail);
    require(strlen(snapshot) > 2048, "test snapshot should exceed old fixed buffer");

    probe_state_t probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, true, true, true);
    require(plan.count == 3, "large complete snapshot should be parsed fully");
    socketManagerIptablesCleanupPlanDrop(&plan);
    free(snapshot);
}

static void testLeaseProbeErrorFailsFamily(void)
{
    const char *snapshot = "-N WW2_ABABABABABABABAB_4\n";
    probe_state_t probe = {.error_tokens = {0xABABABABABABABABULL}, .error_count = 1};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(snapshot, true, NULL, false, &probe, &plan, false, false, true);
    require(plan.count == 0, "unknown ownership must not schedule cleanup");
    socketManagerIptablesCleanupPlanDrop(&plan);
}

static void testCleanupFailureOrdering(void)
{
    const char *duplicate_snapshot = "-N WW2_CDCDCDCDCDCDCDCD_4\n"
                                     "-A PREROUTING -j WW2_CDCDCDCDCDCDCDCD_4\n"
                                     "-A PREROUTING -j WW2_CDCDCDCDCDCDCDCD_4\n";
    probe_state_t probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    requirePlan(duplicate_snapshot, true, NULL, false, &probe, &plan, true, true, true);

    cleanup_runner_state_t jump_failure = {.fail_call = 0};
    bool                   v4_ok = true;
    bool                   v6_ok = true;
    require(! socketManagerIptablesExecuteCleanupPlan(
                &plan, fakeCleanupRunner, &jump_failure, &v4_ok, &v6_ok),
            "jump deletion failure should fail cleanup");
    require(jump_failure.call_count == 2, "all jump deletions should be attempted before stopping the chain");
    require(jump_failure.actions[0] == kSocketManagerIptablesCleanupDeleteJump &&
                jump_failure.actions[1] == kSocketManagerIptablesCleanupDeleteJump,
            "flush and delete must be skipped after a jump deletion failure");
    require(! v4_ok && v6_ok, "jump deletion failure should fail only its family");

    cleanup_runner_state_t retry = {.fail_call = SIZE_MAX};
    v4_ok = true;
    v6_ok = true;
    require(socketManagerIptablesExecuteCleanupPlan(&plan, fakeCleanupRunner, &retry, &v4_ok, &v6_ok),
            "a later cleanup attempt should be able to retry the complete chain plan");
    require(retry.call_count == 4 && retry.actions[2] == kSocketManagerIptablesCleanupFlushChain &&
                retry.actions[3] == kSocketManagerIptablesCleanupDeleteChain,
            "retry did not run both unlink operations before flush and delete");
    require(v4_ok && v6_ok, "successful retry should preserve family reconciliation state");
    socketManagerIptablesCleanupPlanDrop(&plan);

    const char *single_snapshot = "-N WW2_EFEFEFEFEFEFEFEF_4\n"
                                  "-A PREROUTING -j WW2_EFEFEFEFEFEFEFEF_4\n";
    probe = (probe_state_t) {0};
    requirePlan(single_snapshot, true, NULL, false, &probe, &plan, true, true, true);
    cleanup_runner_state_t flush_failure = {.fail_call = 1};
    v4_ok = true;
    v6_ok = true;
    require(! socketManagerIptablesExecuteCleanupPlan(
                &plan, fakeCleanupRunner, &flush_failure, &v4_ok, &v6_ok),
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
    int first_lock = -1;
    int second_lock = -1;
    require(socketManagerIptablesAcquireReconcileLock(&first_lock, 0), "could not acquire reconciliation lock");
    require(! socketManagerIptablesAcquireReconcileLock(&second_lock, 0),
            "contending reconciliation lock should time out");
    socketManagerIptablesReleaseLease(&first_lock);
    require(socketManagerIptablesAcquireReconcileLock(&second_lock, 0),
            "reconciliation lock should be reusable after release");
    socketManagerIptablesReleaseLease(&second_lock);

    const uint64_t token = 0xF0E1D2C3B4A59687ULL;
    int            first_owner = -1;
    int            second_owner = -1;
    require(socketManagerIptablesAcquireOwnerLease(token, &first_owner) == kSocketManagerIptablesLeaseAcquired,
            "could not acquire owner lease");
    require(socketManagerIptablesAcquireOwnerLease(token, &second_owner) == kSocketManagerIptablesLeaseInUse,
            "contending owner lease should report active ownership");
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

    probe_state_t probe = {0};
    socket_manager_iptables_cleanup_plan_t plan;
    socketManagerIptablesCleanupPlanInit(&plan);
    bool v4_ok = true;
    bool v6_ok = true;
    realloc_failure_min_size = 1024;
    require(! socketManagerIptablesBuildCleanupPlan(
                snapshot, true, "", true, fakeProbe, &probe, &plan, &v4_ok, &v6_ok),
            "injected planning allocation failure should be reported");
    require(! v4_ok && ! v6_ok, "internal planning failure must fail every included family");
    require(plan.count == 0 && plan.ops == NULL, "internal planning failure must discard the partial plan");
    socketManagerIptablesCleanupPlanDrop(&plan);
#endif
}

static void testInspectAllocationFailureReapsChild(void)
{
#if defined(__linux__) && defined(SOCKET_MANAGER_IPTABLES_ALLOC_FAILURE_TEST)
    char tool_path[] = "/tmp/waterwall-inspect-test-XXXXXX";
    int  tool_fd     = mkstemp(tool_path);
    require(tool_fd >= 0, "could not create fake inspection tool");
    const char script[] = "#!/bin/sh\nexec sleep 30\n";
    require(write(tool_fd, script, sizeof(script) - 1U) == (ssize_t) (sizeof(script) - 1U),
            "could not write fake inspection tool");
    require(close(tool_fd) == 0, "could not close fake inspection tool");
    require(chmod(tool_path, 0700) == 0, "could not make fake inspection tool executable");

    socket_manager_iptables_cmd_output_t output;
    fail_next_allocation = true;
    require(! socketManagerIptablesRunInspectCommand(tool_path, &output),
            "inspection should fail when output allocation fails");
    require(output.spawn_failed, "inspection allocation failure should be reported");

    errno = 0;
    require(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD,
            "inspection allocation failure left an unreaped child");
    socketManagerIptablesCmdOutputDrop(&output);
    require(unlink(tool_path) == 0, "could not remove fake inspection tool");
#endif
}

int main(void)
{
    testNameFormattingAndParsing();
    testStrictNameRejection();
    testOneStaleIpv4Chain();
    testPairedActiveTokenPreservesBothFamilies();
    testDuplicateJumpsAndOrphanChain();
    testUnexpectedReferencesBlockCandidate();
    testAllJumpAndGotoReferencesAreDetected();
    testIgnoresUnrelatedAndLookalikes();
    testIncompleteSnapshotRejected();
    testLargeSnapshotBeyondOldFixedBuffer();
    testLeaseProbeErrorFailsFamily();
    testCleanupFailureOrdering();
    testLockAndOwnerLeaseContention();
    testInternalPlanningFailureIsAtomic();
    testInspectAllocationFailureReapsChild();

    printf("socket_manager_iptables_recovery_test: all tests passed\n");
    return 0;
}
