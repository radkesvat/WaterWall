/* VMess AuthID/session replay admission: inclusive timestamp boundaries, future
 * timestamps, rollback, atomic refusal, bounded capacity, expiration and four
 * simultaneous callers. Uses explicit clocks; never sleeps or changes host time.
 * CTest: waterwall.vmess_replay_unit (Debug and Release). */
#include "VmessServer/replay.h"

#include "test_assert.h"

#include <pthread.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef struct replay_input_s
{
    uint8_t auth[16], uuid[16], key[16], iv[16];
} replay_input_t;

static replay_input_t input(unsigned auth, unsigned session)
{
    replay_input_t result = {.uuid = {0x31}, .iv = {0x53}};
    memoryCopy(result.auth, &auth, sizeof(auth));
    memoryCopy(result.key, &session, sizeof(session));
    return result;
}

static bool admit(vmess_replay_t *table, replay_input_t value, uint64_t timestamp, uint64_t wall, uint64_t mono)
{
    return vmessReplayAdmit(table, value.auth, value.uuid, value.key, value.iv, timestamp, wall, mono);
}

static void timestampBoundaries(void)
{
    const uint64_t timestamps[] = {879, 880, 1000, 1120, 1121, UINT64_MAX};
    const bool     accepted[]   = {false, true, true, true, false, false};
    for (size_t i = 0; i < ARRAY_SIZE(timestamps); ++i)
    {
        vmess_replay_t *table = vmessReplayCreate(4);
        require(admit(table, input(1, 1), timestamps[i], 1000, 1000) == accepted[i],
                "timestamp acceptance differs from the inclusive 120-second window");
        vmessReplayDestroy(table);
    }
    vmess_replay_t *table = vmessReplayCreate(4);
    require(! admit(table, input(1, 1), 1000, 1000, UINT64_MAX), "monotonic expiry overflow accepted");
    require(admit(table, input(1, 1), 1000, 1000, 1000), "overflow refusal published a replay mark");
    vmessReplayDestroy(table);
}

static void duplicateAdmissionIsAtomic(void)
{
    vmess_replay_t *table = vmessReplayCreate(8);
    require(admit(table, input(1, 1), 1000, 1000, 1000), "initial admission failed");
    require(! admit(table, input(1, 2), 1000, 1000, 1000), "same AuthID with changed session accepted");
    require(admit(table, input(2, 2), 1000, 1000, 1000), "AuthID refusal polluted the session table");
    require(! admit(table, input(3, 1), 1000, 1000, 1000), "same session with changed AuthID accepted");
    require(admit(table, input(3, 3), 1000, 1000, 1000), "session refusal polluted the AuthID table");
    replay_input_t other_user = input(4, 1);
    other_user.uuid[15]       = 1;
    require(admit(table, other_user, 1000, 1000, 1000), "session identity omitted the full UUID");
    replay_input_t other_iv = input(5, 1);
    other_iv.iv[15]         = 1;
    require(admit(table, other_iv, 1000, 1000, 1000), "session identity omitted the full IV");
    vmessReplayDestroy(table);
}

static void futureTimestampRetention(void)
{
    vmess_replay_t *table = vmessReplayCreate(8);
    require(admit(table, input(1, 1), 1120, 1000, 10000), "future boundary was rejected");
    require(! admit(table, input(1, 2), 1120, 1121, 131000), "AuthID forgotten after only 120 seconds");
    require(! admit(table, input(1, 3), 1120, 1240, 250000), "AuthID forgotten at inclusive old boundary");
    require(! admit(table, input(1, 4), 1120, 1241, 251000), "expired AuthID timestamp was accepted");
    require(admit(table, input(2, 1), 1241, 1241, 251000), "expired session mark prevented a fresh request");
    vmessReplayDestroy(table);
}

static void rollbackCannotResurrectReplay(void)
{
    vmess_replay_t *table = vmessReplayCreate(4);
    require(admit(table, input(1, 1), 1000, 1000, 1000), "first admission failed");
    require(admit(table, input(2, 2), 1300, 1300, 301000), "forward clock admission failed");
    require(! admit(table, input(1, 1), 1000, 1000, 302000), "wall-clock rollback resurrected a purged request");
    require(! admit(table, input(3, 3), 1000, 1000, 303000), "rollback admitted an expired timestamp under a new ID");
    require(admit(table, input(3, 3), 1300, 1300, 304000), "refusal prevented admission after clock recovery");
    vmessReplayDestroy(table);
}

static void capacityAndExpiry(void)
{
    vmess_replay_t *table = vmessReplayCreate(2);
    require(admit(table, input(1, 1), 1000, 1000, 1000), "first capacity slot failed");
    require(admit(table, input(2, 2), 1120, 1000, 1000), "second capacity slot failed");
    require(! admit(table, input(3, 3), 1000, 1000, 1000), "live capacity overflow accepted");
    require(! admit(table, input(1, 4), 1000, 1000, 1000), "capacity overflow evicted an AuthID");
    require(! admit(table, input(4, 2), 1000, 1000, 1000), "capacity overflow evicted a session");
    require(! admit(table, input(3, 3), 1121, 1121, 122000), "expired AuthID bypassed full live session table");
    require(admit(table, input(3, 3), 1180, 1180, 181000), "exact session expiry did not release capacity");
    require(! admit(table, input(2, 4), 1120, 1180, 181000), "session expiry evicted a still-valid AuthID");
    vmessReplayDestroy(table);
}

enum
{
    kCallers = 4,
    kRounds  = 32
};

typedef struct concurrent_call_s
{
    vmess_replay_t    *table;
    pthread_barrier_t *barrier;
    unsigned           wins[kRounds];
} concurrent_call_t;

static void *concurrentAdmit(void *context)
{
    concurrent_call_t *call = context;
    for (unsigned i = 0; i < kRounds; ++i)
    {
        int result = pthread_barrier_wait(call->barrier);
        require(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "concurrent admission barrier failed");
        call->wins[i] = admit(call->table, input(i + 1, i + 1), 1000, 1000, 1000) ? 1 : 0;
    }
    return NULL;
}

static void concurrentOneWinner(void)
{
    vmess_replay_t   *table = vmessReplayCreate(kRounds);
    pthread_barrier_t barrier;
    require(pthread_barrier_init(&barrier, NULL, kCallers) == 0, "barrier initialization failed");
    pthread_t         threads[kCallers];
    concurrent_call_t calls[kCallers] = {0};
    for (unsigned i = 0; i < kCallers; ++i)
    {
        calls[i].table   = table;
        calls[i].barrier = &barrier;
        require(pthread_create(&threads[i], NULL, concurrentAdmit, &calls[i]) == 0, "caller thread creation failed");
    }
    for (unsigned i = 0; i < kCallers; ++i)
        require(pthread_join(threads[i], NULL) == 0, "caller thread join failed");
    for (unsigned round = 0; round < kRounds; ++round)
    {
        unsigned winners = 0;
        for (unsigned i = 0; i < kCallers; ++i)
            winners += calls[i].wins[round];
        require(winners == 1, "simultaneous duplicate admission did not have exactly one winner");
    }
    require(pthread_barrier_destroy(&barrier) == 0, "barrier destruction failed");
    vmessReplayDestroy(table);
}

int main(void)
{
    initWLibc();
    require(globalstateInitializeSecureRandom(), "secure random initialization failed");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();
    TEST_RUN_CASE(timestampBoundaries);
    TEST_RUN_CASE(duplicateAdmissionIsAtomic);
    TEST_RUN_CASE(futureTimestampRetention);
    TEST_RUN_CASE(rollbackCannotResurrectReplay);
    TEST_RUN_CASE(capacityAndExpiry);
    TEST_RUN_CASE(concurrentOneWinner);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
