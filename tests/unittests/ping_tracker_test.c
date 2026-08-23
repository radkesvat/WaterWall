#include "PingCommon/ping_wire.h"
#include "wwapi.h"

#include <pthread.h>

enum
{
    kStressThreads    = 2,
    kStressIterations = 4096,
};

static atomic_uint g_sync_init_calls;
static atomic_uint g_sync_resources_acquired;
static atomic_uint g_sync_resources_destroyed;
static atomic_uint g_sync_fail_call;

bool wSyncInitTestShouldFail(void)
{
    const uint32_t call = atomicAdd(&g_sync_init_calls, 1U) + 1U;
    return call == atomicLoadRelaxed(&g_sync_fail_call);
}

void wSyncInitTestResourceAcquired(void)
{
    discard atomicAdd(&g_sync_resources_acquired, 1U);
}

void wSyncInitTestResourceDestroyed(void)
{
    discard atomicAdd(&g_sync_resources_destroyed, 1U);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "ping_tracker_test: %s\n", message);
        exit(1);
    }
}

static void resetSyncSeam(uint32_t fail_call)
{
    atomicStoreRelaxed(&g_sync_init_calls, 0);
    atomicStoreRelaxed(&g_sync_resources_acquired, 0);
    atomicStoreRelaxed(&g_sync_resources_destroyed, 0);
    atomicStoreRelaxed(&g_sync_fail_call, fail_call);
}

static void testConstructionFailureCleanup(void)
{
    resetSyncSeam(1);
    require(pingwireTrackerCreate() == NULL, "tracker accepted first-mutex construction failure");
    require(atomicLoadRelaxed(&g_sync_resources_acquired) == 0,
            "first-mutex failure acquired a synchronization resource");
    require(atomicLoadRelaxed(&g_sync_resources_destroyed) == 0,
            "first-mutex failure destroyed an uninitialized synchronization resource");

    resetSyncSeam(2);
    require(pingwireTrackerCreate() == NULL, "tracker accepted second-mutex construction failure");
    require(atomicLoadRelaxed(&g_sync_resources_acquired) == 1,
            "second-mutex failure did not acquire exactly the first resource");
    require(atomicLoadRelaxed(&g_sync_resources_destroyed) == 1,
            "second-mutex failure did not destroy exactly the first resource");

    resetSyncSeam(0);
    ping_wire_tracker_t *tracker = pingwireTrackerCreate();
    require(tracker != NULL, "tracker construction failed without injection");
    require(atomicLoadRelaxed(&g_sync_resources_acquired) == 2,
            "successful tracker construction did not acquire two resources");
    pingwireTrackerDestroy(tracker);
    require(atomicLoadRelaxed(&g_sync_resources_destroyed) == 2,
            "successful tracker destruction did not release two resources");
}

static void fillDigestKey(uint8_t key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE])
{
    for (uint32_t i = 0; i < WCRYPTO_BLAKE2S_MAX_KEY_SIZE; ++i)
    {
        key[i] = (uint8_t) (0x80U + i);
    }
}

static ping_wire_envelope_t makeEnvelope(uint8_t type, uint16_t identifier, uint16_t sequence, const uint8_t *payload,
                                         uint16_t payload_length)
{
    return (ping_wire_envelope_t) {
        .icmp_payload        = payload,
        .source_ipv4         = UINT32_C(0x0200000a),
        .destination_ipv4    = UINT32_C(0x0100000a),
        .icmp_payload_length = payload_length,
        .identifier          = identifier,
        .sequence            = sequence,
        .type                = type,
        .code                = 0,
    };
}

static void testBoundedReplacementAndSequenceReuse(void)
{
    uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE];
    fillDigestKey(digest_key);

    ping_wire_tracker_t *tracker = pingwireTrackerCreate();
    require(tracker != NULL, "replacement tracker construction failed");

    uint8_t payload[4] = {1, 2, 3, 4};
    for (uint32_t i = 0; i <= kPingWireOutstandingCapacity; ++i)
    {
        payload[0] = (uint8_t) i;
        require(pingwireOutstandingRecord(tracker,
                                          digest_key,
                                          7,
                                          (uint16_t) i,
                                          UINT32_C(0x0200000a),
                                          UINT32_C(0x0100000a),
                                          payload,
                                          sizeof(payload)),
                "outstanding replacement record failed");
    }

    const uint8_t        evicted_payload[4] = {0, 2, 3, 4};
    ping_wire_envelope_t evicted            = makeEnvelope(ICMP_ER, 7, 0, evicted_payload, sizeof(evicted_payload));
    require(! pingwireOutstandingConsume(tracker, digest_key, &evicted),
            "oldest outstanding entry survived bounded replacement");

    require(pingwireOutstandingRecord(tracker,
                                      digest_key,
                                      7,
                                      0,
                                      UINT32_C(0x0200000a),
                                      UINT32_C(0x0100000a),
                                      evicted_payload,
                                      sizeof(evicted_payload)),
            "sequence reuse after eviction could not be recorded");
    require(pingwireOutstandingConsume(tracker, digest_key, &evicted),
            "new sequence generation after eviction was not consumable");
    require(! pingwireOutstandingConsume(tracker, digest_key, &evicted), "one reply consumed more than once");

    require(pingwireOutstandingRecord(tracker,
                                      digest_key,
                                      7,
                                      0,
                                      UINT32_C(0x0200000a),
                                      UINT32_C(0x0100000a),
                                      evicted_payload,
                                      sizeof(evicted_payload)) &&
                pingwireOutstandingRecord(tracker,
                                          digest_key,
                                          7,
                                          0,
                                          UINT32_C(0x0200000a),
                                          UINT32_C(0x0100000a),
                                          evicted_payload,
                                          sizeof(evicted_payload)),
            "repeated exact outstanding registration failed");
    require(pingwireOutstandingConsume(tracker, digest_key, &evicted),
            "newest repeated outstanding registration was not consumable");
    require(! pingwireOutstandingConsume(tracker, digest_key, &evicted),
            "one reply consumed an older repeated registration");

    uint8_t              replay_payload[4] = {0, 5, 6, 7};
    ping_wire_envelope_t replay            = makeEnvelope(ICMP_ECHO, 9, 0, replay_payload, sizeof(replay_payload));
    require(pingwireReplayMark(tracker, digest_key, &replay) == kPingWireReplayNew, "first replay record was not new");
    require(pingwireReplayMark(tracker, digest_key, &replay) == kPingWireReplayDuplicate,
            "immediate replay was not detected");

    for (uint32_t i = 1; i <= kPingWireReplayCapacity; ++i)
    {
        replay_payload[0] = (uint8_t) i;
        replay.sequence   = (uint16_t) i;
        require(pingwireReplayMark(tracker, digest_key, &replay) == kPingWireReplayNew,
                "replay replacement record failed");
    }

    replay_payload[0] = 0;
    replay.sequence   = 0;
    require(pingwireReplayMark(tracker, digest_key, &replay) == kPingWireReplayNew,
            "evicted replay identity remained suppressed");

    pingwireTrackerDestroy(tracker);
    memorySecureZero(digest_key, sizeof(digest_key));
}

typedef struct stress_state_s
{
    ping_wire_tracker_t *tracker;
    uint8_t              digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE];
    atomic_uint          ready[kStressThreads];
    atomic_uint          done[kStressThreads];
    atomic_bool          failed;
} stress_state_t;

typedef struct stress_thread_s
{
    stress_state_t *state;
    uint32_t        index;
} stress_thread_t;

static bool waitForAtLeast(stress_state_t *state, atomic_uint *value, uint32_t expected)
{
    while (atomicLoadExplicit(value, memory_order_acquire) < expected)
    {
        if (atomicLoadExplicit(&state->failed, memory_order_acquire))
        {
            return false;
        }
        YIELD_CPU();
    }
    return true;
}

static void *stressThread(void *argument)
{
    stress_thread_t *thread = argument;
    stress_state_t  *state  = thread->state;
    const uint32_t   self   = thread->index;
    const uint32_t   peer   = 1U - self;

    for (uint32_t iteration = 0; iteration < kStressIterations; ++iteration)
    {
        uint8_t payload[16];
        for (uint32_t i = 0; i < sizeof(payload); ++i)
        {
            payload[i] = (uint8_t) (iteration * 17U + self * 53U + i);
        }

        const uint16_t identifier = (uint16_t) (0x4000U + self);
        const uint16_t sequence   = (uint16_t) (iteration * 2U + self);
        if (! pingwireOutstandingRecord(state->tracker,
                                        state->digest_key,
                                        identifier,
                                        sequence,
                                        UINT32_C(0x0200000a),
                                        UINT32_C(0x0100000a),
                                        payload,
                                        sizeof(payload)))
        {
            atomicStoreExplicit(&state->failed, true, memory_order_release);
            return NULL;
        }

        atomicStoreExplicit(&state->ready[self], iteration + 1U, memory_order_release);
        if (! waitForAtLeast(state, &state->ready[peer], iteration + 1U))
        {
            return NULL;
        }

        uint8_t peer_payload[16];
        for (uint32_t i = 0; i < sizeof(peer_payload); ++i)
        {
            peer_payload[i] = (uint8_t) (iteration * 17U + peer * 53U + i);
        }
        ping_wire_envelope_t reply = makeEnvelope(ICMP_ER,
                                                  (uint16_t) (0x4000U + peer),
                                                  (uint16_t) (iteration * 2U + peer),
                                                  peer_payload,
                                                  sizeof(peer_payload));
        if (! pingwireOutstandingConsume(state->tracker, state->digest_key, &reply) ||
            pingwireOutstandingConsume(state->tracker, state->digest_key, &reply))
        {
            atomicStoreExplicit(&state->failed, true, memory_order_release);
            return NULL;
        }

        atomicStoreExplicit(&state->done[self], iteration + 1U, memory_order_release);
        if (! waitForAtLeast(state, &state->done[peer], iteration + 1U))
        {
            return NULL;
        }
    }

    return NULL;
}

static void testCrossThreadRecordConsumeStress(void)
{
    resetSyncSeam(0);

    stress_state_t state;
    memoryZero(&state, sizeof(state));
    atomic_init(&state.failed, false);
    for (uint32_t i = 0; i < kStressThreads; ++i)
    {
        atomic_init(&state.ready[i], 0);
        atomic_init(&state.done[i], 0);
    }
    fillDigestKey(state.digest_key);
    state.tracker = pingwireTrackerCreate();
    require(state.tracker != NULL, "stress tracker construction failed");

    pthread_t       threads[kStressThreads];
    stress_thread_t arguments[kStressThreads];
    for (uint32_t i = 0; i < kStressThreads; ++i)
    {
        arguments[i] = (stress_thread_t) {.state = &state, .index = i};
        require(pthread_create(&threads[i], NULL, stressThread, &arguments[i]) == 0,
                "failed to create tracker stress thread");
    }
    for (uint32_t i = 0; i < kStressThreads; ++i)
    {
        require(pthread_join(threads[i], NULL) == 0, "failed to join tracker stress thread");
    }

    require(! atomicLoadExplicit(&state.failed, memory_order_acquire),
            "cross-thread tracker stress lost or double-consumed a request");
    pingwireTrackerDestroy(state.tracker);
    require(atomicLoadRelaxed(&g_sync_resources_acquired) == atomicLoadRelaxed(&g_sync_resources_destroyed),
            "stress tracker leaked synchronization resources");
    memorySecureZero(&state, sizeof(state));
}

int main(void)
{
    initWLibc();
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto initialization failed");

    testConstructionFailureCleanup();
    testBoundedReplacementAndSequenceReuse();
    testCrossThreadRecordConsumeStress();

    wCryptoGlobalCleanup();
    puts("ping_tracker_test: all cases passed");
    return 0;
}
