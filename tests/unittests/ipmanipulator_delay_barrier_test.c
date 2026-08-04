#include "IpManipulator/structure.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kCapturedCapacity = kIpManipulatorDelayBarrierMaxPackets + 4
};

static uint8_t  captured_ids[kCapturedCapacity];
static uint32_t captured_count;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

/* helpers.c references these owner hooks; delay-barrier tests do not use them. */
void echsnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                   uint16_t dst_port, uint64_t generation)
{
    discard t;
    discard src_addr;
    discard dst_addr;
    discard src_port;
    discard dst_port;
    discard generation;
}

void smugglesnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                       uint16_t dst_port)
{
    discard t;
    discard src_addr;
    discard dst_addr;
    discard src_port;
    discard dst_port;
}

static void capturePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;

    require(captured_count < kCapturedCapacity, "delay-barrier capture overflow");
    require(sbufGetLength(buf) >= 1U, "delay-barrier packet became empty");
    captured_ids[captured_count++] = *(const uint8_t *) sbufGetRawPtr(buf);
    sbufDestroy(buf);
}

static sbuf_t *makePacket(uint8_t id)
{
    sbuf_t *buf = sbufCreate(1);

    sbufSetLength(buf, 1);
    *sbufGetMutablePtr(buf) = id;
    return buf;
}

static ipmanipulator_flow_table_t *tableForKind(ipmanipulator_tstate_t *state, ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        return &state->first_sni_table;
    case kIpManipulatorDelayBarrierSmuggleSni:
        return &state->smuggle_table;
    case kIpManipulatorDelayBarrierOverlapSni:
        return &state->overlap_table;
    default:
        return NULL;
    }
}

static ipmanipulator_delay_barrier_t *barrierForRecord(void *record, ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        return &((ipmanipulator_firstsni_flow_t *) record)->delay_barrier;
    case kIpManipulatorDelayBarrierSmuggleSni:
        return &((ipmanipulator_smuggle_flow_t *) record)->delay_barrier;
    case kIpManipulatorDelayBarrierOverlapSni:
        return &((ipmanipulator_overlap_flow_t *) record)->delay_barrier;
    default:
        return NULL;
    }
}

static uint32_t recordSizeForKind(ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        return sizeof(ipmanipulator_firstsni_flow_t);
    case kIpManipulatorDelayBarrierSmuggleSni:
        return sizeof(ipmanipulator_smuggle_flow_t);
    case kIpManipulatorDelayBarrierOverlapSni:
        return sizeof(ipmanipulator_overlap_flow_t);
    default:
        return 0;
    }
}

static void destroyBarrierRecord(void *record, void *context)
{
    ipmanipulator_delay_barrier_kind_e kind = (ipmanipulator_delay_barrier_kind_e) (uintptr_t) context;

    ipmanipulatorDelayBarrierDestroy(barrierForRecord(record, kind));
}

static void initializeTable(ipmanipulator_tstate_t *state, ipmanipulator_delay_barrier_kind_e kind)
{
    ipmanipulator_flow_table_t *table = tableForKind(state, kind);

    require(ipmanipulatorFlowTableInit(table,
                                       "delay-barrier-unit",
                                       kIpManipulatorFlowLimitMin,
                                       1,
                                       recordSizeForKind(kind),
                                       destroyBarrierRecord,
                                       (void *) (uintptr_t) kind),
            "failed to initialize delay-barrier flow table");
}

static ipmanipulator_flow_entry_t *reserveEntry(ipmanipulator_tstate_t *state, ipmanipulator_delay_barrier_kind_e kind,
                                                const ipmanipulator_flow_key_t *key)
{
    ipmanipulator_flow_table_t *table = tableForKind(state, kind);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(table, key);
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardReserve(table, shard, key, 0, UINT64_MAX);

    ipmanipulatorFlowShardUnlock(shard);
    require(entry != NULL, "failed to reserve delay-barrier flow entry");
    return entry;
}

static ipmanipulator_delay_barrier_t *findBarrierLocked(ipmanipulator_tstate_t            *state,
                                                        ipmanipulator_delay_barrier_kind_e kind,
                                                        const ipmanipulator_flow_key_t    *key,
                                                        ipmanipulator_flow_shard_t       **out_shard)
{
    ipmanipulator_flow_table_t *table = tableForKind(state, kind);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(table, key);
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(table, shard, key);

    require(entry != NULL, "delay-barrier flow entry disappeared");
    *out_shard = shard;
    return barrierForRecord(ipmanipulatorFlowEntryRecord(entry), kind);
}

static void removeEntry(ipmanipulator_tstate_t *state, ipmanipulator_delay_barrier_kind_e kind,
                        const ipmanipulator_flow_key_t *key)
{
    ipmanipulator_flow_table_t *table = tableForKind(state, kind);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(table, key);
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(table, shard, key);

    require(entry != NULL, "delay-barrier entry was missing before removal");
    ipmanipulatorFlowShardRemove(table, shard, entry);
    ipmanipulatorFlowShardUnlock(shard);
}

static void testKind(ipmanipulator_delay_barrier_kind_e kind)
{
    tunnel_t *t    = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    tunnel_t  next = {.fnPayloadU = capturePacket};
    line_t    line = {0};

    require(t != NULL, "failed to allocate delay-barrier tunnel");
    t->tstate_size = sizeof(ipmanipulator_tstate_t);
    t->next        = &next;

    atomicStoreRelaxed(&line.refc, 1);
    line.alive = true;
    line.wid   = 0;

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_proto_swap_tcp_number = -1;
    state->trick_proto_swap_udp_number = -1;
    atomicStoreU64Relaxed(&state->delay_barrier_next_generation, 0);
    initializeTable(state, kind);

    ipmanipulator_flow_key_t key = ipmanipulatorFlowKeyMake(0x0A000001U, 40000, 0x0A000002U, 443);
    discard                  reserveEntry(state, kind, &key);

    ipmanipulator_flow_shard_t    *shard   = NULL;
    ipmanipulator_delay_barrier_t *barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 100);
    uint64_t generation     = barrier->generation;
    bool     needs_schedule = false;

    line_t foreign_line = {0};
    atomicStoreRelaxed(&foreign_line.refc, 1);
    foreign_line.alive = true;
    foreign_line.wid   = 1;

    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(250), false, &needs_schedule),
            "owner-worker FIFO packet was not retained");
    sbuf_t *foreign_packet = makePacket(251);
    require(! ipmanipulatorDelayBarrierTryEnqueue(barrier, &foreign_line, foreign_packet, false, &needs_schedule),
            "mixed-worker FIFO packet was retained");
    require(barrier->owner_wid == 0, "delay barrier did not stamp its first packet owner");
    sbufDestroy(foreign_packet);

    ipmanipulator_delay_batch_t ownership_batch = {0};
    ipmanipulatorDelayBarrierTake(barrier, &ownership_batch);
    captured_count = 0;
    require(ipmanipulatorDelayBatchSendUpstream(t, &ownership_batch),
            "owner-worker FIFO fail-open unexpectedly killed the line");
    require(captured_count == 1 && captured_ids[0] == 250, "owner-worker FIFO release changed its packet set");

    ipmanipulatorDelayBarrierInitialize(state, barrier, 100);
    ipmanipulator_ordered_output_t mixed_outputs[] = {
        {.line = &line, .buf = makePacket(252), .send = capturePacket, .due_ms = 100},
        {.line = &foreign_line, .buf = makePacket(253), .send = capturePacket, .due_ms = 100},
    };
    require(! ipmanipulatorDelayBarrierInstallOrdered(barrier, mixed_outputs, 2, &needs_schedule),
            "mixed-worker ordered outputs were installed");
    require(barrier->owner_wid == kInvalidWID, "rejected ordered outputs changed the barrier owner");
    sbufDestroy(mixed_outputs[0].buf);
    sbufDestroy(mixed_outputs[1].buf);
    generation = barrier->generation;

    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(1), false, &needs_schedule) &&
                needs_schedule,
            "first FIFO packet did not arm the one release action");
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(2), false, &needs_schedule) &&
                ! needs_schedule,
            "second FIFO packet armed a duplicate release action");
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(3), true, &needs_schedule),
            "terminal FIFO packet was not retained");
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    ipmanipulatorDelayBarrierTestSetNow(100);
    ipmanipulatorDelayBarrierTestFire(t, &key, kind, generation);
    require(captured_count == 3 && captured_ids[0] == 1 && captured_ids[1] == 2 && captured_ids[2] == 3,
            "deadline release did not preserve FIFO/terminal order");
    require(ipmanipulatorFlowTableCount(tableForKind(state, kind)) == 0,
            "terminal FIFO release did not remove the flow");
    require(atomicLoadRelaxed(&line.refc) == 1, "deadline release leaked retained line references");

    /* Reusing the exact tuple must allocate a generation no stale timer can match. */
    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 200);
    uint64_t old_generation = barrier->generation;
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(4), false, &needs_schedule),
            "old tuple generation could not retain a packet");
    ipmanipulatorFlowShardUnlock(shard);
    removeEntry(state, kind, &key);
    require(atomicLoadRelaxed(&line.refc) == 1, "tuple removal leaked its retained line reference");

    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 200);
    uint64_t new_generation = barrier->generation;
    require(new_generation != old_generation, "tuple reuse repeated a delay-barrier generation");
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(5), false, &needs_schedule),
            "new tuple generation could not retain a packet");
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    ipmanipulatorDelayBarrierTestSetNow(200);
    ipmanipulatorDelayBarrierTestFire(t, &key, kind, old_generation);
    require(captured_count == 0, "stale tuple timer released a newer flow");
    ipmanipulatorDelayBarrierTestFire(t, &key, kind, new_generation);
    require(captured_count == 1 && captured_ids[0] == 5, "current tuple timer did not release its packet");

    /* One overdue callback must drain transcript outputs in explicit logical
     * order before it releases the barrier FIFO. This exercises the same timer
     * runner used in production instead of manually taking the barrier. */
    removeEntry(state, kind, &key);
    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 500);
    ipmanipulator_ordered_output_t ordered_outputs[] = {
        {.line = &line, .buf = makePacket(30), .send = capturePacket, .due_ms = 400},
        {.line = &line, .buf = makePacket(31), .send = capturePacket, .due_ms = 500},
    };
    require(ipmanipulatorDelayBarrierInstallOrdered(barrier, ordered_outputs, 2, &needs_schedule) && needs_schedule,
            "ordered transcript did not arm its single scheduler");
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(32), false, &needs_schedule) &&
                ! needs_schedule,
            "barrier tail armed a timer independent from its transcript scheduler");
    generation = barrier->generation;
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    ipmanipulatorDelayBarrierTestSetNow(600);
    ipmanipulatorDelayBarrierTestFire(t, &key, kind, generation);
    require(captured_count == 3 && captured_ids[0] == 30 && captured_ids[1] == 31 && captured_ids[2] == 32,
            "overdue ordered scheduler released the barrier before earlier transcript outputs");
    require(atomicLoadRelaxed(&line.refc) == 1, "ordered transcript release leaked retained line references");

    /* A schedule rejected before acceptance must flush the complete barrier. */
    removeEntry(state, kind, &key);
    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 800);
    ipmanipulator_ordered_output_t rejected_outputs[] = {
        {.line = &line, .buf = makePacket(40), .send = capturePacket, .due_ms = 700},
        {.line = &line, .buf = makePacket(41), .send = capturePacket, .due_ms = 750},
    };
    require(ipmanipulatorDelayBarrierInstallOrdered(barrier, rejected_outputs, 2, &needs_schedule) && needs_schedule,
            "rejected-schedule fixture did not arm its scheduler");
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(42), false, &needs_schedule) &&
                ! needs_schedule,
            "rejected-schedule fixture did not retain its FIFO tail");
    generation = barrier->generation;
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    ipmanipulatorDelayBarrierTestSetScheduleFailure(true);
    require(! ipmanipulatorDelayBarrierSchedule(t, &key, kind, generation, 0, 1),
            "forced delay-barrier scheduling failure reported success");
    ipmanipulatorDelayBarrierFailOpen(t, &key, kind, generation);
    ipmanipulatorDelayBarrierTestSetScheduleFailure(false);
    require(captured_count == 3 && captured_ids[0] == 40 && captured_ids[1] == 41 && captured_ids[2] == 42,
            "rejected delay-barrier scheduling did not flush in order");
    require(atomicLoadRelaxed(&line.refc) == 1, "rejected delay-barrier scheduling leaked line references");

    /* A failed self-reschedule flushes all outputs that are not due yet. */
    removeEntry(state, kind, &key);
    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 900);
    ipmanipulator_ordered_output_t reschedule_outputs[] = {
        {.line = &line, .buf = makePacket(50), .send = capturePacket, .due_ms = 800},
        {.line = &line, .buf = makePacket(51), .send = capturePacket, .due_ms = 850},
    };
    require(ipmanipulatorDelayBarrierInstallOrdered(barrier, reschedule_outputs, 2, &needs_schedule) && needs_schedule,
            "reschedule-failure fixture did not arm its scheduler");
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(52), false, &needs_schedule) &&
                ! needs_schedule,
            "reschedule-failure fixture did not retain its FIFO tail");
    generation = barrier->generation;
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    ipmanipulatorDelayBarrierTestSetNow(800);
    ipmanipulatorDelayBarrierTestSetScheduleFailure(true);
    ipmanipulatorDelayBarrierTestFire(t, &key, kind, generation);
    ipmanipulatorDelayBarrierTestSetScheduleFailure(false);
    require(captured_count == 3 && captured_ids[0] == 50 && captured_ids[1] == 51 && captured_ids[2] == 52,
            "failed delay-barrier self-reschedule did not flush the remainder in order");
    require(atomicLoadRelaxed(&line.refc) == 1, "failed self-reschedule leaked line references");

    /* Model packet A immediately before the deadline and packet B arriving
     * after it while the timer callback is still pending. The call sites take
     * and send the older batch before they forward the current packet. */
    removeEntry(state, kind, &key);
    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 250);
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(6), false, &needs_schedule),
            "pre-deadline packet A was not retained");
    ipmanipulatorFlowShardUnlock(shard);

    ipmanipulatorDelayBarrierTestSetNow(251);
    barrier                                    = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulator_delay_batch_t deadline_batch = {0};
    ipmanipulatorDelayBarrierTake(barrier, &deadline_batch);
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    require(ipmanipulatorDelayBatchSendUpstream(t, &deadline_batch),
            "late-timer boundary release unexpectedly killed the line");
    capturePacket(&next, &line, makePacket(7));
    require(captured_count == 2 && captured_ids[0] == 6 && captured_ids[1] == 7,
            "a post-deadline packet overtook the older pending FIFO packet");

    /* Capacity failure opens in order: detach older entries, then send current. */
    removeEntry(state, kind, &key);
    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 300);
    for (uint8_t id = 0; id < kIpManipulatorDelayBarrierMaxPackets; ++id)
    {
        require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(id), false, &needs_schedule),
                "FIFO filled before the packet-count bound");
    }

    sbuf_t *current = makePacket(kIpManipulatorDelayBarrierMaxPackets);
    require(! ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, current, false, &needs_schedule),
            "FIFO accepted a packet past its count bound");
    ipmanipulator_delay_batch_t batch = {0};
    ipmanipulatorDelayBarrierTake(barrier, &batch);
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    require(ipmanipulatorDelayBatchSendUpstream(t, &batch), "ordered fail-open unexpectedly killed the line");
    capturePacket(&next, &line, current);
    require(captured_count == kIpManipulatorDelayBarrierMaxPackets + 1U,
            "ordered fail-open emitted the wrong packet count");
    for (uint8_t id = 0; id <= kIpManipulatorDelayBarrierMaxPackets; ++id)
    {
        require(captured_ids[id] == id, "ordered fail-open changed FIFO order");
    }

    removeEntry(state, kind, &key);

    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 350);
    sbuf_t *too_large = sbufCreate(kIpManipulatorDelayBarrierMaxBytes + 1U);
    sbufSetLength(too_large, kIpManipulatorDelayBarrierMaxBytes + 1U);
    require(! ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, too_large, false, &needs_schedule),
            "FIFO accepted a packet past its retained-byte bound");
    require(barrier->count == 0 && barrier->retained_bytes == 0, "retained-byte rejection partially mutated the FIFO");
    ipmanipulatorFlowShardUnlock(shard);
    sbufDestroy(too_large);
    removeEntry(state, kind, &key);

    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 375);
    sbuf_t *byte_limit_packet = sbufCreate(kIpManipulatorDelayBarrierMaxBytes);
    sbufSetLength(byte_limit_packet, kIpManipulatorDelayBarrierMaxBytes);
    *(uint8_t *) sbufGetMutablePtr(byte_limit_packet) = 20;
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, byte_limit_packet, false, &needs_schedule),
            "FIFO rejected a packet at its retained-byte bound");
    current = makePacket(21);
    require(! ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, current, false, &needs_schedule),
            "FIFO accepted a packet past its retained-byte bound");
    memoryZero(&batch, sizeof(batch));
    ipmanipulatorDelayBarrierTake(barrier, &batch);
    ipmanipulatorFlowShardUnlock(shard);

    captured_count = 0;
    require(ipmanipulatorDelayBatchSendUpstream(t, &batch),
            "byte-bound ordered fail-open unexpectedly killed the line");
    capturePacket(&next, &line, current);
    require(captured_count == 2 && captured_ids[0] == 20 && captured_ids[1] == 21,
            "byte-bound fail-open changed FIFO order");
    removeEntry(state, kind, &key);

    /* Destruction of an armed barrier must recycle every buffer and unlock its line. */
    discard reserveEntry(state, kind, &key);
    barrier = findBarrierLocked(state, kind, &key, &shard);
    ipmanipulatorDelayBarrierInitialize(state, barrier, 400);
    require(ipmanipulatorDelayBarrierTryEnqueue(barrier, &line, makePacket(9), false, &needs_schedule),
            "destruction fixture could not retain a packet");
    ipmanipulatorFlowShardUnlock(shard);
    require(atomicLoadRelaxed(&line.refc) == 2, "armed barrier did not retain its line");
    ipmanipulatorFlowTableDestroy(tableForKind(state, kind));
    require(atomicLoadRelaxed(&line.refc) == 1, "flow-table destruction leaked an armed barrier reference");

    memoryFreeAligned(t);
}

int main(void)
{
    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");

    GSTATE.workers_count = 2; // one ordinary event worker plus the lwIP slot
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);

    testKind(kIpManipulatorDelayBarrierFirstSni);
    testKind(kIpManipulatorDelayBarrierSmuggleSni);
    testKind(kIpManipulatorDelayBarrierOverlapSni);

    testWorkerUnbindWID();
    testWorkerRegistryRestore(&g_test_worker_registry);
    GSTATE.workers_count = 0;

    globalstateDestroySecureRandom();
    return 0;
}
