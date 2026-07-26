#include "device_lifetime.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct quiesce_probe_s
{
    device_lifetime_gate_t *gate;
    unsigned int            yields;
    unsigned int            leave_on_yield;
} quiesce_probe_t;

typedef struct destroy_probe_s
{
    unsigned int calls;
} destroy_probe_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static master_pool_item_t *createTestPoolItem(void *userdata)
{
    discard userdata;
    return memoryAllocate(1);
}

static void destroyTestPoolItem(master_pool_item_t *item)
{
    memoryFree(item);
}

static void probeYield(void *context)
{
    quiesce_probe_t *probe = context;
    probe->yields++;
    if (probe->yields == probe->leave_on_yield)
    {
        unsigned int entered = atomicSubExplicit(&probe->gate->in_flight, 1, memory_order_release);
        require(entered == 1, "remote-entry probe did not release the final operation");
    }
}

static void failIfYielded(void *context)
{
    unsigned int *calls = context;
    (*calls)++;
}

static void probeSessionDestroy(device_reader_session_t *session, void *context)
{
    destroy_probe_t *probe = context;
    probe->calls++;
    deviceReaderSessionDestroy(session);
}

static device_reader_session_t *createTestSession(void)
{
    return deviceReaderSessionCreate(4, createTestPoolItem, destroyTestPoolItem);
}

static void testGateOpenEnterAndClose(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);

    require(! deviceLifetimeGateIsActive(&gate), "a new gate was active");
    require(! deviceLifetimeGateEnter(&gate), "enter succeeded on a closed gate");

    deviceLifetimeGateOpen(&gate);
    require(deviceLifetimeGateIsActive(&gate), "opening the gate did not publish it");
    require(deviceLifetimeGateEnter(&gate), "enter failed on an open gate");
    deviceLifetimeGateLeave(&gate);

    deviceLifetimeGateCloseAndQuiesce(&gate, deviceLifetimeYieldThread, NULL);
    require(! deviceLifetimeGateEnter(&gate), "enter succeeded after close");
}

static void testCloseWaitsForLastLeave(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);
    deviceLifetimeGateOpen(&gate);
    atomicStoreExplicit(&gate.in_flight, 1, memory_order_release);

    quiesce_probe_t probe = {
        .gate           = &gate,
        .leave_on_yield = 3,
    };
    deviceLifetimeGateCloseAndQuiesce(&gate, probeYield, &probe);

    require(probe.yields == probe.leave_on_yield, "quiesce returned before the last leave");
    require(atomicLoadExplicit(&gate.in_flight, memory_order_acquire) == 0, "quiesce left an in-flight operation");
}

static void testSelfQuiesceDoesNotDeadlock(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);
    deviceLifetimeGateOpen(&gate);
    require(deviceLifetimeGateEnter(&gate), "failed to establish a same-thread operation");

    unsigned int yields = 0;
    deviceLifetimeGateCloseAndQuiesce(&gate, failIfYielded, &yields);
    require(yields == 0, "same-thread quiesce tried to wait for itself");
    require(! deviceLifetimeGateIsActive(&gate), "same-thread quiesce left the gate open");
    require(atomicLoadExplicit(&gate.in_flight, memory_order_acquire) == 1,
            "same-thread quiesce changed the guarded operation count");

    deviceLifetimeGateLeave(&gate);
}

static void testClosedQuiesceIsNoOp(void)
{
    device_lifetime_gate_t gate;
    deviceLifetimeGateInit(&gate);

    unsigned int yields = 0;
    deviceLifetimeGateCloseAndQuiesce(&gate, failIfYielded, &yields);
    deviceLifetimeGateCloseAndQuiesce(&gate, failIfYielded, &yields);
    require(yields == 0, "an already-closed gate yielded");
}

static void testSessionReferenceLifetime(void)
{
    device_reader_session_t *session = createTestSession();
    destroy_probe_t          probe   = {0};

    deviceReaderSessionRef(session);
    deviceReaderSessionRef(session);
    deviceReaderSessionRef(session);

    deviceReaderSessionUnref(session, probeSessionDestroy, &probe);
    deviceReaderSessionUnref(session, probeSessionDestroy, &probe);
    require(probe.calls == 0, "the session was destroyed before its last reference");
    deviceReaderSessionUnref(session, probeSessionDestroy, &probe);
    require(probe.calls == 0, "message-first release destroyed the device reference");
    deviceReaderSessionUnref(session, probeSessionDestroy, &probe);
    require(probe.calls == 1, "the final release did not destroy the session exactly once");

    session = createTestSession();
    probe   = (destroy_probe_t) {0};
    deviceReaderSessionRef(session);
    deviceReaderSessionUnref(session, probeSessionDestroy, &probe);
    require(probe.calls == 0, "device-first release destroyed a live message session");
    deviceReaderSessionUnref(session, probeSessionDestroy, &probe);
    require(probe.calls == 1, "message release did not destroy a device-released session");
}

static void testSessionGenerationRejectsStaleStamp(void)
{
    device_reader_session_t *session = createTestSession();

    uint32_t first_generation = deviceReaderSessionBegin(session);
    require(deviceReaderSessionMatchesGeneration(session, first_generation),
            "the current generation did not match its stamp");

    deviceLifetimeGateCloseAndQuiesce(&session->delivery_gate, deviceLifetimeYieldThread, NULL);
    uint32_t second_generation = deviceReaderSessionBegin(session);
    require(second_generation != first_generation, "beginning a new session did not advance the generation");
    require(! deviceReaderSessionMatchesGeneration(session, first_generation),
            "a stale message stamp matched the new session");

    deviceLifetimeGateCloseAndQuiesce(&session->delivery_gate, deviceLifetimeYieldThread, NULL);
    deviceReaderSessionUnref(session, NULL, NULL);
}

int main(void)
{
    testGateOpenEnterAndClose();
    testCloseWaitsForLastLeave();
    testSelfQuiesceDoesNotDeadlock();
    testClosedQuiesceIsNoOp();
    testSessionReferenceLifetime();
    testSessionGenerationRejectsStaleStamp();
    puts("device lifetime tests passed");
    return 0;
}
