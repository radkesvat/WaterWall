#pragma once

/*
 * Device-neutral lifetime primitives for short, non-blocking I/O hot paths.
 */

#include "loggers/internal_logger.h"
#include "master_pool.h"
#include "watomic.h"
#include "wmutex.h"

typedef struct device_lifetime_gate_s
{
    atomic_bool active;
    atomic_uint in_flight;
} device_lifetime_gate_t;

typedef void (*DeviceLifetimeYieldFn)(void *context);

enum
{
    kDeviceLifetimeGateWarningWaitMs          = 2000,
    kDeviceLifetimeGateWarningCheckYieldCount = 256,
    kDeviceLifetimeTrackedGatesPerThread      = 4
};

typedef struct device_lifetime_thread_entry_s
{
    device_lifetime_gate_t *gate;
    unsigned int            depth;
} device_lifetime_thread_entry_t;

typedef struct device_lifetime_thread_entries_s
{
    device_lifetime_thread_entry_t entries[kDeviceLifetimeTrackedGatesPerThread];
    unsigned int                   overflow_depth;
} device_lifetime_thread_entries_t;

/*
 * Track successful entries per thread so an accidental self-quiesce can fail
 * open instead of hanging terminal shutdown forever.
 */
extern thread_local device_lifetime_thread_entries_t device_lifetime_thread_entries;

static inline void deviceLifetimeTrackThreadEnter(device_lifetime_gate_t *gate)
{
    device_lifetime_thread_entry_t *free_entry = NULL;
    for (unsigned int i = 0; i < kDeviceLifetimeTrackedGatesPerThread; i++)
    {
        device_lifetime_thread_entry_t *entry = &device_lifetime_thread_entries.entries[i];
        if (entry->gate == gate)
        {
            entry->depth++;
            return;
        }
        if (entry->gate == NULL && free_entry == NULL)
        {
            free_entry = entry;
        }
    }

    if (free_entry != NULL)
    {
        free_entry->gate  = gate;
        free_entry->depth = 1;
        return;
    }

    /*
     * Real device paths nest at most the delivery and writer gates. Conservatively
     * treat an unexpectedly deeper nesting as self-owned during quiesce.
     */
    device_lifetime_thread_entries.overflow_depth++;
}

static inline void deviceLifetimeTrackThreadLeave(device_lifetime_gate_t *gate)
{
    for (unsigned int i = 0; i < kDeviceLifetimeTrackedGatesPerThread; i++)
    {
        device_lifetime_thread_entry_t *entry = &device_lifetime_thread_entries.entries[i];
        if (entry->gate != gate)
        {
            continue;
        }

        assert(entry->depth > 0);
        entry->depth--;
        if (entry->depth == 0)
        {
            entry->gate = NULL;
        }
        return;
    }

    assert(device_lifetime_thread_entries.overflow_depth > 0);
    if (device_lifetime_thread_entries.overflow_depth > 0)
    {
        device_lifetime_thread_entries.overflow_depth--;
    }
}

static inline bool deviceLifetimeThreadIsInsideGate(const device_lifetime_gate_t *gate)
{
    if (device_lifetime_thread_entries.overflow_depth > 0)
    {
        return true;
    }

    for (unsigned int i = 0; i < kDeviceLifetimeTrackedGatesPerThread; i++)
    {
        const device_lifetime_thread_entry_t *entry = &device_lifetime_thread_entries.entries[i];
        if (entry->gate == gate)
        {
            return true;
        }
    }
    return false;
}

static inline void deviceLifetimeGateInit(device_lifetime_gate_t *gate)
{
    atomicStoreRelaxed(&gate->active, false);
    atomicStoreRelaxed(&gate->in_flight, 0);
}

static inline void deviceLifetimeGateOpen(device_lifetime_gate_t *gate)
{
    /*
     * A closed-gate probe may have incremented in_flight but not yet observed
     * active=false. Publishing a new generation is safe once its resources are
     * installed; that probe either rejects the old generation or joins the new one.
     */
    atomicStoreExplicit(&gate->active, true, memory_order_release);
}

static inline bool deviceLifetimeGateEnter(device_lifetime_gate_t *gate)
{
    unsigned int previous = atomicAddExplicit(&gate->in_flight, 1, memory_order_acq_rel);
    assert(previous != UINT_MAX);
    discard previous;

    if (UNLIKELY(! atomicLoadExplicit(&gate->active, memory_order_acquire)))
    {
        unsigned int entered = atomicSubExplicit(&gate->in_flight, 1, memory_order_release);
        assert(entered > 0);
        discard entered;
        return false;
    }

    deviceLifetimeTrackThreadEnter(gate);
    return true;
}

static inline void deviceLifetimeGateLeave(device_lifetime_gate_t *gate)
{
    deviceLifetimeTrackThreadLeave(gate);
    unsigned int entered = atomicSubExplicit(&gate->in_flight, 1, memory_order_release);
    assert(entered > 0);
    discard entered;
}

static inline bool deviceLifetimeGateIsActive(const device_lifetime_gate_t *gate)
{
    return atomicLoadExplicit(&gate->active, memory_order_acquire);
}

static inline void deviceLifetimeYieldThread(void *context)
{
    discard context;

    YIELD_CPU();
#ifdef OS_WIN
    static thread_local unsigned int windows_yield_count;
    windows_yield_count++;
    if (windows_yield_count % 64 == 0)
    {
        SwitchToThread();
    }
#else
    YIELD_THREAD();
#endif
}

static inline void deviceLifetimeGateCloseAndQuiesce(device_lifetime_gate_t *gate, DeviceLifetimeYieldFn yield_fn,
                                                     void *yield_context)
{
    assert(yield_fn != NULL);

    atomicStoreExplicit(&gate->active, false, memory_order_seq_cst);

    if (UNLIKELY(deviceLifetimeThreadIsInsideGate(gate)))
    {
        /*
         * Current device callers reach self-quiesce only through the
         * _Noreturn terminateProgram() shutdown path, so the guarded callback
         * cannot resume after teardown. A recoverable self-quiesce must not
         * free protected state after taking this fail-open branch.
         */
        LOGE("Device lifetime gate quiesce was requested from inside the guarded region; skipping the wait to avoid "
             "self-deadlock");
        return;
    }

    unsigned int wait_started_at = getTickMS();
    unsigned int yields          = 0;
    bool         warned          = false;
    for (;;)
    {
        unsigned int in_flight = atomicLoadExplicit(&gate->in_flight, memory_order_acquire);
        if (in_flight == 0)
        {
            return;
        }

        yield_fn(yield_context);
        yields++;
        if (! warned && yields % kDeviceLifetimeGateWarningCheckYieldCount == 0 &&
            getTickMS() - wait_started_at >= kDeviceLifetimeGateWarningWaitMs)
        {
            LOGW("Device lifetime gate is still waiting for %u in-flight operation(s)", in_flight);
            warned = true;
        }
    }
}

typedef struct device_reader_session_s
{
    atomic_uint            refcount;
    atomic_uint            generation;
    device_lifetime_gate_t delivery_gate;
    master_pool_t         *message_pool;
} device_reader_session_t;

typedef void (*DeviceReaderSessionDestroyHook)(device_reader_session_t *session, void *context);

static inline device_reader_session_t *deviceReaderSessionCreate(uint32_t                    message_pool_capacity,
                                                                 MasterPoolItemCreateHandle  create_item_handle,
                                                                 MasterPoolItemDestroyHandle destroy_item_handle)
{
    device_reader_session_t *session = memoryAllocate(sizeof(*session));
    *session                         = (device_reader_session_t) {
                                .refcount     = 1,
                                .generation   = 0,
                                .message_pool = masterpoolCreateWithCapacity(message_pool_capacity),
    };
    deviceLifetimeGateInit(&session->delivery_gate);
    masterpoolInstallCallBacks(session->message_pool, create_item_handle, destroy_item_handle);
    return session;
}

static inline void deviceReaderSessionRef(device_reader_session_t *session)
{
    unsigned int previous = atomicAddExplicit(&session->refcount, 1, memory_order_relaxed);
    assert(previous > 0 && previous != UINT_MAX);
    discard previous;
}

static inline void deviceReaderSessionDestroy(device_reader_session_t *session)
{
    masterpoolMakeEmpty(session->message_pool);
    masterpoolDestroy(session->message_pool);
    memoryFree(session);
}

/*
 * A non-NULL destroy hook owns the final destruction of both the session and
 * its message pool. Tests use this to verify last-reference behavior.
 */
static inline void deviceReaderSessionUnref(device_reader_session_t       *session,
                                            DeviceReaderSessionDestroyHook destroy_hook, void *destroy_context)
{
    unsigned int previous = atomicSubExplicit(&session->refcount, 1, memory_order_acq_rel);
    assert(previous > 0);
    if (previous != 1)
    {
        return;
    }

    if (destroy_hook != NULL)
    {
        destroy_hook(session, destroy_context);
        return;
    }

    deviceReaderSessionDestroy(session);
}

static inline uint32_t deviceReaderSessionBegin(device_reader_session_t *session)
{
    uint32_t generation = (uint32_t) atomicAddExplicit(&session->generation, 1, memory_order_acq_rel) + UINT32_C(1);
    deviceLifetimeGateOpen(&session->delivery_gate);
    return generation;
}

static inline uint32_t deviceReaderSessionGeneration(const device_reader_session_t *session)
{
    return (uint32_t) atomicLoadExplicit(&session->generation, memory_order_acquire);
}

static inline bool deviceReaderSessionMatchesGeneration(const device_reader_session_t *session, uint32_t generation)
{
    return generation == deviceReaderSessionGeneration(session);
}
