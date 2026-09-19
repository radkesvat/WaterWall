#pragma once

/*
 * Refcounted lifetime for device-reader messages queued to worker threads.
 */

#include "buffer_pool.h"
#include "devices/device_frag_affinity.h"
#include "master_pool.h"
#include "quiescence_gate.h"
#include "worker.h"

/*
 * Hands one packet to the packet chain. After this callback takes ownership,
 * the packet follows ordinary buffer lifecycle semantics.
 */
typedef void (*DeviceReaderDeliverFn)(void *device, sbuf_t *buf, wid_t wid);

typedef struct device_reader_session_s
{
    atomic_uint           refcount;
    atomic_uint           generation;
    atomic_bool           producer_admission;
    quiescence_gate_t     delivery_gate;
    master_pool_t        *message_pool;
    uint16_t              batch_capacity;
    void                 *device;
    DeviceReaderDeliverFn deliver;
    buffer_pool_t        *reader_buffer_pool;

    /* Reader-owned assembly/raw staging. The mutex serializes generation
     * transitions; only the reader (or the joined-reader lifecycle owner) may
     * access its pool and release retained storage. */
    device_frag_affinity_table_t *frag_affinity;
} device_reader_session_t;

device_reader_session_t *deviceReaderSessionCreate(uint32_t pool_capacity, uint16_t batch_capacity, void *device,
                                                   DeviceReaderDeliverFn deliver, buffer_pool_t *reader_buffer_pool,
                                                   device_fragment_policy_t policy);
void                     deviceReaderSessionRef(device_reader_session_t *session);
void                     deviceReaderSessionUnref(device_reader_session_t *session);

/*
 * Opens a new delivery generation after the previous reader producer was
 * joined. Generation zero is invalid; zero therefore reports exhaustion or
 * lifecycle misuse and leaves delivery closed.
 */
uint32_t deviceReaderSessionBegin(device_reader_session_t *session);
void     deviceReaderSessionEnd(device_reader_session_t *session);
void     deviceReaderSessionEndRequest(device_reader_session_t *session);
void     deviceReaderSessionEndWait(device_reader_session_t *session);

#ifdef DEVICE_READER_SESSION_TEST_HOOKS
/* Unit-only synchronization seam for deterministic EndWait race coverage. */
typedef void (*DeviceReaderSessionEndWaitYieldHook)(device_reader_session_t *session, void *context);
void deviceReaderSessionInstallEndWaitYieldHook(DeviceReaderSessionEndWaitYieldHook hook, void *context);
#endif

/*
 * Called after End and producer join, and after the reader pool's thread
 * ownership was reset, while that pool is still alive. It returns the staged
 * fragments End deliberately left in place - End runs on the lifecycle thread
 * while the reader still owns the pool, so it must not touch it - and keeps the
 * local poison state a reopened generation needs.
 */
void deviceReaderSessionRetireGenerationBuffers(device_reader_session_t *session);

/*
 * Called after End and producer join, while the device-owned reader pool is
 * still alive. It releases staged fragments and makes delayed final unref safe.
 */
void deviceReaderSessionRetireProducerBuffers(device_reader_session_t *session);

/*
 * Takes ownership of all `count` buffers. Invalid batch sizes are logged and
 * returned to the reader pool instead of overflowing the message allocation.
 * The posting thread must already own a live session reference. A queued
 * message acquires an additional reference and keeps it through delivery or
 * cleanup.
 */
bool deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count);
