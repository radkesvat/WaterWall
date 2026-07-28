#pragma once

/*
 * Refcounted lifetime for device-reader messages queued to worker threads.
 */

#include "buffer_pool.h"
#include "devices/device_lifetime.h"
#include "master_pool.h"
#include "worker.h"

typedef void (*DeviceReaderDeliverFn)(void *device, sbuf_t *buf, wid_t wid);

typedef struct device_reader_session_s
{
    atomic_uint            refcount;
    atomic_uint            generation;
    device_lifetime_gate_t delivery_gate;
    master_pool_t         *message_pool;
    uint16_t               batch_capacity;
    void                  *device;
    DeviceReaderDeliverFn  deliver;
    buffer_pool_t         *reader_buffer_pool;
} device_reader_session_t;

device_reader_session_t *deviceReaderSessionCreate(uint32_t pool_capacity, uint16_t batch_capacity, void *device,
                                                   DeviceReaderDeliverFn deliver, buffer_pool_t *reader_buffer_pool);
void                     deviceReaderSessionRef(device_reader_session_t *session);
void                     deviceReaderSessionUnref(device_reader_session_t *session);

/*
 * Opens a new delivery generation after the previous reader producer was
 * joined. Generation zero is invalid; zero therefore reports exhaustion or
 * lifecycle misuse and leaves delivery closed.
 */
uint32_t deviceReaderSessionBegin(device_reader_session_t *session);
void     deviceReaderSessionEnd(device_reader_session_t *session);
uint32_t deviceReaderSessionGeneration(const device_reader_session_t *session);
bool     deviceReaderSessionMatchesGeneration(const device_reader_session_t *session, uint32_t generation);

/*
 * Takes ownership of all `count` buffers. Invalid batch sizes are logged and
 * returned to the reader pool instead of overflowing the message allocation.
 * The posting thread must already own a live session reference. A queued
 * message acquires an additional reference and keeps it through delivery or
 * cleanup.
 */
void deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count);

/*
 * Worker-message callbacks are public test seams. Production callers should
 * post through deviceReaderSessionPost().
 */
void deviceReaderSessionMessageReceived(void *worker, void *arg1, void *arg2, void *arg3);
void deviceReaderSessionCleanupPostedMessage(void *arg1, void *arg2, void *arg3);
