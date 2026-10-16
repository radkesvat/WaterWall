#pragma once

#include "shiftbuffer.h"
#include "watomic.h"
#include "worker.h"

enum
{
    kRawWriterQueueMax     = 128 * 1024,
    kRawWriterBatchPackets = 512
};

typedef struct raw_writer_generation_s raw_writer_generation_t;
typedef struct raw_writer_lane_s       raw_writer_lane_t;

/* Lifecycle operations are serialized by the device owner. Producers keep the
 * writer live until TrySend returns. Destroy requires producer quiescence;
 * already accepted worker tokens retain their generation independently. */
typedef struct raw_writer_s
{
    atomic_uintptr_t         published_generation;
    raw_writer_generation_t *current;
    raw_writer_generation_t *retired;
} raw_writer_t;

typedef enum raw_writer_send_result_e
{
    kRawWriterSendOk = 0,
    kRawWriterSendDown,
    kRawWriterSendClosed,
    kRawWriterSendFull
} raw_writer_send_result_t;

typedef enum raw_writer_batch_status_e
{
    kRawWriterBatchContinue = 0,
    kRawWriterBatchBlocked,
    kRawWriterBatchFailed
} raw_writer_batch_status_t;

typedef struct raw_writer_batch_result_s
{
    size_t                    consumed;
    raw_writer_batch_status_t status;
} raw_writer_batch_result_t;

/* Owner-worker callback. Consume/recycle exactly the returned prefix; the
 * writer retains the suffix ahead of newer packets. Bound native attempts,
 * returning Continue to yield even when repeated EINTR prevented progress.
 * Do not pump an event loop, reenter output, or stop/destroy this writer.
 * Blocked can retain a native borrow of the first unconsumed buffer when the
 * external-notification mode is selected. Failed must leave no native borrow
 * of this callback's remaining suffix, and reports an orderly fatal failure. */
typedef raw_writer_batch_result_t (*raw_writer_batch_fn)(void *context, worker_t *worker, raw_writer_lane_t *lane,
                                                         sbuf_t **buffers, size_t count);

/* Runs on the lifecycle coordinator after all admitted operations have ended,
 * before any retained buffer is destroyed. Cancel/complete native borrows and
 * quiesce external notification roots here. Never access worker-local pools or
 * event-loop state. NULL is valid for synchronous native backends. */
typedef void (*raw_writer_stop_fn)(void *context, wid_t wid);

void rawWriterInit(raw_writer_t *writer);
/* retry_delay_ms > 0: one timed retry after Blocked; zero: backend calls Notify
 * once when the outstanding native operation is ready for owner completion. */
bool rawWriterOpen(raw_writer_t *writer, size_t packet_limit, uint32_t retry_delay_ms, void *context,
                   raw_writer_batch_fn write_batch, raw_writer_stop_fn stop_worker);
void rawWriterCloseRequest(raw_writer_t *writer);
void rawWriterCloseWait(raw_writer_t *writer);
void rawWriterDestroy(raw_writer_t *writer);
/* Event-worker-only. Only Ok transfers ownership. Never writes synchronously. */
raw_writer_send_result_t rawWriterTrySend(raw_writer_t *writer, sbuf_t *buffer);
/* Foreign-thread-safe completion notification, exactly once for an externally
 * blocked operation. The backend keeps its notification root/lane live until
 * stop_worker quiesces it. This only posts owner work; it never consumes packets.
 * False means closed admission or worker-message refusal; no ownership returns
 * to the caller. */
bool rawWriterNotify(raw_writer_lane_t *lane);
