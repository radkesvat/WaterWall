#pragma once

#include "shiftbuffer.h"
#include "watomic.h"
#include "worker.h"

enum
{
    kTunWriterQueueMax     = 128 * 1024,
    kTunWriterBatchPackets = 64,
    kTunWriterBatchCharge  = 256 * 1024
};

typedef struct tun_writer_generation_s tun_writer_generation_t;

/* The lifecycle owner serializes Open/CloseRequest/CloseWait/Destroy. Producers
 * require a live writer until TrySend returns. Destroy requires those external
 * producer contexts to be quiesced; accepted drain tokens may outlive Destroy. */
typedef struct tun_writer_s
{
    atomic_uintptr_t         published_generation;
    tun_writer_generation_t *current;
    tun_writer_generation_t *retired;
} tun_writer_t;

typedef enum tun_writer_send_result_e
{
    kTunWriterSendOk = 0,
    kTunWriterSendDown,
    kTunWriterSendClosed,
    kTunWriterSendFull
} tun_writer_send_result_t;

/* Runs on the supplied event worker, outside the submitting callback. Consumes
 * every buffer, including on failure, using worker->buffer_pool or destruction.
 * False reports a fatal native failure: the writer requests program shutdown
 * after leaving admission. The callback must not stop/wait/destroy this writer. */
typedef bool (*tun_writer_batch_fn)(void *context, worker_t *worker, sbuf_t **buffers, size_t count);

void tunWriterInit(tun_writer_t *writer);
bool tunWriterOpen(tun_writer_t *writer, size_t packet_limit, size_t charge_limit, void *context,
                   tun_writer_batch_fn write_batch);
/* CloseRequest never waits. CloseWait discards queued ownership after admitted
 * producers and native writes finish, then retires the closed generation. */
void tunWriterCloseRequest(tun_writer_t *writer);
void tunWriterCloseWait(tun_writer_t *writer);
void tunWriterDestroy(tun_writer_t *writer);
/* Event-worker-only submission. Ok transfers ownership; every refusal leaves
 * the original buffer with the caller. No native write runs synchronously. */
tun_writer_send_result_t tunWriterTrySend(tun_writer_t *writer, sbuf_t *buffer);
