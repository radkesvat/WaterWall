#pragma once

#include "buffer_queue.h"
#include "buffer_stream.h"

enum
{
    kHttpReceiveSliceBytes    = 16 * 1024,
    kHttpReceiveNestedBytes   = 1024 * 1024,
    kHttpReceiveNestedCharge  = 2 * 1024 * 1024,
    kHttpReceiveNestedEntries = 1024,
    kHttpReceiveStreamBytes   = 64 * 1024,
    kHttpReceiveStreamCharge  = 2 * 1024 * 1024
};

/* Owner-worker, stable-address input serialization. The current outer delivery
 * is synchronous working storage; nested input, including a popped active
 * nested buffer, shares the bounded budget. No callbacks or line operations. */
typedef struct http_receive_s
{
    buffer_queue_t              pending;
    buffer_budget_t             budget;
    buffer_budget_reservation_t reservation;
    sbuf_t                     *active;
    bool                        draining;
} http_receive_t;

typedef enum http_receive_result_e
{
    kHttpReceiveDrain,
    kHttpReceiveQueued,
    kHttpReceiveEmpty,
    kHttpReceiveRejected
} http_receive_result_t;

void httpReceiveInit(http_receive_t *receive);
void httpReceiveDestroy(http_receive_t *receive, buffer_pool_t *pool);
/* Takes input except on Rejected. Empty input is recycled immediately. */
http_receive_result_t httpReceiveAdmit(http_receive_t *receive, buffer_pool_t *pool, sbuf_t *buf);
/* Transfers the next <=16 KiB slice, publishing consumption before return.
 * NULL ends the drain. Call only while the node's state is still live. */
sbuf_t *httpReceiveNext(http_receive_t *receive, buffer_pool_t *pool);
/* Enforce retained logical bytes, compact excessive allocation/entry retention.
 * Waiting split uploads supply their separate existing logical-byte allowance.
 * Empty input retains no allocation. No callbacks. */
bool httpReceiveSettle(buffer_stream_t *stream, size_t max_bytes);
