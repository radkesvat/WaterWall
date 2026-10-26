#pragma once

#include "buffer_pool.h"
#include "nghttp2/nghttp2.h"

typedef struct h2_data_item_s h2_data_item_t;

/* One stream's ordinary-buffer providers, confined to the pool's owner worker.
 * Initialize before use and keep this queue at a stable address until destruction:
 * nghttp2 borrows the queue through its provider source. The pool outlives it.
 * Fields are private to HttpCommon; callers use the operations below. */
typedef struct h2_data_queue_s
{
    h2_data_item_t *head, *tail, *active;
    buffer_pool_t  *pool;
    uint32_t        max_read;
} h2_data_queue_t;

typedef enum h2_data_status_e
{
    H2_DATA_IDLE,
    H2_DATA_BLOCKED,
    H2_DATA_STARTED,
    H2_DATA_FAILED
} h2_data_status_t;

typedef struct h2_data_result_s
{
    h2_data_status_t status;
    int              nghttp2_error;
} h2_data_result_t;

void h2DataInit(h2_data_queue_t *queue, buffer_pool_t *pool, uint32_t max_read);

/* Takes ownership, including empty buffers. NULL represents an empty provider.
 * Nodes retain their policy for dropping empty nonterminal application input. */
void h2DataAppend(h2_data_queue_t *queue, sbuf_t *payload, bool end_stream);

/* The caller establishes stream/HEADERS readiness. Does not pump the session.
 * IDLE: active provider or empty queue. BLOCKED: DATA_EXIST, front unchanged.
 * STARTED: session borrows the active provider. FAILED: rejected item released;
 * remaining items still belong to the queue and must be destroyed on closure. */
h2_data_result_t h2DataTrySubmit(h2_data_queue_t *queue, nghttp2_session *session, int32_t stream_id);

/* Call from nghttp2's frame-send callback. Retires only the matching DATA
 * provider whose read reached EOF. True permits submission of the next item. */
bool h2DataOnFrameSent(h2_data_queue_t *queue, const nghttp2_frame *frame, int32_t stream_id);

/* PRECONDITION: the session is absent/deleted and no library callback can use
 * this queue. Releases active and pending payloads on the pool's owner worker.
 * Also accepts an empty zeroed queue during line-state cleanup. */
void h2DataDestroyAfterSession(h2_data_queue_t *queue);
