#include "HttpCommon/h2_data.h"

struct h2_data_item_s
{
    sbuf_t         *payload;
    uint32_t        offset;
    bool            end_stream;
    bool            complete;
    h2_data_item_t *next;
};

static void h2DataItemDestroy(h2_data_queue_t *queue, h2_data_item_t *item)
{
    if (item == NULL)
    {
        return;
    }
    if (item->payload != NULL)
    {
        bufferpoolReuseBuffer(queue->pool, item->payload);
    }
    memoryFree(item);
}

void h2DataInit(h2_data_queue_t *queue, buffer_pool_t *pool, uint32_t max_read)
{
    assert(queue != NULL && pool != NULL && max_read > 0);
    *queue = (h2_data_queue_t) {.pool = pool, .max_read = max_read};
}

void h2DataAppend(h2_data_queue_t *queue, sbuf_t *payload, bool end_stream)
{
    assert(queue != NULL && queue->pool != NULL);
    assert(payload == NULL || ! sbufIsSplice(payload));

    h2_data_item_t *item = memoryAllocate(sizeof(*item));
    *item                = (h2_data_item_t) {.payload = payload, .end_stream = end_stream};
    if (queue->tail == NULL)
    {
        queue->head = item;
    }
    else
    {
        queue->tail->next = item;
    }
    queue->tail = item;
}

static ssize_t h2DataReadCallback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                                  uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    discard session;
    discard stream_id;
    discard user_data;
    assert(source != NULL && source->ptr != NULL);

    h2_data_queue_t *queue = source->ptr;
    h2_data_item_t  *item  = queue->active;
    assert(item != NULL);
    uint32_t payload_len = item->payload == NULL ? 0 : sbufGetLength(item->payload);
    assert(item->offset <= payload_len);
    uint32_t remaining = payload_len - item->offset;
    uint32_t to_copy   = (uint32_t) min((uint64_t) remaining, (uint64_t) length);
    to_copy            = min(to_copy, queue->max_read);

    if (to_copy > 0)
    {
        memoryCopy(buf, (const uint8_t *) sbufGetRawPtr(item->payload) + item->offset, to_copy);
        item->offset += to_copy;
    }
    if (item->offset == payload_len)
    {
        item->complete = true;
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        if (! item->end_stream)
        {
            *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        }
    }
    return (ssize_t) to_copy;
}

h2_data_result_t h2DataTrySubmit(h2_data_queue_t *queue, nghttp2_session *session, int32_t stream_id)
{
    assert(queue != NULL && queue->pool != NULL && session != NULL);
    if (queue->active != NULL || queue->head == NULL)
    {
        return (h2_data_result_t) {.status = H2_DATA_IDLE};
    }
    assert(stream_id > 0);

    h2_data_item_t       *item     = queue->head;
    nghttp2_data_provider provider = {.source = {.ptr = queue}, .read_callback = h2DataReadCallback};
    uint8_t               flags    = item->end_stream ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE;
    /* submit_data copies the provider without invoking its read callback. Keep
     * the front in place on DATA_EXIST; publish active before the caller pumps. */
    int rc = nghttp2_submit_data(session, flags, stream_id, &provider);
    if (rc == NGHTTP2_ERR_DATA_EXIST)
    {
        return (h2_data_result_t) {.status = H2_DATA_BLOCKED, .nghttp2_error = rc};
    }

    queue->head = item->next;
    if (queue->head == NULL)
    {
        queue->tail = NULL;
    }
    item->next = NULL;
    if (rc != 0)
    {
        h2DataItemDestroy(queue, item);
        return (h2_data_result_t) {.status = H2_DATA_FAILED, .nghttp2_error = rc};
    }
    queue->active = item;
    return (h2_data_result_t) {.status = H2_DATA_STARTED};
}

bool h2DataOnFrameSent(h2_data_queue_t *queue, const nghttp2_frame *frame, int32_t stream_id)
{
    assert(queue != NULL && frame != NULL);
    if (frame->hd.type != NGHTTP2_DATA || frame->hd.stream_id != stream_id || queue->active == NULL ||
        ! queue->active->complete)
    {
        return false;
    }

    h2DataItemDestroy(queue, queue->active);
    queue->active = NULL;
    return true;
}

void h2DataDestroyAfterSession(h2_data_queue_t *queue)
{
    assert(queue != NULL);
    h2DataItemDestroy(queue, queue->active);
    h2_data_item_t *item = queue->head;
    while (item != NULL)
    {
        h2_data_item_t *next = item->next;
        h2DataItemDestroy(queue, item);
        item = next;
    }
    *queue = (h2_data_queue_t) {0};
}
