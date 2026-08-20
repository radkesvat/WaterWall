#include "TlsRecordShapingCommon/record_shaping.h"

struct tlsrecordshaping_metadata_node_s
{
    tlsrecordshaping_metadata_node_t *next;
    uint32_t                          delay_ms;
};

struct tlsrecordshaping_output_node_s
{
    tlsrecordshaping_output_node_t *next;
    sbuf_t                         *record;
    uint64_t                        release_at_ms;
};

void tlsrecordshapingOutputQueueInitialize(tlsrecordshaping_output_queue_t *queue, buffer_pool_t *pool)
{
    assert(queue != NULL && pool != NULL);
    *queue = (tlsrecordshaping_output_queue_t) {
        .ciphertext_stream = bufferstreamCreate(pool, 0),
        .initialized       = true,
    };
}

void tlsrecordshapingOutputQueueDestroy(tlsrecordshaping_output_queue_t *queue)
{
    assert(queue != NULL);

    if (! queue->initialized)
    {
        return;
    }

    while (queue->metadata_head != NULL)
    {
        tlsrecordshaping_metadata_node_t *next = queue->metadata_head->next;
        memoryFree(queue->metadata_head);
        queue->metadata_head = next;
    }
    while (queue->pending_metadata_head != NULL)
    {
        tlsrecordshaping_metadata_node_t *next = queue->pending_metadata_head->next;
        memoryFree(queue->pending_metadata_head);
        queue->pending_metadata_head = next;
    }
    while (queue->output_head != NULL)
    {
        tlsrecordshaping_output_node_t *next = queue->output_head->next;
        reuseBuffer(queue->output_head->record);
        memoryFree(queue->output_head);
        queue->output_head = next;
    }

    bufferstreamDestroy(&queue->ciphertext_stream);
    memoryZero(queue, sizeof(*queue));
}

static bool pushMetadata(tlsrecordshaping_metadata_node_t **head, tlsrecordshaping_metadata_node_t **tail,
                         size_t *count, uint32_t delay_ms)
{
    assert(head != NULL && tail != NULL && count != NULL);

    tlsrecordshaping_metadata_node_t *node = memoryAllocateZero(sizeof(*node));
    if (UNLIKELY(node == NULL))
    {
        return false;
    }
    node->delay_ms = delay_ms;
    if (*tail != NULL)
    {
        (*tail)->next = node;
    }
    else
    {
        *head = node;
    }
    *tail = node;
    *count += 1;
    return true;
}

bool tlsrecordshapingOutputQueuePushMetadata(tlsrecordshaping_output_queue_t *queue, uint32_t delay_ms)
{
    assert(queue != NULL && queue->initialized);

    if (delay_ms > kTlsRecordShapingMaxDelayMs)
    {
        return false;
    }

    return pushMetadata(&queue->metadata_head, &queue->metadata_tail, &queue->metadata_count, delay_ms);
}

bool tlsrecordshapingOutputQueuePushPendingMetadata(tlsrecordshaping_output_queue_t *queue, uint32_t delay_ms)
{
    assert(queue != NULL && queue->initialized);

    if (delay_ms > kTlsRecordShapingMaxDelayMs)
    {
        return false;
    }

    return pushMetadata(
        &queue->pending_metadata_head, &queue->pending_metadata_tail, &queue->pending_metadata_count, delay_ms);
}

bool tlsrecordshapingOutputQueueHasPendingMetadata(const tlsrecordshaping_output_queue_t *queue)
{
    assert(queue != NULL && queue->initialized);

    return queue->pending_metadata_head != NULL;
}

bool tlsrecordshapingOutputQueueCommitMetadata(tlsrecordshaping_output_queue_t *queue, uint32_t fallback_delay_ms)
{
    assert(queue != NULL && queue->initialized);

    if (fallback_delay_ms > kTlsRecordShapingMaxDelayMs)
    {
        return false;
    }

    uint32_t delay_ms = fallback_delay_ms;
    if (queue->pending_metadata_head != NULL)
    {
        tlsrecordshaping_metadata_node_t *node = queue->pending_metadata_head;
        queue->pending_metadata_head           = node->next;
        if (queue->pending_metadata_head == NULL)
        {
            queue->pending_metadata_tail = NULL;
        }
        queue->pending_metadata_count -= 1;
        delay_ms = node->delay_ms;
        memoryFree(node);
    }
    return tlsrecordshapingOutputQueuePushMetadata(queue, delay_ms);
}

static bool parseRecordLength(tlsrecordshaping_output_queue_t *queue, size_t *record_length,
                              char error[kTlsRecordShapingErrorSize])
{
    uint8_t header[kTlsRecordShapingRecordHeaderSize];
    bufferstreamViewBytesAt(&queue->ciphertext_stream, 0, header, sizeof(header));
    uint16_t body_length = ((uint16_t) header[3] << 8U) | header[4];

    if (header[0] != 0x17 || header[1] != 0x03 || header[2] != 0x03 || body_length == 0 ||
        body_length > kTlsRecordShapingMaxRecordBody)
    {
        return tlsrecordshapingSetError(error,
                                        "outgoing TLS 1.3 record framing mismatch (type=%u version=%02x%02x length=%u)",
                                        (unsigned int) header[0],
                                        (unsigned int) header[1],
                                        (unsigned int) header[2],
                                        (unsigned int) body_length);
    }

    *record_length = kTlsRecordShapingRecordHeaderSize + (size_t) body_length;
    return true;
}

static tlsrecordshaping_metadata_node_t *popMetadata(tlsrecordshaping_output_queue_t *queue)
{
    tlsrecordshaping_metadata_node_t *node = queue->metadata_head;
    if (node == NULL)
    {
        return NULL;
    }
    queue->metadata_head = node->next;
    if (queue->metadata_head == NULL)
    {
        queue->metadata_tail = NULL;
    }
    queue->metadata_count -= 1;
    return node;
}

static bool pushOutput(tlsrecordshaping_output_queue_t *queue, sbuf_t *record, uint64_t release_at_ms)
{
    tlsrecordshaping_output_node_t *node = memoryAllocateZero(sizeof(*node));
    if (UNLIKELY(node == NULL))
    {
        return false;
    }
    node->record                         = record;
    node->release_at_ms                  = release_at_ms;
    if (queue->output_tail != NULL)
    {
        queue->output_tail->next = node;
    }
    else
    {
        queue->output_head = node;
    }
    queue->output_tail = node;
    queue->output_count += 1;
    queue->queued_ciphertext_bytes += sbufGetLength(record);
    return true;
}

bool tlsrecordshapingOutputQueueFeed(tlsrecordshaping_output_queue_t *queue, sbuf_t *ciphertext, uint64_t now_ms,
                                     char error[kTlsRecordShapingErrorSize])
{
    assert(queue != NULL && queue->initialized && ciphertext != NULL);

    bufferstreamPush(&queue->ciphertext_stream, ciphertext);
    while (bufferstreamGetBufLen(&queue->ciphertext_stream) >= kTlsRecordShapingRecordHeaderSize)
    {
        size_t record_length = 0;
        if (! parseRecordLength(queue, &record_length, error))
        {
            return false;
        }
        if (bufferstreamGetBufLen(&queue->ciphertext_stream) < record_length)
        {
            return true;
        }

        tlsrecordshaping_metadata_node_t *metadata = popMetadata(queue);
        if (metadata == NULL)
        {
            return tlsrecordshapingSetError(error, "outgoing TLS record has no matching shaping decision");
        }

        uint64_t release_at = now_ms + metadata->delay_ms;
        if (release_at < now_ms)
        {
            release_at = UINT64_MAX;
        }
        if (release_at < queue->previous_release_at_ms)
        {
            release_at = queue->previous_release_at_ms;
        }
        queue->previous_release_at_ms = release_at;

        sbuf_t *record = bufferstreamReadExact(&queue->ciphertext_stream, record_length);
        if (! pushOutput(queue, record, release_at))
        {
            reuseBuffer(record);
            memoryFree(metadata);
            return tlsrecordshapingSetError(error, "failed to allocate outgoing TLS record queue node");
        }
        memoryFree(metadata);
    }
    return true;
}

bool tlsrecordshapingOutputQueueFinishFeed(const tlsrecordshaping_output_queue_t *queue,
                                           char                                   error[kTlsRecordShapingErrorSize])
{
    assert(queue != NULL && queue->initialized);

    if (bufferstreamGetBufLen((buffer_stream_t *) &queue->ciphertext_stream) != 0)
    {
        return tlsrecordshapingSetError(error, "outgoing TLS write BIO ended with a partial record");
    }
    if (queue->metadata_count != 0)
    {
        return tlsrecordshapingSetError(error, "shaping decision has no matching outgoing TLS record");
    }
    if (queue->pending_metadata_count != 0)
    {
        return tlsrecordshapingSetError(error, "padding callback decision has no matching outgoing TLS record header");
    }
    return true;
}

sbuf_t *tlsrecordshapingOutputQueuePopReady(tlsrecordshaping_output_queue_t *queue, uint64_t now_ms, bool force)
{
    assert(queue != NULL && queue->initialized);

    if (queue->output_head == NULL || (! force && queue->output_head->release_at_ms > now_ms))
    {
        return NULL;
    }

    tlsrecordshaping_output_node_t *node = queue->output_head;
    queue->output_head                   = node->next;
    if (queue->output_head == NULL)
    {
        queue->output_tail            = NULL;
        queue->previous_release_at_ms = 0;
    }
    queue->output_count -= 1;
    queue->queued_ciphertext_bytes -= sbufGetLength(node->record);

    sbuf_t *record = node->record;
    memoryFree(node);
    return record;
}

bool tlsrecordshapingOutputQueueNextDelay(const tlsrecordshaping_output_queue_t *queue, uint64_t now_ms,
                                          uint32_t *delay_ms)
{
    assert(queue != NULL && queue->initialized && delay_ms != NULL);

    if (queue->output_head == NULL)
    {
        return false;
    }
    if (queue->output_head->release_at_ms <= now_ms)
    {
        *delay_ms = 0;
        return true;
    }

    uint64_t difference = queue->output_head->release_at_ms - now_ms;
    *delay_ms           = difference > UINT32_MAX ? UINT32_MAX : (uint32_t) difference;
    return true;
}

size_t tlsrecordshapingOutputQueueBytes(const tlsrecordshaping_output_queue_t *queue)
{
    assert(queue != NULL && queue->initialized);

    return queue->queued_ciphertext_bytes;
}

size_t tlsrecordshapingOutputQueueCount(const tlsrecordshaping_output_queue_t *queue)
{
    assert(queue != NULL && queue->initialized);

    return queue->output_count;
}

bool tlsrecordshapingOutputQueueIsEmpty(const tlsrecordshaping_output_queue_t *queue)
{
    assert(queue != NULL);

    /* Handshake takeover also queries this queue when record shaping is disabled. */
    if (! queue->initialized)
    {
        return true;
    }

    return queue->output_count == 0 && queue->metadata_count == 0 && queue->pending_metadata_count == 0 &&
           bufferstreamGetBufLen((buffer_stream_t *) &queue->ciphertext_stream) == 0;
}
