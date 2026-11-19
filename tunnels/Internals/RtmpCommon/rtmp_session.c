#include "rtmp_session.h"

#include "buffer_budget.h"
#include "rtmp_credit.h"
#include "wmem.h"
#include "ww-rtmp-engine.h"

#include <assert.h>
#include <string.h>

enum
{
    kInputSlice       = 4096,
    kPendingBytes     = 1024 * 1024,
    kPendingCharge    = 2 * kPendingBytes,
    kPendingEntries   = 1024,
    kSetupAllowance   = 8192,
    kControlAllowance = 8192,
    kMaxDataChunks    = (RTMP_WIRE_BODY_MAX + kRtmpOutChunkSize - 1) / kRtmpOutChunkSize,
};

static_assert((int) RTMP_WIRE_BODY_MAX == kRtmpMaxMessageSize, "RTMP message cap must match codec");
static_assert(RTMP_SESSION_WIRE_MAX == kRtmpOutChunkSize + kRtmpMaxChunkHeaderSize,
              "RTMP wire chunk cap must match engine");
static_assert((int) RTMP_SESSION_WIRE_MAX >= kRtmpMaxHandshakeOutput, "RTMP wire queue must hold the handshake");
static_assert((int) RTMP_SESSION_APP_MAX == kRtmpMaxAppLength &&
                  (int) RTMP_SESSION_STREAM_MAX == kRtmpMaxStreamLength &&
                  (int) RTMP_SESSION_URL_MAX == kRtmpMaxUrlLength,
              "RTMP settings must match engine capacities");

typedef enum
{
    kClientUnstarted,
    kNegotiating,
    kPublishPending,
    kActive,
    kPeerClosed,
    kFailed,
} session_phase_t;

typedef struct rtmp_entry
{
    struct rtmp_entry *next;
    size_t             length;
    size_t             offset;
    bool               handshake;
    uint8_t            bytes[];
} rtmp_entry_t;

typedef struct
{
    buffer_budget_t budget;
    size_t          entries;
    size_t          entry_limit;
} rtmp_retention_t;

typedef struct
{
    rtmp_entry_t     *head;
    rtmp_entry_t     *tail;
    rtmp_retention_t *retention;
} rtmp_queue_t;

struct rtmp_session
{
    ww_rtmp_engine_t *engine;
    session_phase_t   phase;
    bool              server;
    size_t            block_size;
    uint32_t          stream_id;
    rtmp_credit_t     credit;
    rtmp_retention_t  tx;
    rtmp_retention_t  rx;
    rtmp_retention_t  control;
    rtmp_queue_t      plain;
    rtmp_queue_t      carrier;
    rtmp_queue_t      decoded;
    rtmp_queue_t      startup;
    rtmp_queue_t      wire_data;
    rtmp_queue_t      wire_control;
};

static bool queueCapture(rtmp_queue_t *queue, const void *first, size_t first_size, const void *second,
                         size_t second_size, bool handshake)
{
    const size_t      length    = first_size + second_size;
    rtmp_retention_t *retention = queue->retention;
    if (length == 0)
        return true;

    const size_t charge = sizeof(rtmp_entry_t) + length;
    if (retention->entries == retention->entry_limit ||
        ! bufferbudgetTryAcquire(&retention->budget, (buffer_budget_cost_t) {length, charge}))
        return false;
    rtmp_entry_t *entry = memoryAllocate(charge);
    *entry              = (rtmp_entry_t) {.length = length, .handshake = handshake};
    if (first_size > 0)
        memcpy(entry->bytes, first, first_size);
    if (second_size > 0)
        memcpy(entry->bytes + first_size, second, second_size);
    if (queue->tail != NULL)
        queue->tail->next = entry;
    else
        queue->head = entry;
    queue->tail = entry;
    ++retention->entries;
    return true;
}

static size_t queuePeek(const rtmp_queue_t *queue)
{
    return queue->head == NULL ? 0 : queue->head->length - queue->head->offset;
}

static size_t queueTake(rtmp_queue_t *queue, uint8_t *dst, size_t capacity)
{
    rtmp_entry_t *entry = queue->head;
    if (entry == NULL || capacity == 0)
        return 0;
    const size_t remaining = entry->length - entry->offset;
    const size_t count     = capacity < remaining ? capacity : remaining;
    if (dst != NULL)
        memcpy(dst, entry->bytes + entry->offset, count);

    rtmp_retention_t *retention = queue->retention;
    if (count == remaining)
    {
        queue->head = entry->next;
        if (queue->head == NULL)
            queue->tail = NULL;
        bufferbudgetRelease(&retention->budget, (buffer_budget_cost_t) {count, sizeof(*entry) + entry->length});
        --retention->entries;
        memoryFree(entry);
    }
    else
    {
        entry->offset += count;
        bufferbudgetRelease(&retention->budget, (buffer_budget_cost_t) {count, 0});
    }
    return count;
}

static void queueDestroy(rtmp_queue_t *queue)
{
    while (queueTake(queue, NULL, SIZE_MAX) != 0)
    {
    }
}

static int captureWire(void *context, const void *header, size_t header_size, const void *payload, size_t payload_size,
                       ww_rtmp_output_e kind)
{
    rtmp_session_t *session = context;
    if (header_size > RTMP_SESSION_WIRE_MAX || payload_size > RTMP_SESSION_WIRE_MAX - header_size)
        return -1;

    rtmp_queue_t *queue = &session->startup;
    if (kind == kRtmpOutputData)
    {
        assert(session->phase == kActive);
        queue = &session->wire_data;
    }
    else if (session->phase == kActive)
    {
        queue = &session->wire_control;
    }
    return queueCapture(queue, header, header_size, payload, payload_size, kind == kRtmpOutputHandshake) ? 0 : -1;
}

static int captureData(void *context, const void *body, size_t length, uint32_t timestamp, uint32_t chunk_stream_id,
                       uint32_t message_stream_id)
{
    rtmp_session_t *session = context;
    const uint8_t  *data;
    size_t          size;
    (void) timestamp;
    if (session->phase != kActive || chunk_stream_id != kRtmpDataChunkStream ||
        message_stream_id != session->stream_id || ! rtmpWireDecode(body, length, &data, &size))
        return -1;
    return queueCapture(&session->decoded, data, size, NULL, 0, false) ? 0 : -1;
}

static int captureEvent(void *context, ww_rtmp_event_e event, uint32_t value, uint8_t detail)
{
    rtmp_session_t *session = context;
    switch (event)
    {
    case kRtmpEventPublish:
        if (! session->server || session->phase != kNegotiating)
            return -1;
        session->phase = kPublishPending;
        return 0;
    case kRtmpEventReady:
        if (value == 0 || session->phase != (session->server ? kPublishPending : kNegotiating))
            return -1;
        session->phase     = kActive;
        session->stream_id = value;
        return 0;
    case kRtmpEventAck:
        return rtmpCreditReceiveAck(&session->credit, value) ? 0 : -1;
    case kRtmpEventBandwidth:
        return rtmpCreditSetBandwidth(&session->credit, value, detail) ? 0 : -1;
    }
    return -1;
}

static bool sessionCheck(rtmp_session_t *session, bool ok)
{
    if (! ok)
        session->phase = kFailed;
    return ok;
}

static bool validString(const char *text, size_t max_length)
{
    return text != NULL && *text != '\0' && strlen(text) <= max_length;
}

rtmp_session_t *rtmpSessionCreate(bool server, const char *app, const char *stream, const char *tc_url,
                                  size_t block_size)
{
    if (block_size == 0 || block_size > RTMP_SESSION_DATA_MAX || ! validString(app, RTMP_SESSION_APP_MAX) ||
        ! validString(stream, RTMP_SESSION_STREAM_MAX) || (! server && ! validString(tc_url, RTMP_SESSION_URL_MAX)))
        return NULL;

    static const ww_rtmp_engine_callbacks_t callbacks = {
        .send  = captureWire,
        .data  = captureData,
        .event = captureEvent,
    };
    rtmp_session_t *session           = memoryAllocateZero(sizeof(*session));
    session->phase                    = server ? kNegotiating : kClientUnstarted;
    session->server                   = server;
    session->block_size               = block_size;
    session->tx.entry_limit           = kPendingEntries;
    session->rx.entry_limit           = kPendingEntries;
    session->control.entry_limit      = kPendingEntries;
    const buffer_budget_cost_t limits = {kPendingBytes, kPendingCharge};
    bufferbudgetInit(&session->tx.budget, limits);
    bufferbudgetInit(&session->rx.budget, limits);
    bufferbudgetInit(&session->control.budget, (buffer_budget_cost_t) {kControlAllowance, 2 * kControlAllowance});
    session->plain.retention        = &session->tx;
    session->startup.retention      = &session->tx;
    session->wire_data.retention    = &session->tx;
    session->wire_control.retention = &session->control;
    session->carrier.retention      = &session->rx;
    session->decoded.retention      = &session->rx;
    session->engine                 = wwRtmpEngineCreate(server, app, stream, tc_url, &callbacks, session);
    if (session->engine == NULL)
    {
        memoryFree(session);
        return NULL;
    }
    return session;
}

void rtmpSessionDestroy(rtmp_session_t *session)
{
    wwRtmpEngineDestroy(session->engine);
    queueDestroy(&session->plain);
    queueDestroy(&session->carrier);
    queueDestroy(&session->decoded);
    queueDestroy(&session->startup);
    queueDestroy(&session->wire_data);
    queueDestroy(&session->wire_control);
    memoryFree(session);
}

bool rtmpSessionStart(rtmp_session_t *session)
{
    assert(session->phase == kClientUnstarted);
    session->phase = kNegotiating;
    return sessionCheck(session, wwRtmpEngineStart(session->engine) == 0);
}

bool rtmpSessionAccept(rtmp_session_t *session)
{
    assert(session->server && session->phase == kPublishPending);
    return sessionCheck(session, wwRtmpEngineAccept(session->engine) == 0 && session->phase == kActive);
}

bool rtmpSessionQueuePlain(rtmp_session_t *session, const uint8_t *bytes, size_t size)
{
    if (session->phase == kFailed || session->phase == kPeerClosed)
        return false;
    if (size == 0)
        return true;

    // Leave space inside the shared TX budget for framing and startup output.
    const size_t used = bufferbudgetGetUsage(&session->tx.budget).bytes;
    return sessionCheck(session,
                        used <= kPendingBytes - kSetupAllowance && size <= kPendingBytes - kSetupAllowance - used &&
                            session->tx.entries < kPendingEntries - kMaxDataChunks &&
                            queueCapture(&session->plain, bytes, size, NULL, 0, false));
}

bool rtmpSessionQueueCarrier(rtmp_session_t *session, const uint8_t *bytes, size_t size)
{
    if (session->phase == kFailed || session->phase == kPeerClosed)
        return false;
    return sessionCheck(session, size <= kPendingBytes && queueCapture(&session->carrier, bytes, size, NULL, 0, false));
}

static bool encodePlain(rtmp_session_t *session, uint32_t timestamp)
{
    size_t length = queuePeek(&session->plain);
    if (length > session->block_size)
        length = session->block_size;

    const size_t body_max    = RTMP_WIRE_PREFIX_MAX + length;
    const size_t chunk_count = (body_max + kRtmpOutChunkSize - 1) / kRtmpOutChunkSize;
    const size_t wire_max    = body_max + chunk_count * kRtmpMaxChunkHeaderSize;
    const size_t charge_max  = wire_max + chunk_count * sizeof(rtmp_entry_t);

    // Reserve the complete emission before entering the writer. Its callbacks
    // only append captured chunks, so no competing admission can use this room.
    const buffer_budget_cost_t usage = bufferbudgetGetUsage(&session->tx.budget);
    if (wire_max > kPendingBytes - (usage.bytes - length) || charge_max > kPendingCharge - usage.charge ||
        chunk_count > kPendingEntries - session->tx.entries)
        return false;

    uint8_t            *body      = memoryAllocate(body_max);
    const rtmp_entry_t *plain     = session->plain.head;
    const size_t        body_size = rtmpWireEncode(plain->bytes + plain->offset, length, body, body_max);
    assert(body_size > 0);
    queueTake(&session->plain, NULL, length);
    const int result = wwRtmpEngineSendData(session->engine, body, body_size, timestamp);
    memoryFree(body);
    return result == 0;
}

bool rtmpSessionStep(rtmp_session_t *session, uint32_t elapsed_ms, bool *progress)
{
    *progress = false;
    if (session->phase == kFailed)
        return false;
    if (session->phase == kPeerClosed)
        return true;

    if (session->phase != kClientUnstarted && session->carrier.head != NULL)
    {
        uint8_t      input[kInputSlice];
        const size_t size = queueTake(&session->carrier, input, sizeof(input));
        *progress         = true;
        const int result  = wwRtmpEngineInput(session->engine, input, size);
        if (result == kRtmpInputClosed)
        {
            session->phase = kPeerClosed;
            return true;
        }
        if (result != 0)
            return sessionCheck(session, false);
        const uint32_t window = session->credit.window;
        if (window != 0 && wwRtmpEngineAdvertiseWindow(session->engine, window) != 0)
            return sessionCheck(session, false);
    }

    if (session->phase == kActive && session->plain.head != NULL && session->wire_data.head == NULL)
    {
        *progress = true;
        return sessionCheck(session, encodePlain(session, elapsed_ms));
    }
    return true;
}

bool rtmpSessionPublishPending(const rtmp_session_t *session)
{
    return session->phase == kPublishPending;
}

bool rtmpSessionIsActive(const rtmp_session_t *session)
{
    return session->phase == kActive;
}

bool rtmpSessionPeerClosed(const rtmp_session_t *session)
{
    return session->phase == kPeerClosed;
}

bool rtmpSessionHasTxTail(const rtmp_session_t *session)
{
    return session->plain.head != NULL || session->wire_data.head != NULL;
}

size_t rtmpSessionPendingRx(const rtmp_session_t *session)
{
    return bufferbudgetGetUsage(&session->rx.budget).bytes;
}

static const rtmp_queue_t *wireHead(const rtmp_session_t *session)
{
    if (session->phase == kFailed || session->phase == kPeerClosed)
        return NULL;
    if (session->startup.head != NULL)
    {
        if (session->startup.head->handshake ||
            rtmpCreditCanSend(&session->credit, queuePeek(&session->startup), false))
            return &session->startup;
        return NULL;
    }
    if (session->wire_control.head != NULL &&
        rtmpCreditCanSend(&session->credit, queuePeek(&session->wire_control), false))
        return &session->wire_control;
    if (session->wire_data.head != NULL && rtmpCreditCanSend(&session->credit, queuePeek(&session->wire_data), true))
        return &session->wire_data;
    return NULL;
}

size_t rtmpSessionPeekWire(const rtmp_session_t *session)
{
    const rtmp_queue_t *queue = wireHead(session);
    return queue == NULL ? 0 : queuePeek(queue);
}

bool rtmpSessionNeedsSendCredit(const rtmp_session_t *session)
{
    return session->phase == kActive && session->wire_data.head != NULL && wireHead(session) == NULL;
}

size_t rtmpSessionPeekPlain(const rtmp_session_t *session)
{
    return session->phase != kFailed ? queuePeek(&session->decoded) : 0;
}

size_t rtmpSessionTakeWire(rtmp_session_t *session, uint8_t *dst, size_t capacity, bool *is_data)
{
    const rtmp_queue_t *head = wireHead(session);
    if (is_data != NULL)
        *is_data = false;
    if (head == NULL || capacity < queuePeek(head))
        return 0;

    const size_t size = queuePeek(head);
    if (! head->head->handshake)
        rtmpCreditCommit(&session->credit, size);

    rtmp_queue_t *queue = &session->startup;
    if (head == &session->wire_control)
        queue = &session->wire_control;
    else if (head == &session->wire_data)
    {
        queue = &session->wire_data;
        if (is_data != NULL)
            *is_data = true;
    }
    return queueTake(queue, dst, size);
}

size_t rtmpSessionTakePlain(rtmp_session_t *session, uint8_t *dst, size_t capacity)
{
    return session->phase != kFailed ? queueTake(&session->decoded, dst, capacity) : 0;
}
