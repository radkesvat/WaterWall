#include "ConnectionStripeCommon/stripe.h"

#include "loggers/network_logger.h"

typedef struct stripe_session_s stripe_session_t;
typedef struct stripe_line_s    stripe_line_t;

typedef enum stripe_finish_action_e
{
    kStripeFinishReceived,
    kStripeFinishInitiated,
} stripe_finish_action_t;

typedef struct stripe_id_s
{
    uint8_t  bytes[16];
    uint64_t hash;
} stripe_id_t;

static size_t stripeIdHash(const stripe_id_t *id)
{
    return (size_t) id->hash;
}
static bool stripeIdEqual(const stripe_id_t *a, const stripe_id_t *b)
{
    return memoryCompare(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

#define i_type stripe_map_t
#define i_key  stripe_id_t
#define i_val  stripe_session_t *
#define i_hash stripeIdHash
#define i_eq   stripeIdEqual
#include "stc/hmap.h"
#undef i_type
#undef i_key
#undef i_val
#undef i_hash
#undef i_eq

typedef struct stripe_worker_s
{
    stripe_map_t        sessions;
    stripe_session_t   *head;
    stripe_line_t      *pending;
    local_idle_table_t *timers;
    uint32_t            session_count;
    uint32_t            pending_count;
    bool                quiesced;
} stripe_worker_t;

typedef struct stripe_state_s
{
    const stripe_output_t *output;
    stripe_endpoint_role_t role;
    stripe_worker_t       *workers;
    uint64_t               hash_seed;
    uint32_t               receive_window;
    uint32_t               max_buffered;
    uint32_t               setup_timeout;
    uint32_t               drain_timeout;
    uint32_t               max_sessions;
    uint32_t               max_pending;
    uint16_t               connections;
    wid_t                  worker_count;
} stripe_state_t;

struct stripe_line_s
{
    stripe_session_t     *session;
    line_t               *line;
    tunnel_t             *tunnel;
    stripe_line_t        *pending_prev;
    stripe_line_t        *pending_next;
    local_idle_item_t    *deadline;
    splice_frame_reader_t reader;
    uint8_t               intro[kStripeJoinSize];
    uint16_t              intro_have;
    uint16_t              index;
    stripe_line_role_t    role;
    bool                  pending;
    bool                  paused;
};

typedef struct stripe_record_s
{
    sbuf_t  *body;
    uint64_t offset;
    uint64_t index;
} stripe_record_t;

struct stripe_session_s
{
    tunnel_t         *tunnel;
    stripe_worker_t  *worker;
    stripe_session_t *prev;
    stripe_session_t *next;
    buffer_pool_t    *pool;
    stripe_id_t       id;
    line_t           *application;
    line_t           *lanes[kStripeMaxConnections];
    stripe_record_t   records[kStripeFrameWindow];
    /* End offset of each outstanding outgoing record, used to validate credit. */
    uint64_t                    sent_ends[kStripeFrameWindow];
    buffer_budget_t             tx_budget;
    buffer_queue_t              tx_queue;
    sbuf_t                     *tx_active;
    buffer_budget_reservation_t tx_reservation;
    local_idle_item_t          *deadline;
    uint64_t                    tx_accepted;
    uint64_t                    tx_offset;
    uint64_t                    tx_index;
    uint64_t                    tx_ack_offset;
    uint64_t                    tx_ack_index;
    uint64_t                    rx_offset;
    uint64_t                    rx_index;
    uint64_t                    rx_final_offset;
    uint64_t                    rx_final_index;
    size_t                      rx_bytes;
    uint32_t                    peer_window;
    uint32_t                    refs;
    uint16_t                    count;
    uint16_t                    joined;
    uint16_t                    cursor;
    uint16_t                    padding;
    wid_t                       wid;
    bool                        initializing : 1;
    bool                        ready : 1;
    bool                        established : 1;
    bool                        est_seen : 1;
    bool                        source_paused : 1;
    bool                        receive_paused : 1;
    bool                        pumping : 1;
    bool                        pump_requested : 1;
    bool                        credit_dirty : 1;
    bool                        local_close : 1;
    bool                        drain_started : 1;
    bool                        close_sent : 1;
    bool                        close_acked : 1;
    bool                        remote_close : 1;
    bool                        remote_acked : 1;
    bool                        closed : 1;
};

static void stripePump(stripe_session_t *s);
static void stripeAbort(stripe_session_t *s, const char *reason);
static void stripeBeginClose(stripe_session_t *s);

static stripe_state_t *stripeState(tunnel_t *t)
{
    return tunnelGetState(t);
}
static void stripeRef(stripe_session_t *s)
{
    assert(s->refs != UINT32_MAX);
    ++s->refs;
}
static void stripeUnref(stripe_session_t *s)
{
    assert(s->refs != 0);
    if (--s->refs == 0)
    {
        assert(s->closed);
        memoryFree(s);
    }
}

static void stripeRemoveDeadline(local_idle_item_t **slot)
{
    local_idle_item_t *item = *slot;
    if (item)
    {
        *slot = NULL;
        discard localidletableRemoveIdleItem(item->table, item);
    }
}

static stripe_worker_t *stripeWorker(tunnel_t *t, wid_t wid)
{
    stripe_state_t *ts = stripeState(t);
    assert(workerWIDIsRegistered(wid) && wid < ts->worker_count);
    return &ts->workers[wid];
}

static local_idle_table_t *stripeTimers(tunnel_t *t, wid_t wid)
{
    stripe_worker_t *w = stripeWorker(t, wid);
    assert(! w->quiesced);
    if (! w->timers)
        w->timers = localIdleTableCreate(getWorkerLoop(wid));
    return w->timers;
}

static void stripeUnlinkPending(stripe_line_t *ls)
{
    stripeRemoveDeadline(&ls->deadline);
    if (! ls->pending)
        return;
    stripe_worker_t *w = stripeWorker(ls->tunnel, lineGetWID(ls->line));
    if (ls->pending_prev)
        ls->pending_prev->pending_next = ls->pending_next;
    else
        w->pending = ls->pending_next;
    if (ls->pending_next)
        ls->pending_next->pending_prev = ls->pending_prev;
    assert(w->pending_count);
    --w->pending_count;
    ls->pending      = false;
    ls->pending_prev = ls->pending_next = NULL;
}

static void stripeLineClear(tunnel_t *t, line_t *line)
{
    stripe_line_t *ls = lineGetState(line, t);
    stripeUnlinkPending(ls);
    if (spliceframereaderIsAttached(&ls->reader))
        spliceframereaderDestroy(&ls->reader);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

/* Only call after removing the line from the session. A received Finish has
 * already closed the neighbour; kStripeFinishReceived never reflects it. */
static void stripeFinishLine(stripe_session_t *s, line_t *line, stripe_line_role_t role, stripe_finish_action_t action)
{
    tunnel_t              *t      = s->tunnel;
    const stripe_output_t *output = stripeState(t)->output;
    const bool             owned  = role == output->owned_line_role;
    lineRef(line);
    stripeLineClear(t, line);
    if (action == kStripeFinishInitiated)
    {
        if (role == kStripeTransportLine)
            output->transport_finish(t, line);
        else
            output->application_finish(t, line);
    }
    if (owned)
        lineDestroy(line);
    lineUnref(line);
}

static void stripeAbort(stripe_session_t *s, const char *reason)
{
    if (s->closed)
        return;
    stripeRef(s);
    s->closed = true;
    LOGD("ConnectionStripe%s: session closed: %s",
         stripeState(s->tunnel)->role == kStripeClientEndpoint ? "Client" : "Server",
         reason);
    stripeRemoveDeadline(&s->deadline);
    stripe_worker_t *w = s->worker;
    stripe_map_t_erase(&w->sessions, s->id);
    if (s->prev)
        s->prev->next = s->next;
    else
        w->head = s->next;
    if (s->next)
        s->next->prev = s->prev;
    assert(w->session_count);
    --w->session_count;
    bufferqueueDestroy(&s->tx_queue);
    if (s->tx_active)
    {
        bufferpoolReuseBuffer(s->pool, s->tx_active);
        s->tx_active = NULL;
    }
    bufferbudgetReservationRelease(&s->tx_reservation);
    bufferbudgetAssertEmpty(&s->tx_budget);
    for (unsigned i = 0; i < kStripeFrameWindow; ++i)
    {
        if (s->records[i].body)
            bufferpoolReuseBuffer(s->pool, s->records[i].body);
        s->records[i].body = NULL;
    }
    /* Clear membership before every outward callback. Reentry can inspect the
     * remaining session, but may neither revive it nor close a detached line. */
    for (unsigned i = 0; i < s->count; ++i)
    {
        line_t *line = s->lanes[i];
        s->lanes[i]  = NULL;
        if (line)
            stripeFinishLine(s, line, kStripeTransportLine, kStripeFinishInitiated);
    }
    line_t *app    = s->application;
    s->application = NULL;
    if (app)
        stripeFinishLine(s, app, kStripeApplicationLine, kStripeFinishInitiated);
    stripeUnref(s); /* inventory */
    stripeUnref(s);
}

static void stripeSessionExpired(local_idle_item_t *item)
{
    stripe_session_t *s = item->userdata;
    stripeRemoveDeadline(&s->deadline);
    stripeAbort(s, s->drain_started ? "drain deadline expired" : "setup deadline expired");
}

static void stripePendingExpired(local_idle_item_t *item)
{
    stripe_line_t *ls   = item->userdata;
    line_t        *line = ls->line;
    tunnel_t      *t    = ls->tunnel;
    LOGD("ConnectionStripeServer: pending JOIN deadline expired");
    stripeLineClear(t, line);
    stripeState(t)->output->transport_finish(t, line);
}

static stripe_session_t *stripeSessionCreate(tunnel_t *t, wid_t wid, stripe_id_t id, uint16_t count)
{
    stripe_state_t  *ts = stripeState(t);
    stripe_worker_t *w  = stripeWorker(t, wid);
    if (w->quiesced || w->session_count >= ts->max_sessions)
        return NULL;
    stripe_session_t *s = memoryAllocateZero(sizeof(*s));
    s->tunnel           = t;
    s->worker           = w;
    s->wid              = wid;
    s->pool             = getWorkerBufferPool(wid);
    s->padding          = bufferpoolGetSmallBufferPadding(s->pool);
    s->id               = id;
    s->count            = count;
    s->refs             = 1;
    bufferbudgetInit(&s->tx_budget, (buffer_budget_cost_t) {ts->max_buffered, ts->max_buffered});
    bufferqueueInitEmpty(&s->tx_queue);
    bufferqueueAttachBudget(&s->tx_queue, &s->tx_budget);
    const bool inserted = stripe_map_t_insert(&w->sessions, id, s).inserted;
    assert(inserted);
    discard inserted;
    s->next = w->head;
    if (w->head)
        w->head->prev = s;
    w->head = s;
    ++w->session_count;
    s->deadline = localidletableCreateItem(
        stripeTimers(t, wid), (hash_t) (uintptr_t) s, s, stripeSessionExpired, ts->setup_timeout);
    assert(s->deadline);
    return s;
}

static sbuf_t *stripeBuffer(stripe_session_t *s, size_t length)
{
    sbuf_t *buf = sbufCreateWithPadding(length, s->padding);
    sbufSetLength(buf, length);
    return buf;
}

/* Match stripeBuffer's exact allocation geometry without checking out storage.
 * Lengths are bounded by validated settings or the DATA frame limit. */
static size_t stripeCanonicalCharge(stripe_session_t *s, size_t length)
{
    size_t     capacity = 0, charge = 0;
    const bool valid =
        sbufTryComputeCapacity(length, s->padding, &capacity) && sbufTryComputeQueueCharge(capacity, &charge);
    assert(valid);
    discard valid;
    return charge;
}

static sbuf_t *stripeCanonicalCopy(stripe_session_t *s, sbuf_t *source)
{
    const size_t length = sbufGetLength(source);
    sbuf_t      *copy   = stripeBuffer(s, length);
    sbufReadRangeToMemory(source, sbufGetMutablePtr(copy), length);
    bufferpoolReuseBuffer(s->pool, source);
    return copy;
}

static void stripeHeader(uint8_t *p, uint8_t type, uint32_t length, uint64_t offset, uint64_t aux)
{
    p[0] = type;
    p[1] = p[2] = p[3] = 0;
    PUT_BE32(p + 4, length);
    PUT_BE64(p + 8, offset);
    PUT_BE64(p + 16, aux);
}

static void stripeSend(stripe_session_t *s, unsigned index, sbuf_t *buf)
{
    line_t *line = s->lanes[index];
    if (s->closed || ! line)
    {
        bufferpoolReuseBuffer(s->pool, buf);
        return;
    }
    lineRef(line);
    stripeState(s->tunnel)->output->transport_payload(s->tunnel, line, buf);
    lineUnref(line);
}

static void stripeControl(stripe_session_t *s, uint8_t type, uint64_t offset, uint64_t aux)
{
    sbuf_t *buf = stripeBuffer(s, kStripeHeaderSize);
    stripeHeader(sbufGetMutablePtr(buf), type, 0, offset, aux);
    stripeSend(s, 0, buf);
}

static int stripeWritableLane(stripe_session_t *s)
{
    for (unsigned n = 0; n < s->count; ++n)
    {
        unsigned i = (s->cursor + n) % s->count;
        if (s->lanes[i])
        {
            stripe_line_t *ls = lineGetState(s->lanes[i], s->tunnel);
            if (! ls->paused)
                return (int) i;
        }
    }
    return -1;
}

static bool stripeHasCredit(const stripe_session_t *s)
{
    return s->tx_index - s->tx_ack_index < kStripeFrameWindow && s->tx_offset - s->tx_ack_offset < s->peer_window;
}

static void stripeSourcePressure(stripe_session_t *s)
{
    if (s->closed || ! s->application || s->initializing || s->local_close)
        return;
    stripe_state_t *ts     = stripeState(s->tunnel);
    const size_t    charge = bufferbudgetGetUsage(&s->tx_budget).charge;
    bool            pause  = ! s->ready || ! stripeHasCredit(s) || stripeWritableLane(s) < 0 ||
                 charge >= (uint64_t) ts->max_buffered * 3 / 4;
    if (s->source_paused && charge > ts->max_buffered / 2)
        pause = true;
    if (pause == s->source_paused)
        return;
    s->source_paused = pause;
    line_t *app      = s->application;
    lineRef(app);
    if (pause)
        ts->output->application_pause(s->tunnel, app);
    else
        ts->output->application_resume(s->tunnel, app);
    lineUnref(app);
}

static void stripeNotifyEstablished(stripe_session_t *s)
{
    if (s->closed || s->initializing || s->established || ! s->est_seen || ! s->application)
        return;
    s->established = true;
    line_t *app    = s->application;
    lineRef(app);
    stripeState(s->tunnel)->output->est_borrowed(s->tunnel, app);
    lineUnref(app);
}

static bool stripeStartDrain(stripe_session_t *s)
{
    if (s->worker->quiesced || ! wloopNormalDispatchAllowed(getWorkerLoop(s->wid)))
        return false;
    if (! s->drain_started)
    {
        s->drain_started = true;
        stripeRemoveDeadline(&s->deadline);
        s->deadline = localidletableCreateItem(stripeTimers(s->tunnel, s->wid),
                                               (hash_t) (uintptr_t) s,
                                               s,
                                               stripeSessionExpired,
                                               stripeState(s->tunnel)->drain_timeout);
        assert(s->deadline);
    }
    return true;
}

static void stripeBeginClose(stripe_session_t *s)
{
    if (s->closed || s->local_close)
        return;
    s->local_close    = true;
    s->receive_paused = false;
    if (! stripeStartDrain(s))
        stripeAbort(s, "drain admission closed");
}

static bool stripeDeliver(stripe_session_t *s)
{
    if (s->receive_paused && s->application)
        return false;
    stripe_record_t *record = &s->records[s->rx_index % kStripeFrameWindow];
    if (! record->body)
        return false;
    if (record->index != s->rx_index || record->offset != s->rx_offset)
    {
        stripeAbort(s, "DATA record index and byte offset disagree");
        return false;
    }
    sbuf_t *buf         = record->body;
    record->body        = NULL;
    const size_t length = sbufGetLength(buf);
    s->rx_bytes -= length;
    s->rx_offset += length;
    ++s->rx_index;
    s->credit_dirty = true;
    line_t *app     = s->application;
    if (! app)
    {
        bufferpoolReuseBuffer(s->pool, buf);
        return true;
    }
    lineRef(app);
    stripeState(s->tunnel)->output->application_payload(s->tunnel, app, buf);
    lineUnref(app);
    return true;
}

static bool stripeTransmit(stripe_session_t *s)
{
    if (! stripeHasCredit(s))
        return false;
    int index = stripeWritableLane(s);
    if (index < 0)
        return false;
    if (! s->tx_active)
        s->tx_active = bufferqueuePopFrontReserved(&s->tx_queue, &s->tx_reservation);
    if (! s->tx_active)
        return false;
    size_t length = min(sbufGetLength(s->tx_active), (size_t) kStripeMaxFrame);
    length        = (size_t) min((uint64_t) length, s->peer_window - (s->tx_offset - s->tx_ack_offset));
    assert(length != 0);
    sbuf_t *out = sbufIsSplice(s->tx_active) && length > sbufGetResidentPrefixLength(s->tx_active)
                      ? bufferpoolGetSpliceBuffer(s->pool)
                      : NULL;
    if (out && sbufGetHeadroom(out) < s->padding)
    {
        bufferpoolReuseBuffer(s->pool, out);
        out = NULL;
    }
    out = sbufMoveRangeTo(s->pool, s->tx_active, out, length, length, s->padding);
    sbufShiftLeft(out, kStripeHeaderSize);
    stripeHeader(sbufGetMutablePtr(out), kStripeData, (uint32_t) length, s->tx_offset, s->tx_index);
    bufferbudgetReservationSetBytes(&s->tx_reservation, sbufGetLength(s->tx_active));
    if (sbufGetLength(s->tx_active) == 0)
    {
        bufferpoolReuseBuffer(s->pool, s->tx_active);
        s->tx_active = NULL;
        bufferbudgetReservationRelease(&s->tx_reservation);
    }
    s->tx_offset += length;
    s->sent_ends[s->tx_index % kStripeFrameWindow] = s->tx_offset;
    ++s->tx_index;
    s->cursor = (uint16_t) ((index + 1) % s->count);
    stripeSend(s, (unsigned) index, out);
    return true;
}

static void stripePump(stripe_session_t *s)
{
    if (s->closed || s->initializing)
        return;
    if (s->pumping)
    {
        s->pump_requested = true;
        return;
    }
    stripeRef(s);
    s->pumping = true;
    bool progress;
    do
    {
        s->pump_requested = false;
        progress          = false;
        if (s->ready)
        {
            while (! s->closed && stripeDeliver(s))
                progress = true;
            if (s->closed)
                break;
            if (s->credit_dirty)
            {
                s->credit_dirty = false;
                stripeControl(s, kStripeWindow, s->rx_offset, s->rx_index);
            }
            if (s->closed)
                break;
            if (s->remote_close && s->rx_index == s->rx_final_index && ! s->remote_acked)
            {
                if (s->rx_offset != s->rx_final_offset)
                {
                    stripeAbort(s, "CLOSE final byte count disagrees with consumed DATA");
                    break;
                }
                s->remote_acked = true;
                stripeControl(s, kStripeCloseAck, s->rx_final_offset, s->rx_final_index);
                if (s->closed)
                    break;
                stripeBeginClose(s);
                if (s->closed)
                    break;
                line_t *app    = s->application;
                s->application = NULL;
                if (app)
                    stripeFinishLine(s, app, kStripeApplicationLine, kStripeFinishInitiated);
                if (s->closed)
                    break;
                progress = true;
            }
            while (! s->closed && stripeTransmit(s))
                progress = true;
            if (s->closed)
                break;
            if (s->local_close && ! s->close_sent && s->tx_offset == s->tx_accepted)
            {
                s->close_sent = true;
                stripeControl(s, kStripeClose, s->tx_offset, s->tx_index);
            }
            if (s->closed)
                break;
            if (s->close_acked && s->remote_acked)
            {
                stripeAbort(s, "protocol close completed"); /* every accepted byte has crossed its final barrier */
                break;
            }
        }
        /* Resume may synchronously admit payload or Finish after the data
         * drains above. Honour its pump request before returning idle. */
        stripeSourcePressure(s);
    } while (! s->closed && (progress || s->pump_requested));
    s->pumping = false;
    stripeUnref(s);
}

void connectionstripeApplicationPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    stripe_line_t    *ls = lineGetState(line, t);
    stripe_session_t *s  = ls->session;
    assert(s && ls->role == kStripeApplicationLine);
    stripeRef(s);
    size_t length = sbufGetLength(buf);
    if (s->closed || s->local_close || length == 0)
    {
        bufferpoolReuseBuffer(s->pool, buf);
        stripeUnref(s);
        return;
    }
    if (length > stripeState(t)->max_buffered || UINT64_MAX - s->tx_accepted < length)
    {
        bufferpoolReuseBuffer(s->pool, buf);
        stripeAbort(s,
                    length > stripeState(t)->max_buffered ? "application payload exceeds max-buffered-bytes"
                                                          : "application byte counter exhausted");
        stripeUnref(s);
        return;
    }
    /* Keep suitable pipe input, but never retain a large allocation for a tiny
     * payload. Queue charge is local policy, not kernel pipe memory. */
    size_t                     charge;
    const buffer_budget_cost_t used = bufferbudgetGetUsage(&s->tx_budget);
    if (! sbufIsSplice(buf) || ! sbufTryGetQueueCharge(buf, &charge) || charge > stripeCanonicalCharge(s, length) ||
        charge > stripeState(t)->max_buffered - used.charge)
        buf = stripeCanonicalCopy(s, buf);
    if (! bufferqueueTryPushBack(&s->tx_queue, &buf))
    {
        bufferpoolReuseBuffer(s->pool, buf);
        stripeAbort(s, "application queue byte or allocation-charge limit exceeded");
    }
    else
    {
        s->tx_accepted += length;
        stripePump(s);
    }
    stripeUnref(s);
}

static bool stripeAcceptData(stripe_session_t *s, uint64_t offset, uint64_t index, sbuf_t *body)
{
    const size_t   length = sbufGetLength(body);
    const uint64_t window = stripeState(s->tunnel)->receive_window;
    if (index == UINT64_MAX || index < s->rx_index || index - s->rx_index >= kStripeFrameWindow ||
        offset < s->rx_offset || offset - s->rx_offset > window || length > window - (offset - s->rx_offset) ||
        UINT64_MAX - offset < length || s->rx_bytes > window - length ||
        (s->remote_close && (index >= s->rx_final_index || offset + length > s->rx_final_offset)))
        goto reject;
    stripe_record_t *slot = &s->records[index % kStripeFrameWindow];
    if (slot->body)
        goto reject;
    for (unsigned i = 0; i < kStripeFrameWindow; ++i)
    {
        stripe_record_t *other = &s->records[i];
        if (! other->body)
            continue;
        if ((other->index < index && other->offset + sbufGetLength(other->body) > offset) ||
            (other->index > index && offset + length > other->offset))
            goto reject;
    }
    /* Preserve a private pipe or a suitably sized ordinary extraction, with
     * the same window-plus-record storage allowance as exact ordinary copies. */
    size_t charge;
    if (sbufGetHeadroom(body) < s->padding || ! sbufTryGetQueueCharge(body, &charge) ||
        charge > stripeCanonicalCharge(s, length))
        body = stripeCanonicalCopy(s, body);
    *slot = (stripe_record_t) {.body = body, .offset = offset, .index = index};
    s->rx_bytes += length;
    return true;
reject:
    bufferpoolReuseBuffer(s->pool, body);
    return false;
}

static bool stripeAcceptControl(stripe_session_t *s, uint8_t type, uint64_t offset, uint64_t aux)
{
    stripe_state_t *ts = stripeState(s->tunnel);
    switch (type)
    {
    case kStripeReady:
        if (ts->role != kStripeClientEndpoint || s->ready || aux != s->count || offset < kStripeMinReceiveWindow ||
            offset > kStripeMaxReceiveWindow)
            return false;
        s->peer_window = (uint32_t) offset;
        s->ready       = true;
        stripeRemoveDeadline(&s->deadline);
        return true;
    case kStripeWindow:
        if (! s->ready || aux < s->tx_ack_index || aux > s->tx_index || offset < s->tx_ack_offset ||
            offset > s->tx_offset)
            return false;
        if (aux == s->tx_ack_index)
            return offset == s->tx_ack_offset;
        if (s->sent_ends[(aux - 1) % kStripeFrameWindow] != offset)
            return false;
        s->tx_ack_index  = aux;
        s->tx_ack_offset = offset;
        return true;
    case kStripeClose:
        if (! s->ready || s->remote_close || aux < s->rx_index || aux - s->rx_index > kStripeFrameWindow ||
            offset < s->rx_offset || offset - s->rx_offset > ts->receive_window ||
            (aux == s->rx_index && offset != s->rx_offset))
            return false;
        for (unsigned i = 0; i < kStripeFrameWindow; ++i)
            if (s->records[i].body &&
                (s->records[i].index >= aux || s->records[i].offset + sbufGetLength(s->records[i].body) > offset))
                return false;
        s->remote_close    = true;
        s->rx_final_offset = offset;
        s->rx_final_index  = aux;
        return stripeStartDrain(s);
    case kStripeCloseAck:
        if (! s->close_sent || s->close_acked || offset != s->tx_offset || aux != s->tx_index)
            return false;
        s->close_acked = true;
        return true;
    default:
        return false;
    }
}

static void stripeReadFrames(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    stripe_line_t    *ls = lineGetState(line, t);
    stripe_session_t *s  = ls->session;
    assert(s && ls->role == kStripeTransportLine);
    stripeRef(s);
    lineRef(line);
    splice_frame_admit_t result = spliceframereaderAdmit(&ls->reader, buf);
    if (result == kSpliceFrameQueued || result == kSpliceFrameEmpty)
        goto done;
    if (result != kSpliceFrameDrain)
    {
        stripeAbort(s, "frame parser admission refused");
        goto done;
    }
    while (! s->closed && lineIsAlive(line) && ls->session == s)
    {
        const uint8_t *p = spliceframereaderPeekHeader(&ls->reader);
        if (! p)
            break;
        uint8_t  type   = p[0];
        uint32_t length = GET_BE32(p + 4);
        uint64_t offset = GET_BE64(p + 8);
        uint64_t aux    = GET_BE64(p + 16);
        bool     data   = type == kStripeData;
        if (p[1] || p[2] || p[3] ||
            (data ? ((! s->ready && stripeState(t)->role != kStripeClientEndpoint) || length == 0 ||
                     length > kStripeMaxFrame)
                  : (length != 0 || ls->index != 0)))
        {
            stripeAbort(s, "invalid frame header, lane or readiness");
            break;
        }
        if (! spliceframereaderBodyReady(&ls->reader, length))
            break;
        bool valid;
        if (data)
        {
            sbuf_t *body = spliceframereaderTakeFrame(&ls->reader, length);
            valid        = stripeAcceptData(s, offset, aux, body);
        }
        else
        {
            spliceframereaderDiscardFrame(&ls->reader, 0);
            valid = stripeAcceptControl(s, type, offset, aux);
        }
        if (! valid)
        {
            stripeAbort(s, data ? "invalid DATA range or receive window" : "invalid control frame or session state");
            break;
        }
        stripePump(s);
    }
    if (! s->closed && lineIsAlive(line) && ls->session == s && ! spliceframereaderEndDrain(&ls->reader))
        stripeAbort(s, "frame parser retained allocation-charge limit exceeded");
done:
    lineUnref(line);
    stripeUnref(s);
}

static void stripeLineInit(tunnel_t *t, line_t *line, stripe_session_t *s, stripe_line_role_t role, unsigned index)
{
    stripe_line_t *ls = lineGetState(line, t);
    *ls = (stripe_line_t) {.session = s, .line = line, .tunnel = t, .role = role, .index = (uint16_t) index};
    if (role == kStripeTransportLine)
        spliceframereaderInit(&ls->reader,
                              lineGetBufferPool(line),
                              kStripeHeaderSize,
                              stripeState(t)->max_buffered,
                              stripeState(t)->max_buffered,
                              tunnelGetChain(t)->supports_splice);
}

static void stripeServerReady(stripe_session_t *s)
{
    tunnel_t *t     = s->tunnel;
    s->initializing = true;
    /* The complete group can retain a final server-first reply even if its
     * application finishes inside Init. Wire delivery remains behind Init. */
    s->ready = true;
    stripeRemoveDeadline(&s->deadline);
    line_t *app = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), s->wid);
    stripeLineInit(t, app, s, kStripeApplicationLine, 0);
    s->application = app;
    lineCopyUsers(app, s->lanes[0]);
    addresscontextCopy(lineGetSourceAddressContext(app), lineGetSourceAddressContext(s->lanes[0]));
    lineRef(app);
    stripeState(t)->output->init_owned(t, app);
    if (! s->closed)
    {
        s->initializing = false;
        stripeControl(s, kStripeReady, stripeState(t)->receive_window, s->count);
        stripePump(s);
    }
    lineUnref(app);
}

/* A server inlet remains unassociated until its full bounded JOIN is known.
 * Worker routing uses immutable configuration and ID bytes, never foreign line
 * state. The replay through PipeTunnel initializes a fresh target line. */
static void stripeServerJoin(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    stripe_line_t  *ls        = lineGetState(line, t);
    stripe_state_t *ts        = stripeState(t);
    const char     *rejection = "invalid JOIN header, member index, count or receive window";
    /* Existing owners may flush synchronously during drain. They must not
     * complete a pending group or create another application after quiescence. */
    if (stripeWorker(t, lineGetWID(line))->quiesced || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(line))))
    {
        rejection = "JOIN admission closed";
        goto reject;
    }
    const size_t take = min(sbufGetLength(buf), (size_t) (kStripeJoinSize - ls->intro_have));
    sbufReadRangeToMemory(buf, ls->intro + ls->intro_have, take);
    ls->intro_have += (uint16_t) take;
    if (ls->intro_have != kStripeJoinSize)
    {
        lineReuseBuffer(line, buf);
        return;
    }
    const uint8_t *p      = ls->intro;
    uint16_t       index  = GET_BE16(p + 40);
    uint16_t       count  = GET_BE16(p + 42);
    uint32_t       window = GET_BE32(p + 44);
    if (p[0] != kStripeJoin || p[1] || p[2] || p[3] || GET_BE32(p + 4) != kStripeJoinBodySize || GET_BE64(p + 8) ||
        GET_BE64(p + 16) || ! count || count > ts->connections || index >= count || window < kStripeMinReceiveWindow ||
        window > kStripeMaxReceiveWindow)
        goto reject;
    stripe_id_t id;
    memoryCopy(id.bytes, p + kStripeHeaderSize, sizeof(id.bytes));
    id.hash      = calcHashBytesSeed(id.bytes, sizeof(id.bytes), ts->hash_seed);
    wid_t target = (wid_t) (id.hash % ts->worker_count);
    if (target != lineGetWID(line))
    {
        if (sbufGetLength(buf) > ts->max_buffered)
        {
            rejection = "JOIN replay exceeds max-buffered-bytes";
            goto reject;
        }
        buffer_pool_t *pool   = lineGetBufferPool(line);
        size_t         length = kStripeJoinSize + sbufGetLength(buf);
        sbuf_t        *replay = sbufCreateWithPadding(length, bufferpoolGetSmallBufferPadding(pool));
        sbufSetLength(replay, length);
        memoryCopy(sbufGetMutablePtr(replay), ls->intro, kStripeJoinSize);
        sbufReadRangeToMemory(buf, sbufGetMutablePtr(replay) + kStripeJoinSize, sbufGetLength(buf));
        bufferpoolReuseBuffer(pool, buf);
        const bool paused = ls->paused;
        stripeLineClear(t, line);
        lineRef(line);
        if (pipeTo(t, line, target))
        {
            if (! paused || lineCallWithRef(line, tunnelUpStreamPause, t->prev))
                tunnelUpStreamPayload(t->prev, line, replay);
            else
                bufferpoolReuseBuffer(pool, replay);
        }
        else
        {
            bufferpoolReuseBuffer(pool, replay);
            ts->output->transport_finish(t, line);
        }
        lineUnref(line);
        return;
    }
    stripe_worker_t  *w     = stripeWorker(t, target);
    stripe_map_t_iter found = stripe_map_t_find(&w->sessions, id);
    stripe_session_t *s     = found.ref ? found.ref->second : NULL;
    if (s && (s->count != count || s->peer_window != window || s->lanes[index] || s->ready || s->local_close))
    {
        rejection = "duplicate or inconsistent JOIN for an existing group";
        goto reject;
    }
    if (! s)
    {
        s = stripeSessionCreate(t, target, id, count);
        if (! s)
        {
            rejection = "session admission closed or max-sessions reached";
            goto reject;
        }
        s->peer_window = window;
    }
    stripeRef(s);
    lineRef(line);
    stripeUnlinkPending(ls);
    ls->session     = s;
    ls->index       = index;
    s->lanes[index] = line;
    ++s->joined;
    if (s->joined == s->count)
        stripeServerReady(s);
    if (! s->closed && lineIsAlive(line) && ls->session == s)
        stripeReadFrames(t, line, buf);
    else
        bufferpoolReuseBuffer(s->pool, buf);
    lineUnref(line);
    stripeUnref(s);
    return;
reject:
    LOGD("ConnectionStripeServer: transport rejected: %s", rejection);
    lineReuseBuffer(line, buf);
    stripeLineClear(t, line);
    ts->output->transport_finish(t, line);
}

void connectionstripeTransportPayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    stripe_line_t *ls = lineGetState(line, t);
    assert(ls->role == kStripeTransportLine);
    if (! ls->session)
        stripeServerJoin(t, line, buf);
    else
        stripeReadFrames(t, line, buf);
}

void connectionstripeClientInit(tunnel_t *t, line_t *app)
{
    stripe_state_t *ts = stripeState(t);
    assert(ts->role == kStripeClientEndpoint);
    wid_t wid = lineGetWID(app);
    if (! wloopNormalDispatchAllowed(getWorkerLoop(wid)))
    {
        ts->output->application_finish(t, app);
        return;
    }
    stripe_id_t id;
    do
    {
        getRandomBytes(id.bytes, sizeof(id.bytes));
        id.hash = calcHashBytesSeed(id.bytes, sizeof(id.bytes), ts->hash_seed);
    } while (stripe_map_t_contains(&stripeWorker(t, wid)->sessions, id));
    stripe_session_t *s = stripeSessionCreate(t, wid, id, ts->connections);
    if (! s)
    {
        ts->output->application_finish(t, app);
        return;
    }
    stripeRef(s);
    lineRef(app);
    s->initializing = true;
    s->application  = app;
    stripeLineInit(t, app, s, kStripeApplicationLine, 0);
    for (unsigned i = 0; i < s->count && ! s->closed; ++i)
    {
        line_t *lane = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
        stripeLineInit(t, lane, s, kStripeTransportLine, i);
        s->lanes[i] = lane;
        ++s->joined;
        lineRef(lane);
        ts->output->init_owned(t, lane);
        if (! s->closed)
        {
            sbuf_t  *intro = stripeBuffer(s, kStripeJoinSize);
            uint8_t *p     = sbufGetMutablePtr(intro);
            stripeHeader(p, kStripeJoin, kStripeJoinBodySize, 0, 0);
            memoryCopy(p + kStripeHeaderSize, id.bytes, sizeof(id.bytes));
            PUT_BE16(p + 40, (uint16_t) i);
            PUT_BE16(p + 42, s->count);
            PUT_BE32(p + 44, ts->receive_window);
            stripeSend(s, i, intro);
        }
        lineUnref(lane);
    }
    if (! s->closed)
    {
        s->initializing = false;
        stripeNotifyEstablished(s);
        stripePump(s);
    }
    lineUnref(app);
    stripeUnref(s);
}

void connectionstripeServerInit(tunnel_t *t, line_t *line)
{
    assert(stripeState(t)->role == kStripeServerEndpoint);
    wid_t            wid = lineGetWID(line);
    stripe_worker_t *w   = stripeWorker(t, wid);
    stripeLineInit(t, line, NULL, kStripeTransportLine, 0);
    if (w->quiesced || ! wloopNormalDispatchAllowed(getWorkerLoop(wid)) ||
        w->pending_count >= stripeState(t)->max_pending)
    {
        stripeLineClear(t, line);
        stripeState(t)->output->transport_finish(t, line);
        return;
    }
    stripe_line_t *ls = lineGetState(line, t);
    ls->pending       = true;
    ls->pending_next  = w->pending;
    if (w->pending)
        w->pending->pending_prev = ls;
    w->pending = ls;
    ++w->pending_count;
    ls->deadline = localidletableCreateItem(
        stripeTimers(t, wid), (hash_t) (uintptr_t) ls, ls, stripePendingExpired, stripeState(t)->setup_timeout);
    assert(ls->deadline);
    stripeState(t)->output->est_borrowed(t, line);
}

static void stripeFinish(tunnel_t *t, line_t *line, stripe_line_role_t role)
{
    stripe_line_t    *ls = lineGetState(line, t);
    stripe_session_t *s  = ls->session;
    assert(ls->role == role);
    if (! s)
    {
        stripeLineClear(t, line);
        return;
    }
    stripeRef(s);
    if (role == kStripeApplicationLine)
    {
        assert(s->application == line);
        s->application = NULL;
        stripeFinishLine(s, line, kStripeApplicationLine, kStripeFinishReceived);
        if (! s->closed)
        {
            if (! s->ready)
                stripeAbort(s, "application finished before group readiness");
            else
            {
                stripeBeginClose(s);
                stripePump(s);
            }
        }
    }
    else
    {
        assert(s->lanes[ls->index] == line);
        s->lanes[ls->index] = NULL;
        bool expected       = s->remote_acked && s->close_sent;
        stripeFinishLine(s, line, kStripeTransportLine, kStripeFinishReceived);
        if (! s->closed)
        {
            if (! expected)
                stripeAbort(s, "transport lost before protocol close");
            else
            {
                stripePump(s);
                if (! s->closed && ! s->lanes[0])
                    stripeAbort(s, "control transport closed");
            }
        }
    }
    stripeUnref(s);
}

void connectionstripeApplicationFinish(tunnel_t *t, line_t *line)
{
    stripeFinish(t, line, kStripeApplicationLine);
}

void connectionstripeTransportFinish(tunnel_t *t, line_t *line)
{
    stripeFinish(t, line, kStripeTransportLine);
}

static void stripePressure(tunnel_t *t, line_t *line, stripe_line_role_t role, bool paused)
{
    stripe_line_t    *ls = lineGetState(line, t);
    stripe_session_t *s  = ls->session;
    assert(ls->role == role);
    ls->paused = paused;
    if (! s)
        return;
    stripeRef(s);
    if (role == kStripeApplicationLine)
        s->receive_paused = paused;
    stripePump(s);
    stripeUnref(s);
}

void connectionstripeSetApplicationPaused(tunnel_t *t, line_t *line, bool paused)
{
    stripePressure(t, line, kStripeApplicationLine, paused);
}
void connectionstripeSetTransportPaused(tunnel_t *t, line_t *line, bool paused)
{
    stripePressure(t, line, kStripeTransportLine, paused);
}
void connectionstripeClientTransportEstablished(tunnel_t *t, line_t *line)
{
    stripe_line_t *ls = lineGetState(line, t);
    assert(stripeState(t)->role == kStripeClientEndpoint && ls->role == kStripeTransportLine && ls->session);
    stripe_session_t *s = ls->session;
    stripeRef(s);
    s->est_seen = true;
    stripeNotifyEstablished(s);
    stripeUnref(s);
}

static void stripeWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard          context;
    stripe_worker_t *w = stripeWorker(t, wid);
    w->quiesced        = true;
    if (w->timers)
        localidletableQuiesce(w->timers);
}

static void stripeWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard          context;
    stripe_worker_t *w = stripeWorker(t, wid);
    w->quiesced        = true;
    while (w->head)
        stripeAbort(w->head, "worker stopped");
    while (w->pending)
    {
        line_t *line = w->pending->line;
        stripeLineClear(t, line);
        stripeState(t)->output->transport_finish(t, line);
    }
    if (w->timers)
    {
        assert(localidletableGetItemCount(w->timers) == 0);
        localidletableDestroy(w->timers);
        w->timers = NULL;
    }
}

static void stripeDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard         context;
    stripe_state_t *ts = stripeState(t);
    for (unsigned i = 0; ts->workers && i < ts->worker_count; ++i)
    {
        stripe_worker_t *w = &ts->workers[i];
        assert(! w->head && ! w->pending && ! w->timers);
        stripe_map_t_drop(&w->sessions);
    }
    memoryFree(ts->workers);
    tunnelDestroy(t);
}

static bool stripeSetting(const cJSON *settings, const char *key, uint32_t def, uint32_t low, uint32_t high,
                          uint32_t *out)
{
    int64_t             value  = def;
    json_value_status_t status = jsonGetObjectIntegerInRange(settings, key, low, high, &value);
    if (status == kJsonValueInvalid)
    {
        LOGF("ConnectionStripe: setting '%s' must be an integer from %u to %u", key, (unsigned) low, (unsigned) high);
        return false;
    }
    *out = (uint32_t) value;
    return true;
}

static bool stripeSettings(tunnel_t *t, node_t *node)
{
    const bool   client   = stripeState(t)->role == kStripeClientEndpoint;
    const cJSON *settings = node->node_settings_json;
    if (settings && ! cJSON_IsObject(settings))
    {
        LOGF("ConnectionStripe: 'settings' must be an object");
        return false;
    }
    if (! node->next || ! node->next[0] || ! jsonObjectFieldStringsAreExact(node->node_json, "next"))
    {
        LOGF("ConnectionStripe: 'next' must name a nonempty next node without embedded NUL bytes");
        return false;
    }
    const cJSON *field;
    cJSON_ArrayForEach(field, settings)
    {
        const char *key = field->string;
        if (! key)
        {
            LOGF("ConnectionStripe: every setting must have a name");
            return false;
        }
        bool known = stringCompare(key, client ? "connections" : "max-connections") == 0 ||
                     stringCompare(key, "receive-window-bytes") == 0 || stringCompare(key, "max-buffered-bytes") == 0 ||
                     stringCompare(key, "setup-timeout-ms") == 0 || stringCompare(key, "drain-timeout-ms") == 0 ||
                     stringCompare(key, "max-sessions") == 0 ||
                     (! client && stringCompare(key, "max-pending-connections") == 0);
        if (! known)
        {
            LOGF("ConnectionStripe%s: unknown setting '%s'", client ? "Client" : "Server", key);
            return false;
        }
        for (const cJSON *other = field->next; other; other = other->next)
            if (stringCompare(key, other->string) == 0)
            {
                LOGF("ConnectionStripe: duplicate setting '%s'", key);
                return false;
            }
    }
    stripe_state_t *ts = stripeState(t);
    uint32_t        count;
    if (client && ! cJSON_GetObjectItemCaseSensitive(settings, "connections"))
    {
        LOGF("ConnectionStripeClient: setting 'connections' is required (integer from 1 to %u)",
             (unsigned) kStripeMaxConnections);
        return false;
    }
    if (! stripeSetting(settings,
                        client ? "connections" : "max-connections",
                        kStripeMaxConnections,
                        1,
                        kStripeMaxConnections,
                        &count) ||
        ! stripeSetting(settings,
                        "receive-window-bytes",
                        1024 * 1024,
                        kStripeMinReceiveWindow,
                        kStripeMaxReceiveWindow,
                        &ts->receive_window) ||
        ! stripeSetting(settings, "max-buffered-bytes", 4 * 1024 * 1024, 65536, 64 * 1024 * 1024, &ts->max_buffered) ||
        ! stripeSetting(settings, "setup-timeout-ms", 10000, 1, 600000, &ts->setup_timeout) ||
        ! stripeSetting(settings, "drain-timeout-ms", 10000, 1, 600000, &ts->drain_timeout) ||
        ! stripeSetting(settings, "max-sessions", 1024, 1, 65536, &ts->max_sessions) ||
        ! stripeSetting(settings, "max-pending-connections", 1024, 1, 65536, &ts->max_pending))
        return false;
    ts->connections = (uint16_t) count;
    return true;
}

tunnel_t *connectionstripeCreate(node_t *node, stripe_endpoint_role_t role, const stripe_output_t *output)
{
    assert(node);
    assert(role == kStripeClientEndpoint || role == kStripeServerEndpoint);
    assert(output && output->init_owned && output->est_borrowed && output->transport_payload &&
           output->application_payload && output->application_pause && output->application_resume &&
           output->transport_finish && output->application_finish);
    tunnel_t *t = tunnelCreate(node, sizeof(stripe_state_t), sizeof(stripe_line_t));
    if (! t)
        return NULL;
    t->onDestroy       = stripeDestroy;
    stripe_state_t *ts = stripeState(t);
    ts->role           = role;
    ts->output         = output;
    if (! stripeSettings(t, node))
    {
        stripeDestroy(t, wwLifecycleStartupRollback());
        return NULL;
    }
    ts->hash_seed    = fastRand64();
    ts->worker_count = getWorkersCount();
    ts->workers      = memoryAllocateZero((size_t) ts->worker_count * sizeof(*ts->workers));
    for (unsigned i = 0; i < ts->worker_count; ++i)
        ts->workers[i].sessions = stripe_map_t_init();
    t->onWorkerQuiesce = stripeWorkerQuiesce;
    t->onWorkerStop    = stripeWorkerStop;
    return t;
}
