#include "EnetCommon/session.h"

#include "EnetCommon/driver.h"
#include "buffer_budget.h"
#include "loggers/network_logger.h"

enum
{
    /* Input that arrives from inside a callback waits for the call that is already driving. These bound it. */
    kEnetSessionNestedBytes  = 2 * 1024 * 1024,
    kEnetSessionNestedCharge = 8 * 1024 * 1024,
};

typedef struct enet_work_s
{
    sbuf_t                     *buffer;
    bool                        wire; /* a carrier datagram; otherwise application bytes */
    buffer_budget_reservation_t reservation;
} enet_work_t;
#define i_type enet_work_queue_t
#define i_key  enet_work_t
#include "stc/deque.h"

typedef struct enet_staged_s
{
    sbuf_t *buffer;
} enet_staged_t;
#define i_type enet_staged_queue_t
#define i_key  enet_staged_t
#include "stc/deque.h"

struct enet_session_s
{
    enet_session_config_t    config;
    enet_session_callbacks_t callbacks;
    void                    *user;
    size_t                   references;
    enet_driver_t           *driver;
    wtimer_t                *timer;
    enet_work_queue_t        work;    /* input not yet given to the driver, oldest first */
    enet_staged_queue_t      output;  /* datagrams ENet produced during the last driver call */
    enet_staged_queue_t      inbound; /* stream bytes ENet delivered during the last driver call */
    buffer_budget_t          budget;  /* bounds what work may retain */
    uint64_t                 connect_deadline;
    uint64_t                 close_deadline;
    uint64_t                 current_now;
    enet_driver_close_t      close_reason;
    bool                     started : 1;
    bool                     driving : 1;
    bool                     dead : 1;
    bool                     quiesced : 1;
    bool                     closing : 1;    /* no more application bytes are accepted */
    bool                     close_sent : 1; /* the driver was told to close or abort */
    bool                     connected : 1;
    bool                     connected_pending : 1;
    bool                     closed_pending : 1;
    bool                     service_due : 1;
    bool                     pressure : 1;
};

static uint64_t sessionNow(enet_session_t *s)
{
    return s->config.now != NULL    ? s->config.now(s->config.clock_user)
           : s->config.loop != NULL ? wloopNowMonotonicMS(s->config.loop)
                                    : s->current_now;
}

static uint64_t sessionDeadline(uint64_t start, uint32_t interval)
{
    return start > UINT64_MAX - interval ? UINT64_MAX : start + interval;
}

static const char *sessionRole(const enet_session_t *s)
{
    return s->config.client ? "Client" : "Server";
}

static void sessionDeleteTimer(enet_session_t *s)
{
    if (s->timer != NULL)
    {
        weventSetUserData(s->timer, NULL);
        wtimerDelete(s->timer);
        s->timer = NULL;
    }
}

static void sessionDiscardStaged(enet_session_t *s, enet_staged_queue_t *queue)
{
    while (! enet_staged_queue_t_is_empty(queue))
    {
        bufferpoolReuseBuffer(s->config.pool, enet_staged_queue_t_pull_front(queue).buffer);
    }
}

/* Driver sinks. They run inside a driver call and only stage what they are given. */

static uint8_t *sessionDatagramSink(void *user, size_t length)
{
    enet_session_t *s = user;
    if ((size_t) enet_staged_queue_t_size(&s->output) >= s->config.settings.carrier_queue_limit)
    {
        return NULL; /* the driver counts the drop, and ENet retransmits what was reliable */
    }
    sbuf_t *buffer = bufferpoolTryGetBestFit(s->config.pool, length, 0);
    if (buffer == NULL)
    {
        return NULL;
    }
    sbufSetLength(buffer, length);
    enet_staged_queue_t_push_back(&s->output, (enet_staged_t) {.buffer = buffer});
    return sbufGetMutablePtr(buffer);
}

static void sessionStreamSink(void *user, const uint8_t *data, size_t length)
{
    enet_session_t *s       = user;
    const size_t    largest = bufferpoolGetLargeBufferSize(s->config.pool);
    const uint16_t  padding = bufferpoolGetLargeBufferPadding(s->config.pool);
    /* The stream has no message boundaries, so a large native message becomes several pool-sized buffers. Each
     * keeps the pool's left padding for the tunnels that receive it. */
    while (length > 0)
    {
        const size_t chunk  = min(length, largest);
        sbuf_t      *buffer = bufferpoolGetBestFit(s->config.pool, chunk, padding);
        sbufSetLength(buffer, chunk);
        memoryCopyLarge(sbufGetMutablePtr(buffer), data, chunk);
        enet_staged_queue_t_push_back(&s->inbound, (enet_staged_t) {.buffer = buffer});
        data += chunk;
        length -= chunk;
    }
}

static void sessionConnectedSink(void *user)
{
    enet_session_t *s    = user;
    s->connected         = true;
    s->connected_pending = true;
}

static void sessionClosedSink(void *user, enet_driver_close_t why)
{
    enet_session_t *s = user;
    s->closed_pending = true;
    s->close_reason   = why;
}

void enetSessionRetain(enet_session_t *s)
{
    assert(s != NULL && s->references > 0);
    ++s->references;
}

void enetSessionRelease(enet_session_t *s)
{
    assert(s != NULL && s->references > 0);
    if (--s->references != 0)
    {
        return;
    }
    assert(s->dead);
    sessionDeleteTimer(s);
    while (! enet_work_queue_t_is_empty(&s->work))
    {
        enet_work_t event = enet_work_queue_t_pull_front(&s->work);
        bufferbudgetReservationRelease(&event.reservation);
        bufferpoolReuseBuffer(s->config.pool, event.buffer);
    }
    enet_work_queue_t_drop(&s->work);
    sessionDiscardStaged(s, &s->output);
    enet_staged_queue_t_drop(&s->output);
    sessionDiscardStaged(s, &s->inbound);
    enet_staged_queue_t_drop(&s->inbound);
    bufferbudgetAssertEmpty(&s->budget);
    if (s->driver != NULL)
    {
        enetDriverDestroy(s->driver);
    }
    if (s->callbacks.destroy_user != NULL)
    {
        s->callbacks.destroy_user(s->user);
    }
    memoryFree(s);
}

void enetSessionAbort(enet_session_t *s, enet_session_result_t result)
{
    enetSessionRetain(s);
    if (! s->dead)
    {
        s->dead = true;
        sessionDeleteTimer(s);
        s->callbacks.terminal(s->user, result);
    }
    enetSessionRelease(s);
}

/* Ends a session that this side decided to stop. One native DISCONNECT goes out first, so the peer stops now and
 * not at its own timeout. Only the driving call uses this; an owner's abort emits nothing. */
static void sessionFail(enet_session_t *s, enet_session_result_t result)
{
    assert(s->driving && ! s->dead);
    s->closing    = true;
    s->close_sent = true;
    enetDriverAbort(s->driver, sessionNow(s));
    while (! s->dead && ! s->quiesced && ! enet_staged_queue_t_is_empty(&s->output))
    {
        s->callbacks.emit(s->user, enet_staged_queue_t_pull_front(&s->output).buffer);
    }
    if (! s->dead)
    {
        enetSessionAbort(s, result);
    }
}

static bool sessionExpire(enet_session_t *s, uint64_t now)
{
    if (s->closing && now >= s->close_deadline)
    {
        LOGW("Enet%s: close delivery unconfirmed at the fixed deadline "
             "(close-drain-timeout-ms=%u, unacknowledged_bytes=%zu)",
             sessionRole(s),
             s->config.settings.close_drain_timeout_ms,
             enetDriverQueuedBytes(s->driver));
        sessionFail(s, kEnetSessionDrainTimeout);
        return true;
    }
    if (! s->config.client && ! s->connected && now >= s->connect_deadline)
    {
        LOGD("EnetServer: closing carrier: no native connection (no-recv-timeout-ms=%u)",
             s->config.settings.no_recv_timeout_ms);
        sessionFail(s, kEnetSessionConnectTimeout);
        return true;
    }
    return false;
}

/* Gives accepted application bytes to ENet. Returns false when the driver refused them. */
static bool sessionWrite(enet_session_t *s, const sbuf_t *payload, uint64_t now)
{
    const enet_driver_state_t state = enetDriverState(s->driver);
    if (sbufGetLength(payload) == 0 || (state != kEnetDriverStateConnecting && state != kEnetDriverStateConnected))
    {
        return true;
    }
    if (enetDriverWrite(s->driver, sbufGetRawPtr(payload), sbufGetLength(payload), now))
    {
        return true;
    }
    LOGW("Enet%s: closing session: the send limit refused a payload "
         "(unacknowledged_bytes=%zu, send-buffer-limit=%u, payload_bytes=%zu)",
         sessionRole(s),
         enetDriverQueuedBytes(s->driver),
         s->config.settings.send_buffer_limit,
         (size_t) sbufGetLength(payload));
    return false;
}

/* Hands the results of the last driver call to the owner: connect, then datagrams, then stream bytes, then the
 * end of the session. Any callback can end or quiesce the session, so each step checks again. */
static void sessionFlush(enet_session_t *s)
{
    if (s->connected_pending)
    {
        s->connected_pending = false;
        if (s->callbacks.connected != NULL)
        {
            s->callbacks.connected(s->user);
        }
    }
    while (! s->dead && ! s->quiesced && ! enet_staged_queue_t_is_empty(&s->output))
    {
        s->callbacks.emit(s->user, enet_staged_queue_t_pull_front(&s->output).buffer);
    }
    while (! s->dead && ! s->quiesced && ! enet_staged_queue_t_is_empty(&s->inbound))
    {
        sbuf_t *payload = enet_staged_queue_t_pull_front(&s->inbound).buffer;
        if (s->closing || s->callbacks.payload == NULL)
        {
            bufferpoolReuseBuffer(s->config.pool, payload); /* the application already finished */
        }
        else
        {
            s->callbacks.payload(s->user, payload);
        }
    }
    if (s->dead || s->quiesced)
    {
        return;
    }
    if (s->closed_pending)
    {
        s->closed_pending = false;
        enetSessionAbort(s,
                         s->close_reason == kEnetDriverCloseLocal    ? kEnetSessionClosed
                         : s->close_reason == kEnetDriverCloseRemote ? kEnetSessionPeerClosed
                                                                     : kEnetSessionProtocolFailure);
        return;
    }
    const bool hold = enetDriverSendHold(s->driver);
    if (! s->closing && s->callbacks.pressure != NULL && hold != s->pressure)
    {
        s->pressure = hold;
        s->callbacks.pressure(s->user, hold);
    }
}

static void sessionArmTimer(enet_session_t *s, uint64_t now)
{
    if (s->timer == NULL)
    {
        return;
    }
    uint64_t delay = enetDriverNextServiceDelayMs(s->driver, now);
    if (s->closing)
    {
        delay = min(delay, s->close_deadline > now ? s->close_deadline - now : 1U);
    }
    if (! s->config.client && ! s->connected)
    {
        delay = min(delay, s->connect_deadline > now ? s->connect_deadline - now : 1U);
    }
    wtimerReset(s->timer, delay > UINT32_MAX ? UINT32_MAX : max((uint32_t) delay, 1U));
}

/* The serialized driver. One call at a time takes one piece of work, lets ENet run, and hands the results out.
 * Work that callbacks add meanwhile is taken by the same loop, in order. */
static void sessionDrive(enet_session_t *s)
{
    if (s->driving || s->dead || s->quiesced || ! s->started)
    {
        return;
    }
    enetSessionRetain(s);
    s->driving = true;
    while (! s->dead && ! s->quiesced)
    {
        const uint64_t now = sessionNow(s);
        if (sessionExpire(s, now))
        {
            break;
        }
        if (! enet_work_queue_t_is_empty(&s->work))
        {
            enet_work_t event = enet_work_queue_t_pull_front(&s->work);
            bool        taken = true;
            if (event.wire)
            {
                enetDriverInput(s->driver, sbufGetRawPtr(event.buffer), sbufGetLength(event.buffer), now);
            }
            else
            {
                taken = sessionWrite(s, event.buffer, now);
            }
            bufferpoolReuseBuffer(s->config.pool, event.buffer);
            bufferbudgetReservationRelease(&event.reservation);
            if (! taken)
            {
                sessionFail(s, kEnetSessionCapacityFailure);
                break;
            }
        }
        else if (s->service_due)
        {
            s->service_due = false;
            enetDriverService(s->driver, now);
        }
        else if (s->closing && ! s->close_sent)
        {
            /* Every accepted payload has reached ENet, so the close follows them. */
            s->close_sent = true;
            enetDriverClose(s->driver, now);
        }
        else
        {
            break;
        }
        sessionFlush(s);
    }
    s->driving = false;
    if (! s->dead && ! s->quiesced)
    {
        sessionArmTimer(s, sessionNow(s));
    }
    enetSessionRelease(s);
}

static void sessionSubmit(enet_session_t *s, sbuf_t *buffer, bool wire)
{
    enetSessionRetain(s);
    if (s->dead || s->quiesced || (! wire && s->closing))
    {
        bufferpoolReuseBuffer(s->config.pool, buffer);
    }
    else
    {
        enet_work_t event = {.buffer = buffer, .wire = wire};
        if (! bufferbudgetTryReserve(&s->budget, buffer, &event.reservation))
        {
            const buffer_budget_cost_t used   = bufferbudgetGetUsage(&s->budget);
            const buffer_budget_cost_t limits = bufferbudgetGetLimits(&s->budget);
            LOGW("Enet%s: closing session: %s input retention admission refused "
                 "(retained_bytes=%zu, incoming_bytes=%zu, byte_limit=%zu)",
                 sessionRole(s),
                 wire ? "carrier" : "nested application",
                 used.bytes,
                 (size_t) sbufGetLength(buffer),
                 limits.bytes);
            bufferpoolReuseBuffer(s->config.pool, buffer);
            enetSessionAbort(s, kEnetSessionCapacityFailure);
        }
        else
        {
            enet_work_queue_t_push_back(&s->work, event);
            sessionDrive(s);
        }
    }
    enetSessionRelease(s);
}

void enetSessionSend(enet_session_t *s, sbuf_t *payload)
{
    sessionSubmit(s, payload, false);
}

void enetSessionInput(enet_session_t *s, sbuf_t *packet)
{
    sessionSubmit(s, packet, true);
}

void enetSessionAppFinish(enet_session_t *s)
{
    enetSessionRetain(s);
    if (s->quiesced)
    {
        enetSessionAbort(s, kEnetSessionAborted);
    }
    else if (! s->dead && ! s->closing)
    {
        /* The first closing event fixes the deadline; later progress never moves it. */
        s->closing        = true;
        s->close_deadline = sessionDeadline(sessionNow(s), s->config.settings.close_drain_timeout_ms);
        sessionDrive(s);
    }
    enetSessionRelease(s);
}

void enetSessionStart(enet_session_t *s)
{
    enetSessionRetain(s);
    if (! s->dead && ! s->quiesced && ! s->started)
    {
        s->started     = true;
        s->service_due = true; /* a client sends its connect request now */
        sessionDrive(s);
    }
    enetSessionRelease(s);
}

void enetSessionTick(enet_session_t *s, uint64_t now)
{
    enetSessionRetain(s);
    s->current_now = now;
    if (! s->dead && ! s->quiesced && s->started)
    {
        s->service_due = true;
        sessionDrive(s);
    }
    enetSessionRelease(s);
}

void enetSessionQuiesce(enet_session_t *s)
{
    s->quiesced = true;
    sessionDeleteTimer(s);
}

static void sessionTimerCallback(wtimer_t *timer)
{
    enet_session_t *s = weventGetUserdata(timer);
    assert(s != NULL && s->timer == timer);
    enetSessionTick(s, sessionNow(s));
}

enet_session_t *enetSessionCreate(const enet_session_config_t *config, const enet_session_callbacks_t *callbacks,
                                  void *user)
{
    assert(config != NULL && callbacks != NULL && config->pool != NULL);
    assert(callbacks->emit != NULL && callbacks->terminal != NULL);
    enet_session_t *s = memoryAllocate(sizeof(*s));
    *s                = (enet_session_t) {.config = *config, .callbacks = *callbacks, .user = user, .references = 1};
    bufferbudgetInit(&s->budget,
                     (buffer_budget_cost_t) {.bytes = kEnetSessionNestedBytes, .charge = kEnetSessionNestedCharge});
    const uint64_t now  = sessionNow(s);
    s->connect_deadline = sessionDeadline(now, config->settings.no_recv_timeout_ms);

    const enet_driver_config_t driver_config = {
        .role                 = config->client ? kEnetDriverRoleClient : kEnetDriverRoleServer,
        .host_mtu             = config->settings.host_mtu,
        .ping_interval_ms     = config->settings.ping_interval_ms,
        .no_recv_timeout_ms   = config->settings.no_recv_timeout_ms,
        .send_buffer_limit    = config->settings.send_buffer_limit,
        .receive_buffer_limit = config->settings.receive_buffer_limit,
        .incoming_bandwidth   = config->settings.incoming_bandwidth,
        .outgoing_bandwidth   = config->settings.outgoing_bandwidth,
        .random_seed          = fastRand32(),
    };
    const enet_driver_sinks_t sinks = {
        .datagram  = sessionDatagramSink,
        .stream    = sessionStreamSink,
        .connected = sessionConnectedSink,
        .closed    = sessionClosedSink,
    };
    s->driver = enetDriverCreate(&driver_config, &sinks, s, now);
    if (config->loop != NULL)
    {
        s->timer = wtimerAdd(config->loop, sessionTimerCallback, kEnetDriverActiveTickMs, INFINITE);
    }
    if (s->driver == NULL || (config->loop != NULL && s->timer == NULL))
    {
        s->callbacks.destroy_user = NULL;
        s->dead                   = true;
        enetSessionRelease(s);
        return NULL;
    }
    if (s->timer != NULL)
    {
        weventSetUserData(s->timer, s);
    }
    return s;
}

bool enetSessionIsAlive(const enet_session_t *s)
{
    return ! s->dead;
}

bool enetSessionIsConnected(const enet_session_t *s)
{
    return s->connected && ! s->dead;
}

bool enetSessionIsPressured(const enet_session_t *s)
{
    return s->pressure;
}

size_t enetSessionQueuedBytes(const enet_session_t *s)
{
    return enetDriverQueuedBytes(s->driver);
}

uint64_t enetSessionDroppedDatagrams(const enet_session_t *s)
{
    return enetDriverDroppedDatagrams(s->driver);
}

uint64_t enetSessionCloseDeadline(const enet_session_t *s)
{
    return s->close_deadline;
}
