#include "GnsCommon/session.h"

#include "GnsCommon/engine.h"
#include "GnsCommon/port.h"
#include "buffer_budget.h"
#include "loggers/network_logger.h"

enum
{
    /* Input that arrives from inside a callback waits for the call that is already driving. These bound it. */
    kGnsSessionNestedBytes  = 2 * 1024 * 1024,
    kGnsSessionNestedCharge = 8 * 1024 * 1024,
    /* How often a drive takes what GNS's own thread left in the port before it lets the worker do other work. */
    kGnsSessionRounds       = 4,
    kGnsSessionReceiveBatch = 16,
    /* GNS runs its own timers. The session's timer only carries its deadlines and looks for what GNS decided on
     * its service thread, such as a timeout. */
    kGnsSessionPollConnectingMs = 250,
    kGnsSessionPollConnectedMs  = 1000,
    /* GNS keeps a closed connection for five seconds to answer late packets. The session keeps its endpoint and its
     * carrier this long for the same purpose: long enough for what was already on its way. */
    kGnsSessionCloseLingerMs   = 1000,
    kGnsEndReasonTimeoutRemote = 4001, /* k_ESteamNetConnectionEnd_Remote_Timeout */
    kGnsEndReasonTimeoutLocal  = 5003, /* k_ESteamNetConnectionEnd_Misc_Timeout */
};

typedef struct gns_work_s
{
    sbuf_t                     *buffer;
    bool                        wire; /* a carrier datagram; otherwise application bytes */
    buffer_budget_reservation_t reservation;
} gns_work_t;
#define i_type gns_work_queue_t
#define i_key  gns_work_t
#include "stc/deque.h"

typedef struct gns_staged_s
{
    sbuf_t *buffer;
} gns_staged_t;
#define i_type gns_staged_queue_t
#define i_key  gns_staged_t
#include "stc/deque.h"

#define i_type gns_offset_queue_t
#define i_key  uint64_t
#include "stc/deque.h"

struct gns_session_s
{
    gns_session_config_t     config;
    gns_session_callbacks_t  callbacks;
    void                    *user;
    size_t                   references;
    gns_port_t              *port;
    gns_external_endpoint_t *endpoint;
    gns_external_addr_t      address; /* the endpoint's registration key */
    gns_external_addr_t      peer;    /* server: the source address its carrier's datagrams are given */
    uint32_t                 listen;
    uint32_t                 connection;
    wtimer_t                *timer;
    gns_work_queue_t         work;        /* input not yet given to GNS, oldest first */
    gns_staged_queue_t       inbound;     /* stream bytes taken from GNS and not yet handed to the owner */
    gns_offset_queue_t       messages;    /* stream offsets at which unacknowledged messages end, oldest first */
    buffer_budget_t          budget;      /* bounds what work may retain */
    uint64_t                 submitted;   /* stream bytes given to GNS so far */
    uint64_t                 outstanding; /* queued plus unacknowledged bytes: last reading plus later writes */
    uint64_t                 connect_deadline;
    uint64_t                 close_deadline;
    uint64_t                 linger_deadline;
    bool                     opened : 1; /* the listen socket or the connection was asked for */
    bool                     started : 1;
    bool                     driving : 1;
    bool                     dead : 1;
    bool                     quiesced : 1;
    bool                     closing : 1;    /* no more application bytes are accepted */
    bool                     close_sent : 1; /* this side closed the native connection */
    bool                     connected : 1;
    bool                     pressure : 1;
};

static uint64_t sessionNow(gns_session_t *s)
{
    return wloopNowMonotonicMS(s->config.loop);
}

static uint64_t sessionDeadline(uint64_t start, uint32_t interval)
{
    return start > UINT64_MAX - interval ? UINT64_MAX : start + interval;
}

static const char *sessionRole(const gns_session_t *s)
{
    return s->config.client ? "Client" : "Server";
}

static void sessionDeleteTimer(gns_session_t *s)
{
    if (s->timer != NULL)
    {
        weventSetUserData(s->timer, NULL);
        wtimerDelete(s->timer);
        s->timer = NULL;
    }
}

static void sessionDiscardInbound(gns_session_t *s)
{
    while (! gns_staged_queue_t_is_empty(&s->inbound))
    {
        bufferpoolReuseBuffer(s->config.pool, gns_staged_queue_t_pull_front(&s->inbound).buffer);
    }
}

void gnsSessionRetain(gns_session_t *s)
{
    assert(s != NULL && s->references > 0);
    ++s->references;
}

void gnsSessionRelease(gns_session_t *s)
{
    assert(s != NULL && s->references > 0);
    if (--s->references != 0)
    {
        return;
    }
    assert(s->dead);
    sessionDeleteTimer(s);
    while (! gns_work_queue_t_is_empty(&s->work))
    {
        gns_work_t event = gns_work_queue_t_pull_front(&s->work);
        bufferbudgetReservationRelease(&event.reservation);
        bufferpoolReuseBuffer(s->config.pool, event.buffer);
    }
    gns_work_queue_t_drop(&s->work);
    sessionDiscardInbound(s);
    gns_staged_queue_t_drop(&s->inbound);
    gns_offset_queue_t_drop(&s->messages);
    bufferbudgetAssertEmpty(&s->budget);
    gnsPortRelease(s->port);
    if (s->callbacks.destroy_user != NULL)
    {
        s->callbacks.destroy_user(s->user);
    }
    memoryFree(s);
}

/* Gives back what GNS holds for the session and cuts the port off. Nothing reaches the session from GNS after it:
 * the close notice that GNS writes here is discarded with the rest of the port. */
static void sessionTeardown(gns_session_t *s)
{
    if (s->connection != 0 && ! s->close_sent)
    {
        s->close_sent = true;
        gnsEngineClose(s->connection);
    }
    if (s->listen != 0)
    {
        /* Also ends a connection that was admitted and never reached the session. */
        gnsEngineCloseListen(s->listen);
        s->listen = 0;
    }
    gnsPortDetach(s->port);
    if (s->endpoint != NULL)
    {
        gns_external_endpoint_release(s->endpoint);
        s->endpoint = NULL;
    }
}

void gnsSessionAbort(gns_session_t *s, gns_session_result_t result)
{
    gnsSessionRetain(s);
    if (! s->dead)
    {
        s->dead = true;
        sessionDeleteTimer(s);
        sessionTeardown(s);
        s->callbacks.terminal(s->user, result);
    }
    gnsSessionRelease(s);
}

/* Takes what GNS left in the port: the datagrams go to the carrier, and a server learns its connection here. Every
 * datagram is copied into a buffer of this worker's pool. */
static void sessionEmit(gns_session_t *s)
{
    uint32_t             incoming = 0;
    gns_port_datagram_t *list     = gnsPortTake(s->port, &incoming);
    if (s->connection == 0 && ! s->close_sent)
    {
        s->connection = incoming;
    }
    while (list != NULL)
    {
        gns_port_datagram_t *next = list->next;
        if (! s->dead && ! s->quiesced)
        {
            sbuf_t *packet = bufferpoolGetBestFit(s->config.pool, list->length, 0);
            sbufSetLength(packet, list->length);
            memoryCopy(sbufGetMutablePtr(packet), list->bytes, list->length);
            s->callbacks.emit(s->user, packet);
        }
        gnsPortDatagramFree(list);
        list = next;
    }
}

/* Ends a session that this side decided to stop. The native close goes out first, so the peer stops now and not
 * at its own timeout. Only the driving call uses this; an owner's abort emits nothing. */
static void sessionFail(gns_session_t *s, gns_session_result_t result)
{
    assert(s->driving && ! s->dead);
    s->closing = true;
    if (s->connection != 0 && ! s->close_sent)
    {
        s->close_sent = true;
        gnsEngineClose(s->connection);
        sessionEmit(s);
    }
    if (! s->dead)
    {
        gnsSessionAbort(s, result);
    }
}

static bool sessionExpire(gns_session_t *s, uint64_t now)
{
    if (s->close_sent)
    {
        if (now >= s->linger_deadline)
        {
            gnsSessionAbort(s, kGnsSessionClosed);
            return true;
        }
        return false;
    }
    if (s->closing && now >= s->close_deadline)
    {
        LOGW("Gns%s: close delivery unconfirmed at the fixed deadline "
             "(close-drain-timeout-ms=%u, unacknowledged_bytes=%llu)",
             sessionRole(s),
             s->config.settings.close_drain_timeout_ms,
             (unsigned long long) s->outstanding);
        sessionFail(s, kGnsSessionDrainTimeout);
        return true;
    }
    if (! s->config.client && ! s->connected && now >= s->connect_deadline)
    {
        LOGD("GnsServer: closing carrier: no native connection (timeout-initial-ms=%u)",
             s->config.settings.timeout_initial_ms);
        sessionFail(s, kGnsSessionConnectTimeout);
        return true;
    }
    return false;
}

/* Asks GNS for the listen socket or the connection. A client's first datagram is in the port when this returns. */
static bool sessionOpen(gns_session_t *s)
{
    const gns_settings_t      *settings = &s->config.settings;
    const gns_engine_options_t options  = {
         .packet_size          = (int32_t) settings->packet_size,
         .send_rate            = (int32_t) settings->send_rate,
         .timeout_initial_ms   = (int32_t) settings->timeout_initial_ms,
         .timeout_connected_ms = (int32_t) settings->no_recv_timeout_ms,
         .receive_buffer       = (int32_t) settings->receive_buffer_limit,
         .receive_messages     = (int32_t) settings->receive_messages_limit,
         .receive_message_max  = (int32_t) (settings->receive_buffer_limit / 2U),
    };
    if (s->config.client)
    {
        s->connection = gnsEngineConnect(&s->address, &options);
        return s->connection != 0;
    }
    s->listen = gnsEngineListen(&s->address, &options, gnsPortToken(s->port));
    return s->listen != 0;
}

/* Gives accepted application bytes to GNS as messages of at most 65,536 bytes. Returns false when a limit refused
 * them; a payload that is accepted below the limits is admitted whole. */
static bool sessionWrite(gns_session_t *s, const sbuf_t *payload)
{
    const uint32_t length = (uint32_t) sbufGetLength(payload);
    if (length == 0 || s->connection == 0 || s->close_sent)
    {
        return true;
    }
    const size_t waiting = (size_t) gns_offset_queue_t_size(&s->messages);
    if (s->outstanding > s->config.settings.send_hard_limit || waiting >= kGnsMessagesHardLimit)
    {
        LOGW("Gns%s: closing session: the send limit refused a payload "
             "(unacknowledged_bytes=%llu, unacknowledged_messages=%zu, send-buffer-limit=%u, payload_bytes=%u)",
             sessionRole(s),
             (unsigned long long) s->outstanding,
             waiting,
             s->config.settings.send_buffer_limit,
             length);
        return false;
    }
    const uint8_t *bytes = sbufGetRawPtr(payload);
    for (uint32_t offset = 0; offset < length;)
    {
        const uint32_t          chunk  = min(length - offset, (uint32_t) kGnsMessageBytesMaximum);
        const gns_engine_send_t result = gnsEngineSend(s->connection, bytes + offset, chunk);
        if (result == kGnsEngineSendFailed)
        {
            return true; /* the connection is gone; the status that is read next ends the session */
        }
        if (result == kGnsEngineSendRefused)
        {
            LOGW("Gns%s: closing session: GNS refused a message below the session's own limit", sessionRole(s));
            return false;
        }
        offset += chunk;
        s->submitted += chunk;
        s->outstanding += chunk;
        gns_offset_queue_t_push_back(&s->messages, s->submitted);
    }
    return true;
}

/* Takes complete messages from GNS and hands their bytes to the owner. The stream has no message boundaries, so a
 * large native message becomes several pool-sized buffers, each with the pool's left padding. */
static void sessionReceive(gns_session_t *s)
{
    if (s->connection == 0 || s->close_sent)
    {
        return;
    }
    const size_t   largest = bufferpoolGetLargeBufferSize(s->config.pool);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(s->config.pool);
    for (;;)
    {
        gns_engine_message_t messages[kGnsSessionReceiveBatch];
        const int            count = gnsEngineReceive(s->connection, messages, kGnsSessionReceiveBatch);
        for (int i = 0; i < count && ! s->closing && s->callbacks.payload != NULL; ++i)
        {
            const uint8_t *data   = messages[i].data;
            size_t         length = messages[i].size;
            while (length > 0)
            {
                const size_t chunk  = min(length, largest);
                sbuf_t      *buffer = bufferpoolGetBestFit(s->config.pool, chunk, padding);
                sbufSetLength(buffer, chunk);
                memoryCopyLarge(sbufGetMutablePtr(buffer), data, chunk);
                gns_staged_queue_t_push_back(&s->inbound, (gns_staged_t) {.buffer = buffer});
                data += chunk;
                length -= chunk;
            }
        }
        gnsEngineMessagesRelease(messages, count);
        while (! s->dead && ! s->quiesced && ! gns_staged_queue_t_is_empty(&s->inbound))
        {
            s->callbacks.payload(s->user, gns_staged_queue_t_pull_front(&s->inbound).buffer);
        }
        if (s->dead || s->quiesced)
        {
            sessionDiscardInbound(s);
            return;
        }
        if (count < kGnsSessionReceiveBatch)
        {
            return;
        }
    }
}

/* Reads what GNS knows about the connection and acts on it: the end of the handshake, the end of the connection,
 * what is still unacknowledged, and the limits that keep the connection inside GNS's packet numbering. */
static void sessionPoll(gns_session_t *s)
{
    if (s->connection == 0 || s->close_sent)
    {
        return;
    }
    gns_engine_status_t status;
    gnsEngineStatus(s->connection, &status);
    if (status.state == kGnsEngineClosedByPeer)
    {
        /* Everything the peer sent before its close was taken just before this reading. */
        gnsSessionAbort(s, kGnsSessionPeerClosed);
        return;
    }
    if (status.state == kGnsEngineFailed || status.state == kGnsEngineGone)
    {
        char       text[128] = "";
        const int  reason    = gnsEngineEndReason(s->connection, text, sizeof(text));
        const bool timeout   = reason == kGnsEndReasonTimeoutLocal || reason == kGnsEndReasonTimeoutRemote;
        LOGD("Gns%s: the native connection ended (%d: %s)", sessionRole(s), reason, text);
        gnsSessionAbort(s,
                        ! timeout      ? kGnsSessionProtocolFailure
                        : s->connected ? kGnsSessionPeerClosed
                                       : kGnsSessionConnectTimeout);
        return;
    }
    if (status.state == kGnsEngineConnected && ! s->connected)
    {
        s->connected = true;
        if (s->callbacks.connected != NULL)
        {
            s->callbacks.connected(s->user);
            if (s->dead || s->quiesced)
            {
                return;
            }
        }
    }

    /* Messages whose last byte is acknowledged leave the ring. GNS counts a few header bytes per message as
     * outstanding, so a message can stay a little longer than it has to; it never leaves early. */
    s->outstanding              = (uint64_t) status.queued_bytes + status.unacked_bytes;
    const uint64_t acknowledged = s->submitted - min(s->submitted, s->outstanding);
    while (! gns_offset_queue_t_is_empty(&s->messages) && *gns_offset_queue_t_front(&s->messages) <= acknowledged)
    {
        gns_offset_queue_t_pop_front(&s->messages);
    }

    /* GNS carries 16 bits of each packet number. A round trip that holds this many of the packets being sent is
     * close to where acknowledgements stop making sense. */
    if ((uint64_t) status.ping_ms * status.packets_per_second / 1000U > kGnsWindowPackets)
    {
        LOGW("Gns%s: closing session: the round trip (%u ms) holds more packets than GNS can number at this rate "
             "(%u packets per second); lower send-rate for this path",
             sessionRole(s),
             status.ping_ms,
             status.packets_per_second);
        sessionFail(s, kGnsSessionProtocolFailure);
        return;
    }
    if (s->closing)
    {
        return;
    }
    const uint32_t limit   = s->config.settings.send_buffer_limit;
    const size_t   waiting = (size_t) gns_offset_queue_t_size(&s->messages);
    bool           hold    = s->pressure;
    if (s->outstanding > limit || waiting >= kGnsMessagesHold)
    {
        hold = true;
    }
    else if (s->outstanding <= limit / 2U && waiting <= kGnsMessagesHold / 2U)
    {
        hold = false;
    }
    if (hold != s->pressure)
    {
        s->pressure = hold;
        if (s->callbacks.pressure != NULL)
        {
            s->callbacks.pressure(s->user, hold);
        }
    }
}

static void sessionArmTimer(gns_session_t *s, uint64_t now)
{
    if (s->timer == NULL)
    {
        return;
    }
    uint64_t delay = s->connected ? kGnsSessionPollConnectedMs : kGnsSessionPollConnectingMs;
    if (s->close_sent)
    {
        delay = min(delay, s->linger_deadline > now ? s->linger_deadline - now : 1U);
    }
    else if (s->closing)
    {
        delay = min(delay, s->close_deadline > now ? s->close_deadline - now : 1U);
    }
    else if (! s->config.client && ! s->connected)
    {
        delay = min(delay, s->connect_deadline > now ? s->connect_deadline - now : 1U);
    }
    wtimerReset(s->timer, max((uint32_t) delay, 1U));
}

/* The serialized driver. One call at a time gives one piece of work to GNS, then takes what GNS has for the
 * session: datagrams for the carrier, stream bytes for the application, and the state of the connection. Work
 * that callbacks add meanwhile is taken by the same loop, in order. */
static void sessionDrive(gns_session_t *s)
{
    if (s->driving || s->dead || s->quiesced || ! s->started)
    {
        return;
    }
    gnsSessionRetain(s);
    s->driving = true;
    gnsPortEnter(s->port);
    for (uint32_t round = 0; ! s->dead && ! s->quiesced;)
    {
        const uint64_t now = sessionNow(s);
        if (! s->opened)
        {
            s->opened = true;
            if (! sessionOpen(s))
            {
                LOGE("Gns%s: GameNetworkingSockets did not open the session's %s",
                     sessionRole(s),
                     s->config.client ? "connection" : "listen socket");
                gnsSessionAbort(s, kGnsSessionProtocolFailure);
                break;
            }
        }
        if (sessionExpire(s, now))
        {
            break;
        }
        if (! gns_work_queue_t_is_empty(&s->work))
        {
            gns_work_t event = gns_work_queue_t_pull_front(&s->work);
            bool       taken = true;
            if (event.wire)
            {
                /* A false result means that GNS has nothing bound to the endpoint: the datagram is dropped. */
                discard gns_external_receive(s->endpoint,
                                             s->config.client ? NULL : &s->peer,
                                             sbufGetRawPtr(event.buffer),
                                             sbufGetLength(event.buffer));
            }
            else
            {
                taken = sessionWrite(s, event.buffer);
            }
            bufferpoolReuseBuffer(s->config.pool, event.buffer);
            bufferbudgetReservationRelease(&event.reservation);
            if (! taken)
            {
                sessionFail(s, kGnsSessionCapacityFailure);
                break;
            }
        }
        if (s->connection == 0 && ! s->config.client)
        {
            gnsEngineRunAccepts(); /* the accept callback leaves the server's connection in the port */
        }
        sessionEmit(s);
        if (s->dead || s->quiesced)
        {
            break;
        }
        sessionReceive(s);
        if (s->dead || s->quiesced)
        {
            break;
        }
        sessionPoll(s);
        if (s->dead || s->quiesced)
        {
            break;
        }
        if (! gns_work_queue_t_is_empty(&s->work))
        {
            continue;
        }
        if (s->closing && ! s->close_sent && s->outstanding == 0)
        {
            /* Every accepted payload has reached GNS and is acknowledged, so the close follows them. */
            s->close_sent      = true;
            s->linger_deadline = min(sessionDeadline(now, kGnsSessionCloseLingerMs), s->close_deadline);
            if (s->connection != 0)
            {
                gnsEngineClose(s->connection);
            }
            continue;
        }
        if (gnsPortLeave(s->port))
        {
            break;
        }
        if (++round >= kGnsSessionRounds)
        {
            gnsPortYield(s->port);
            break;
        }
    }
    s->driving = false;
    if (! s->dead && ! s->quiesced)
    {
        sessionArmTimer(s, sessionNow(s));
    }
    gnsSessionRelease(s);
}

static void sessionSubmit(gns_session_t *s, sbuf_t *buffer, bool wire)
{
    gnsSessionRetain(s);
    if (s->dead || s->quiesced || (! wire && s->closing))
    {
        bufferpoolReuseBuffer(s->config.pool, buffer);
    }
    else
    {
        gns_work_t event = {.buffer = buffer, .wire = wire};
        if (! bufferbudgetTryReserve(&s->budget, buffer, &event.reservation))
        {
            const buffer_budget_cost_t used   = bufferbudgetGetUsage(&s->budget);
            const buffer_budget_cost_t limits = bufferbudgetGetLimits(&s->budget);
            LOGW("Gns%s: closing session: %s input retention admission refused "
                 "(retained_bytes=%zu, incoming_bytes=%zu, byte_limit=%zu)",
                 sessionRole(s),
                 wire ? "carrier" : "nested application",
                 used.bytes,
                 (size_t) sbufGetLength(buffer),
                 limits.bytes);
            bufferpoolReuseBuffer(s->config.pool, buffer);
            gnsSessionAbort(s, kGnsSessionCapacityFailure);
        }
        else
        {
            gns_work_queue_t_push_back(&s->work, event);
            sessionDrive(s);
        }
    }
    gnsSessionRelease(s);
}

void gnsSessionSend(gns_session_t *s, sbuf_t *payload)
{
    sessionSubmit(s, payload, false);
}

void gnsSessionInput(gns_session_t *s, sbuf_t *packet)
{
    sessionSubmit(s, packet, true);
}

void gnsSessionAppFinish(gns_session_t *s)
{
    gnsSessionRetain(s);
    if (s->quiesced)
    {
        gnsSessionAbort(s, kGnsSessionAborted);
    }
    else if (! s->dead && ! s->closing)
    {
        /* The first closing event fixes the deadline; later progress never moves it. */
        s->closing        = true;
        s->close_deadline = sessionDeadline(sessionNow(s), s->config.settings.close_drain_timeout_ms);
        sessionDrive(s);
    }
    gnsSessionRelease(s);
}

void gnsSessionStart(gns_session_t *s)
{
    gnsSessionRetain(s);
    if (! s->dead && ! s->quiesced && ! s->started)
    {
        s->started = true;
        sessionDrive(s);
    }
    gnsSessionRelease(s);
}

void gnsSessionQuiesce(gns_session_t *s)
{
    s->quiesced = true;
    sessionDeleteTimer(s);
}

static void sessionTimerCallback(wtimer_t *timer)
{
    gns_session_t *s = weventGetUserdata(timer);
    assert(s != NULL && s->timer == timer);
    sessionDrive(s);
}

/* The port's wake: GNS's own thread left something for the session while no call of the session was running. */
static void sessionWake(void *user)
{
    sessionDrive(user);
}

gns_session_t *gnsSessionCreate(const gns_session_config_t *config, const gns_session_callbacks_t *callbacks,
                                void *user)
{
    assert(config != NULL && callbacks != NULL && config->pool != NULL && config->loop != NULL);
    assert(callbacks->emit != NULL && callbacks->terminal != NULL);
    gns_session_t *s = memoryAllocate(sizeof(*s));
    *s               = (gns_session_t) {.config = *config, .callbacks = *callbacks, .user = user, .references = 1};
    bufferbudgetInit(&s->budget,
                     (buffer_budget_cost_t) {.bytes = kGnsSessionNestedBytes, .charge = kGnsSessionNestedCharge});
    s->connect_deadline = sessionDeadline(sessionNow(s), config->settings.timeout_initial_ms);
    s->port             = gnsPortCreate(config->wid, config->settings.carrier_queue_limit, sessionWake, s);

    /* Synthetic addresses are only registration keys. The port's token is unique among the ports that exist. */
    const uint64_t key = (uint64_t) gnsPortToken(s->port);
    s->address         = (gns_external_addr_t) {.ip = {0xfd, 0x57, 0x57, 0x01}, .port = 27015};
    for (int i = 0; i < 8; ++i)
    {
        s->address.ip[8 + i] = (uint8_t) (key >> (56 - 8 * i));
    }
    s->peer       = s->address;
    s->peer.ip[3] = 0x02;
    s->endpoint   = config->client ? gns_external_endpoint_create_connect(&s->address, gnsPortSend, s->port)
                                   : gns_external_endpoint_create_listen(&s->address, gnsPortSend, s->port);
    s->timer      = wtimerAdd(config->loop, sessionTimerCallback, kGnsSessionPollConnectingMs, INFINITE);
    if (s->endpoint == NULL || s->timer == NULL)
    {
        s->callbacks.destroy_user = NULL;
        s->dead                   = true;
        sessionTeardown(s);
        gnsSessionRelease(s);
        return NULL;
    }
    weventSetUserData(s->timer, s);
    return s;
}

bool gnsSessionIsAlive(const gns_session_t *s)
{
    return ! s->dead;
}

bool gnsSessionIsConnected(const gns_session_t *s)
{
    return s->connected && ! s->dead;
}

bool gnsSessionIsPressured(const gns_session_t *s)
{
    return s->pressure;
}

uint64_t gnsSessionOutstandingBytes(const gns_session_t *s)
{
    return s->outstanding;
}

size_t gnsSessionOutstandingMessages(const gns_session_t *s)
{
    return (size_t) gns_offset_queue_t_size(&s->messages);
}

uint64_t gnsSessionRefusedDatagrams(const gns_session_t *s)
{
    return gnsPortRefusedDatagrams(s->port);
}

uint64_t gnsSessionCloseDeadline(const gns_session_t *s)
{
    return s->close_deadline;
}
