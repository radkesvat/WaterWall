#include "EnetCommon/driver.h"

#include "enet/time.h"
#include "platform.h"

#include <assert.h>
#include <string.h>

/* Bytes accepted before the native handshake finished. The payload follows this header in the same allocation. */
typedef struct enet_driver_pending_s
{
    struct enet_driver_pending_s *next;
    size_t                        length;
} enet_driver_pending_t;

struct enet_driver_s
{
    enet_platform_transport_t transport; /* first member: the platform hands this pointer back to send */
    enet_driver_config_t      config;
    enet_driver_sinks_t       sinks;
    void                     *user;
    ENetHost                 *host;
    ENetPeer                 *peer; /* the host's only peer slot */
    enet_driver_pending_t    *pending_head;
    enet_driver_pending_t    *pending_tail;
    size_t                    queued_bytes; /* accepted and not yet acknowledged by the peer */
    enet_driver_state_t       state;
    bool                      send_hold;
    bool                      close_requested; /* graceful close asked before the handshake finished */
    bool                      entered;         /* a driver call is on the stack */
};

static void *(*enet_driver_allocate)(size_t size) = NULL;
static void (*enet_driver_release)(void *memory)  = NULL;

static void *ENET_CALLBACK enetDriverAllocateThunk(size_t size)
{
    return enet_driver_allocate(size);
}

static void ENET_CALLBACK enetDriverReleaseThunk(void *memory)
{
    enet_driver_release(memory);
}

bool enetDriverInstall(void *(*allocate)(size_t size), void (*release)(void *memory))
{
    if (enet_driver_allocate != NULL)
    {
        return true;
    }
    enet_driver_allocate = allocate;
    enet_driver_release  = release;
    return enetPlatformInstall(enetDriverAllocateThunk, enetDriverReleaseThunk);
}

static enet_platform_transport_t *enetDriverEnter(enet_driver_t *driver, uint64_t now_ms)
{
    assert(! driver->entered); /* a sink called back into the driver */
    driver->entered          = true;
    driver->transport.now_ms = (uint32_t) now_ms;
    return enetPlatformEnter(&driver->transport);
}

static void enetDriverLeave(enet_driver_t *driver, enet_platform_transport_t *previous)
{
    enetPlatformLeave(previous);
    driver->entered = false;
}

static bool enetDriverTransportSend(enet_platform_transport_t *transport, const ENetBuffer *buffers,
                                    size_t buffer_count, size_t total_length)
{
    enet_driver_t *driver = (enet_driver_t *) transport;
    uint8_t       *out    = driver->sinks.datagram(driver->user, total_length);
    if (out == NULL)
    {
        return false;
    }
    for (size_t i = 0; i < buffer_count; ++i)
    {
        memcpy(out, buffers[i].data, buffers[i].dataLength);
        out += buffers[i].dataLength;
    }
    return true;
}

static void ENET_CALLBACK enetDriverPacketFreed(ENetPacket *packet)
{
    /* ENet frees a reliable packet once the peer acknowledged every fragment, or when its queues are reset. */
    enet_driver_t *driver = packet->userData;
    assert(driver->queued_bytes >= packet->dataLength);
    driver->queued_bytes -= packet->dataLength;
}

/* Hands one message to ENet. Its bytes are already counted in queued_bytes. */
static bool enetDriverSubmit(enet_driver_t *driver, const uint8_t *data, size_t length)
{
    ENetPacket *packet   = enet_packet_create(data, length, ENET_PACKET_FLAG_RELIABLE);
    packet->userData     = driver;
    packet->freeCallback = enetDriverPacketFreed;
    if (enet_peer_send(driver->peer, 0, packet) != 0)
    {
        enet_packet_destroy(packet); /* runs enetDriverPacketFreed, which uncounts the bytes */
        return false;
    }
    return true;
}

static void enetDriverAppendPending(enet_driver_t *driver, const uint8_t *data, size_t length)
{
    enet_driver_pending_t *entry = enet_malloc(sizeof(*entry) + length);
    entry->next                  = NULL;
    entry->length                = length;
    memcpy(entry + 1, data, length);
    if (driver->pending_tail != NULL)
    {
        driver->pending_tail->next = entry;
    }
    else
    {
        driver->pending_head = entry;
    }
    driver->pending_tail = entry;
}

static bool enetDriverFlushPending(enet_driver_t *driver)
{
    while (driver->pending_head != NULL)
    {
        enet_driver_pending_t *entry = driver->pending_head;
        driver->pending_head         = entry->next;
        if (driver->pending_head == NULL)
        {
            driver->pending_tail = NULL;
        }
        const bool sent = enetDriverSubmit(driver, (const uint8_t *) (entry + 1), entry->length);
        enet_free(entry);
        if (! sent)
        {
            return false;
        }
    }
    return true;
}

/* Above the limit the hold starts; at or below half of it the hold ends; in between it keeps its state. */
static void enetDriverUpdateHold(enet_driver_t *driver)
{
    if (driver->queued_bytes > driver->config.send_buffer_limit)
    {
        driver->send_hold = true;
    }
    else if (driver->queued_bytes <= driver->config.send_buffer_limit / 2U)
    {
        driver->send_hold = false;
    }
}

static void enetDriverFinish(enet_driver_t *driver, enet_driver_close_t why)
{
    if (driver->state == kEnetDriverStateClosed)
    {
        return;
    }
    if (why == kEnetDriverCloseProtocol)
    {
        /* Tell the peer once, without waiting for an answer, and drop every queue. */
        enet_peer_disconnect_now(driver->peer, 0);
    }
    driver->state = kEnetDriverStateClosed;
    driver->sinks.closed(driver->user, why);
}

/* ENet resets these when it resets a peer, so they are applied again once the peer is connected. */
static void enetDriverApplyPeerSettings(enet_driver_t *driver)
{
    enet_peer_timeout(driver->peer, 0, driver->config.no_recv_timeout_ms, driver->config.no_recv_timeout_ms);
    enet_peer_ping_interval(driver->peer, driver->config.ping_interval_ms);
}

static void enetDriverBeginDisconnect(enet_driver_t *driver)
{
    driver->state = kEnetDriverStateClosing;
    /* enet_peer_disconnect_later sends the disconnect only after every queued reliable command is acknowledged.
     * enet_peer_disconnect would discard the queues first, so it is never used for a graceful close. */
    enet_peer_disconnect_later(driver->peer, 0);
}

static void enetDriverHandle(enet_driver_t *driver, ENetEvent *event)
{
    switch (event->type)
    {
    case ENET_EVENT_TYPE_CONNECT:
        enetDriverApplyPeerSettings(driver);
        driver->state = kEnetDriverStateConnected;
        driver->sinks.connected(driver->user);
        if (! enetDriverFlushPending(driver))
        {
            enetDriverFinish(driver, kEnetDriverCloseProtocol);
            break;
        }
        if (driver->close_requested)
        {
            enetDriverBeginDisconnect(driver);
        }
        break;
    case ENET_EVENT_TYPE_RECEIVE: {
        /* The stream is channel 0, reliable packets only. Anything else would break ordering. */
        ENetPacket *packet    = event->packet;
        const bool  in_stream = event->channelID == 0 && (packet->flags & ENET_PACKET_FLAG_RELIABLE) != 0;
        if (in_stream && packet->dataLength > 0 && driver->state == kEnetDriverStateConnected)
        {
            driver->sinks.stream(driver->user, packet->data, packet->dataLength);
        }
        enet_packet_destroy(packet);
        if (! in_stream)
        {
            enetDriverFinish(driver, kEnetDriverCloseProtocol);
        }
        break;
    }
    case ENET_EVENT_TYPE_DISCONNECT:
        enetDriverFinish(driver,
                         driver->state == kEnetDriverStateClosing ? kEnetDriverCloseLocal : kEnetDriverCloseRemote);
        break;
    default:
        break;
    }
}

/* Runs ENet until it has no more events. The caller has entered the platform. */
static void enetDriverRun(enet_driver_t *driver)
{
    while (driver->state != kEnetDriverStateClosed)
    {
        ENetEvent event;
        const int result = enet_host_service(driver->host, &event, 0);
        if (result < 0)
        {
            enetDriverFinish(driver, kEnetDriverCloseProtocol);
            break;
        }
        if (result == 0)
        {
            break;
        }
        enetDriverHandle(driver, &event);
    }
    /* Acknowledgements free packets inside the loop, so input alone can release the hold. */
    enetDriverUpdateHold(driver);
}

enet_driver_t *enetDriverCreate(const enet_driver_config_t *config, const enet_driver_sinks_t *sinks, void *user,
                                uint64_t now_ms)
{
    assert(enet_driver_allocate != NULL);
    assert(config->host_mtu >= kEnetDriverHostMtuMin && config->host_mtu <= kEnetDriverHostMtuMax);
    assert(config->receive_buffer_limit / 2U >= (uint32_t) kEnetDriverMaxMessage);

    enet_driver_t *driver = enet_malloc(sizeof(*driver));
    memset(driver, 0, sizeof(*driver));
    driver->transport.send        = enetDriverTransportSend;
    driver->transport.random_seed = config->random_seed;
    driver->config                = *config;
    driver->sinks                 = *sinks;
    driver->user                  = user;
    driver->state                 = kEnetDriverStateConnecting;

    enet_platform_transport_t *previous = enetDriverEnter(driver, now_ms);
    driver->host = enet_host_create(NULL, 1, 1, config->incoming_bandwidth, config->outgoing_bandwidth);
    if (driver->host != NULL)
    {
        driver->host->mtu = config->host_mtu;
        /* ENet allocates a whole fragmented packet when its first fragment arrives, so both limits are always set.
         * At the waiting-data limit ENet refuses further commands without acknowledging them. enetDriverInput
         * raises that limit for the one datagram the waiting data is waiting for. */
        driver->host->maximumPacketSize  = config->receive_buffer_limit / 2U;
        driver->host->maximumWaitingData = config->receive_buffer_limit;
        driver->peer                     = &driver->host->peers[0];
        if (config->role == kEnetDriverRoleClient)
        {
            ENetAddress address;
            address.host = kEnetPlatformPeerHost;
            address.port = kEnetPlatformPeerPort;
            if (enet_host_connect(driver->host, &address, 1, 0) == NULL)
            {
                enet_host_destroy(driver->host);
                driver->host = NULL;
            }
            else
            {
                /* The connect request is a reliable command, so the same timeout bounds a connect attempt. */
                enetDriverApplyPeerSettings(driver);
            }
        }
    }
    enetDriverLeave(driver, previous);

    if (driver->host == NULL)
    {
        enet_free(driver);
        return NULL;
    }
    return driver;
}

void enetDriverDestroy(enet_driver_t *driver)
{
    assert(! driver->entered);
    /* Destroying the host frees its packets, which runs their free callbacks against this driver. */
    enet_platform_transport_t *previous = enetPlatformEnter(&driver->transport);
    enet_host_destroy(driver->host);
    enetPlatformLeave(previous);
    while (driver->pending_head != NULL)
    {
        enet_driver_pending_t *entry = driver->pending_head;
        driver->pending_head         = entry->next;
        enet_free(entry);
    }
    enet_free(driver);
}

/* Whether a datagram carries the next reliable command of the stream.
 *
 * ENet acknowledges reliable commands that arrive ahead of a lost one, so the sender keeps going while the receiver
 * holds what it cannot deliver yet. At the waiting-data limit ENet refuses every new command, including the lost one
 * when it arrives again, and then nothing could ever be delivered. The datagram found here is fed with a higher
 * limit. It is read the way ENet's own parser reads it, and anything unexpected counts as "no": ENet validates the
 * datagram itself afterwards. */
static bool enetDriverCarriesNextCommand(const enet_driver_t *driver, const uint8_t *datagram, size_t length)
{
    const ENetPeer *peer = driver->peer;
    if (peer->state != ENET_PEER_STATE_CONNECTED || peer->channelCount == 0 || length < sizeof(enet_uint16))
    {
        return false;
    }
    const enet_uint16 next = (enet_uint16) (peer->channels[0].incomingReliableSequenceNumber + 1U);
    enet_uint16       field;
    memcpy(&field, datagram, sizeof(field));
    const enet_uint16 flags = ENET_NET_TO_HOST_16(field) & ENET_PROTOCOL_HEADER_FLAG_MASK;
    size_t            offset =
        (flags & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME) != 0 ? sizeof(ENetProtocolHeader) : sizeof(enet_uint16);
    if ((flags & ENET_PROTOCOL_HEADER_FLAG_COMPRESSED) != 0 || offset > length)
    {
        return false;
    }
    while (length - offset >= sizeof(ENetProtocolCommandHeader))
    {
        ENetProtocol     command;
        const enet_uint8 number = datagram[offset] & ENET_PROTOCOL_COMMAND_MASK;
        const size_t     size   = number < ENET_PROTOCOL_COMMAND_COUNT ? enet_protocol_command_size(number) : 0;
        if (size == 0 || size > length - offset)
        {
            return false;
        }
        memcpy(&command, datagram + offset, size);
        size_t data_length = 0;
        switch (number)
        {
        case ENET_PROTOCOL_COMMAND_SEND_RELIABLE:
            if (command.header.channelID == 0 && ENET_NET_TO_HOST_16(command.header.reliableSequenceNumber) == next)
            {
                return true;
            }
            data_length = ENET_NET_TO_HOST_16(command.sendReliable.dataLength);
            break;
        case ENET_PROTOCOL_COMMAND_SEND_FRAGMENT:
            if (command.header.channelID == 0 && ENET_NET_TO_HOST_16(command.sendFragment.startSequenceNumber) == next)
            {
                return true;
            }
            data_length = ENET_NET_TO_HOST_16(command.sendFragment.dataLength);
            break;
        case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
            data_length = ENET_NET_TO_HOST_16(command.sendFragment.dataLength);
            break;
        case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE:
            data_length = ENET_NET_TO_HOST_16(command.sendUnreliable.dataLength);
            break;
        case ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
            data_length = ENET_NET_TO_HOST_16(command.sendUnsequenced.dataLength);
            break;
        default:
            break;
        }
        if (data_length > length - offset - size)
        {
            return false;
        }
        offset += size + data_length;
    }
    return false;
}

void enetDriverInput(enet_driver_t *driver, const uint8_t *datagram, size_t length, uint64_t now_ms)
{
    if (driver->state == kEnetDriverStateClosed || length == 0 || length > (size_t) kEnetDriverHostMtuMax)
    {
        return;
    }
    enet_platform_transport_t *previous = enetDriverEnter(driver, now_ms);
    /* A sender that honours ENet's window has at most 65,536 bytes in flight, so the doubled limit always leaves
     * room for the missing command, and retention stays below two and a half times receive_buffer_limit. */
    driver->host->maximumWaitingData = enetDriverCarriesNextCommand(driver, datagram, length)
                                           ? (size_t) driver->config.receive_buffer_limit * 2U
                                           : (size_t) driver->config.receive_buffer_limit;
    driver->transport.input          = datagram;
    driver->transport.input_length   = length;
    enetDriverRun(driver);
    driver->transport.input        = NULL;
    driver->transport.input_length = 0;
    enetDriverLeave(driver, previous);
}

bool enetDriverWrite(enet_driver_t *driver, const uint8_t *data, size_t length, uint64_t now_ms)
{
    assert(driver->state == kEnetDriverStateConnecting || driver->state == kEnetDriverStateConnected);
    assert(! driver->close_requested);
    if (driver->queued_bytes > (size_t) driver->config.send_buffer_limit * 2U)
    {
        return false; /* hard cap: a payload accepted below it is admitted whole */
    }
    enet_platform_transport_t *previous = enetDriverEnter(driver, now_ms);
    bool                       accepted = true;
    while (length > 0 && accepted)
    {
        const size_t chunk = length < (size_t) kEnetDriverMaxMessage ? length : (size_t) kEnetDriverMaxMessage;
        driver->queued_bytes += chunk;
        if (driver->state == kEnetDriverStateConnected)
        {
            accepted = enetDriverSubmit(driver, data, chunk);
        }
        else
        {
            enetDriverAppendPending(driver, data, chunk);
        }
        data += chunk;
        length -= chunk;
    }
    if (accepted)
    {
        enetDriverRun(driver);
    }
    else
    {
        enetDriverFinish(driver, kEnetDriverCloseProtocol);
    }
    enetDriverLeave(driver, previous);
    return accepted;
}

void enetDriverService(enet_driver_t *driver, uint64_t now_ms)
{
    if (driver->state == kEnetDriverStateClosed)
    {
        return;
    }
    enet_platform_transport_t *previous = enetDriverEnter(driver, now_ms);
    enetDriverRun(driver);
    enetDriverLeave(driver, previous);
}

void enetDriverClose(enet_driver_t *driver, uint64_t now_ms)
{
    if (driver->state == kEnetDriverStateClosing || driver->state == kEnetDriverStateClosed || driver->close_requested)
    {
        return;
    }
    enet_platform_transport_t *previous = enetDriverEnter(driver, now_ms);
    if (driver->state == kEnetDriverStateConnected)
    {
        enetDriverBeginDisconnect(driver);
        enetDriverRun(driver);
    }
    else if (driver->pending_head != NULL)
    {
        /* Bytes were accepted before the handshake: deliver them first. The caller's deadline bounds the wait. */
        driver->close_requested = true;
    }
    else
    {
        enet_peer_disconnect_now(driver->peer, 0);
        driver->state = kEnetDriverStateClosed;
        driver->sinks.closed(driver->user, kEnetDriverCloseLocal);
    }
    enetDriverLeave(driver, previous);
}

void enetDriverAbort(enet_driver_t *driver, uint64_t now_ms)
{
    if (driver->state == kEnetDriverStateClosed)
    {
        return;
    }
    enet_platform_transport_t *previous = enetDriverEnter(driver, now_ms);
    enet_peer_disconnect_now(driver->peer, 0);
    driver->state = kEnetDriverStateClosed;
    enetDriverLeave(driver, previous);
}

enet_driver_state_t enetDriverState(const enet_driver_t *driver)
{
    return driver->state;
}

size_t enetDriverQueuedBytes(const enet_driver_t *driver)
{
    return driver->queued_bytes;
}

bool enetDriverSendHold(const enet_driver_t *driver)
{
    return driver->send_hold;
}

uint64_t enetDriverDroppedDatagrams(const enet_driver_t *driver)
{
    return driver->transport.dropped;
}

uint32_t enetDriverNextServiceDelayMs(const enet_driver_t *driver, uint64_t now_ms)
{
    if (driver->state == kEnetDriverStateClosed)
    {
        return ENET_DRIVER_NO_SERVICE;
    }
    ENetPeer *peer = driver->peer;
    if (peer->state == ENET_PEER_STATE_DISCONNECTED)
    {
        return ENET_DRIVER_NO_SERVICE; /* a server that has seen no connect request */
    }
    if (peer->state != ENET_PEER_STATE_CONNECTED || enet_peer_has_outgoing_commands(peer))
    {
        return kEnetDriverActiveTickMs; /* handshake, unacknowledged commands or a disconnect in progress */
    }
    /* Idle: ENet sends a ping once nothing was acknowledged for pingInterval. Wake up exactly then. */
    uint32_t now = (uint32_t) now_ms;
    if (now == 0)
    {
        now = 1;
    }
    const uint32_t silent = ENET_TIME_DIFFERENCE(now, peer->lastReceiveTime);
    return silent >= peer->pingInterval ? 1U : peer->pingInterval - silent;
}
