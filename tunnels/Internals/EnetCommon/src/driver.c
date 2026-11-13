#include "EnetCommon/driver.h"

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

static void enetDriverFinish(enet_driver_t *driver, enet_driver_close_t why)
{
    if (driver->state == kEnetDriverStateClosed)
    {
        return;
    }
    driver->state = kEnetDriverStateClosed;
    driver->sinks.closed(driver->user, why);
}

static void enetDriverHandle(enet_driver_t *driver, ENetEvent *event)
{
    switch (event->type)
    {
    case ENET_EVENT_TYPE_CONNECT:
        driver->state = kEnetDriverStateConnected;
        driver->sinks.connected(driver->user);
        break;
    case ENET_EVENT_TYPE_RECEIVE:
        enet_packet_destroy(event->packet);
        break;
    case ENET_EVENT_TYPE_DISCONNECT:
        enetDriverFinish(driver, kEnetDriverCloseRemote);
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
}

enet_driver_t *enetDriverCreate(const enet_driver_config_t *config, const enet_driver_sinks_t *sinks, void *user,
                                uint64_t now_ms)
{
    assert(enet_driver_allocate != NULL);
    assert(config->host_mtu >= kEnetDriverHostMtuMin && config->host_mtu <= kEnetDriverHostMtuMax);

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
        driver->peer      = &driver->host->peers[0];
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

void enetDriverInput(enet_driver_t *driver, const uint8_t *datagram, size_t length, uint64_t now_ms)
{
    if (driver->state == kEnetDriverStateClosed || length == 0 || length > (size_t) kEnetDriverHostMtuMax)
    {
        return;
    }
    enet_platform_transport_t *previous = enetDriverEnter(driver, now_ms);
    driver->transport.input             = datagram;
    driver->transport.input_length      = length;
    enetDriverRun(driver);
    driver->transport.input        = NULL;
    driver->transport.input_length = 0;
    enetDriverLeave(driver, previous);
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
    (void) now_ms;
    if (driver->state == kEnetDriverStateClosed || driver->peer->state == ENET_PEER_STATE_DISCONNECTED)
    {
        return ENET_DRIVER_NO_SERVICE;
    }
    return kEnetDriverActiveTickMs;
}
