#pragma once

/*
 * One ENet session for one WaterWall line pair.
 *
 * A driver owns one ENetHost with exactly one peer and one channel. It turns
 * application bytes into reliable ENet packets and received reliable packets
 * back into bytes. It never touches sockets, timers, lines or buffers: the
 * caller feeds datagrams and the current time in, and receives output through
 * sinks.
 *
 * Threading: every call for one driver happens on one thread.
 * Reentrancy: sinks run inside driver calls. A sink only stages what it is
 * given. It must not call any enetDriver* function.
 * Time: now_ms is a monotonic millisecond clock. Pass the same clock to every
 * call for one driver.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct enet_driver_s enet_driver_t;

typedef enum enet_driver_role_e
{
    kEnetDriverRoleClient = 0, /* sends the native connect request */
    kEnetDriverRoleServer = 1  /* waits for one native connect request */
} enet_driver_role_t;

typedef enum enet_driver_state_e
{
    kEnetDriverStateConnecting = 0, /* native handshake not finished */
    kEnetDriverStateConnected  = 1,
    kEnetDriverStateClosing    = 2, /* graceful close requested; accepted bytes are draining */
    kEnetDriverStateClosed     = 3  /* terminal */
} enet_driver_state_t;

typedef enum enet_driver_close_e
{
    kEnetDriverCloseLocal    = 0, /* our graceful close completed */
    kEnetDriverCloseRemote   = 1, /* the peer disconnected, or it timed out */
    kEnetDriverCloseProtocol = 2  /* protocol violation or native failure */
} enet_driver_close_t;

enum
{
    kEnetDriverHostMtuMin       = 576,   /* ENET_PROTOCOL_MINIMUM_MTU */
    kEnetDriverHostMtuMax       = 4096,  /* ENET_PROTOCOL_MAXIMUM_MTU; also the largest datagram */
    kEnetDriverMaxMessage       = 65536, /* largest native message the driver sends */
    kEnetDriverActiveTickMs     = 10,    /* service interval while protocol work is pending */
    kEnetDriverSendBufferMin    = 4096,
    kEnetDriverSendBufferMax    = 0x08000000,
    kEnetDriverReceiveBufferMin = 131072,
    kEnetDriverReceiveBufferMax = 0x10000000
};

/* enetDriverNextServiceDelayMs result that means "no timer is needed until the next input". */
#define ENET_DRIVER_NO_SERVICE UINT32_MAX

typedef struct enet_driver_config_s
{
    enet_driver_role_t role;
    uint32_t           host_mtu;             /* kEnetDriverHostMtuMin..kEnetDriverHostMtuMax */
    uint32_t           ping_interval_ms;     /* silence before ENet sends a ping; above 0 */
    uint32_t           no_recv_timeout_ms;   /* T: an unacknowledged command ends the session between T and 2T */
    uint32_t           send_buffer_limit;    /* kEnetDriverSendBufferMin..kEnetDriverSendBufferMax */
    uint32_t           receive_buffer_limit; /* kEnetDriverReceiveBufferMin..kEnetDriverReceiveBufferMax */
    uint32_t           incoming_bandwidth;   /* bytes per second, 0 = unlimited */
    uint32_t           outgoing_bandwidth;   /* bytes per second, 0 = unlimited */
    uint32_t           random_seed;          /* seed for ENet's connect id */
} enet_driver_config_t;

typedef struct enet_driver_sinks_s
{
    /* Returns storage for one outgoing datagram of exactly length bytes, or NULL to drop it. The driver fills the
     * storage before the current driver call returns. */
    uint8_t *(*datagram)(void *user, size_t length);
    /* Decoded stream bytes, in order. The pointer is valid only during the call. */
    void (*stream)(void *user, const uint8_t *data, size_t length);
    /* The native handshake finished. Called once. */
    void (*connected)(void *user);
    /* The session ended. Called at most once, and never after enetDriverAbort. */
    void (*closed)(void *user, enet_driver_close_t why);
} enet_driver_sinks_t;

/* Routes ENet and driver allocation to the given functions. The first call wins. Call it from one thread, before
 * the first driver is created. */
bool enetDriverInstall(void *(*allocate)(size_t size), void (*release)(void *memory));

/* Creates a driver. A client queues its connect request; call enetDriverService to send it. Returns NULL when ENet
 * refuses the host. */
enet_driver_t *enetDriverCreate(const enet_driver_config_t *config, const enet_driver_sinks_t *sinks, void *user,
                                uint64_t now_ms);

/* Frees the driver without telling the peer. Use enetDriverClose or enetDriverAbort first. */
void enetDriverDestroy(enet_driver_t *driver);

/* Feeds one carrier datagram. Empty datagrams and datagrams above kEnetDriverHostMtuMax are ignored. */
void enetDriverInput(enet_driver_t *driver, const uint8_t *datagram, size_t length, uint64_t now_ms);

/* Accepts application bytes in order. Bytes offered before the handshake finishes are buffered. Returns false when
 * the bytes were refused: either the queue was already above twice send_buffer_limit and the driver is unchanged,
 * or ENet failed and the driver is now closed. */
bool enetDriverWrite(enet_driver_t *driver, const uint8_t *data, size_t length, uint64_t now_ms);

/* Runs protocol timers: retransmission, pings and timeouts. */
void enetDriverService(enet_driver_t *driver, uint64_t now_ms);

/* Starts a graceful close: accepted bytes are delivered first, then the peer is told. */
void enetDriverClose(enet_driver_t *driver, uint64_t now_ms);

/* Ends the session now. The peer is told once, without waiting for an answer. The closed sink is not called. */
void enetDriverAbort(enet_driver_t *driver, uint64_t now_ms);

enet_driver_state_t enetDriverState(const enet_driver_t *driver);

/* Bytes accepted by enetDriverWrite that the peer has not acknowledged yet. */
size_t enetDriverQueuedBytes(const enet_driver_t *driver);

/* True while the producer should stay paused: set above send_buffer_limit, cleared at or below half of it. */
bool enetDriverSendHold(const enet_driver_t *driver);

/* Milliseconds until the driver needs enetDriverService again, or ENET_DRIVER_NO_SERVICE. */
uint32_t enetDriverNextServiceDelayMs(const enet_driver_t *driver, uint64_t now_ms);

/* Outgoing datagrams that the datagram sink refused. */
uint64_t enetDriverDroppedDatagrams(const enet_driver_t *driver);
