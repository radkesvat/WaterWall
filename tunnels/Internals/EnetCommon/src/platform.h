#pragma once

/*
 * WaterWall platform layer for the vendored ENet (ww/vendor/enet).
 *
 * ENet's protocol core reaches the operating system only through the
 * enet_socket_*, enet_time_get and enet_host_random_seed functions. Upstream
 * implements them in unix.c and win32.c. Production WaterWall targets compile
 * platform.c instead, so ENet never creates, polls or closes an OS socket.
 *
 * Every ENet call made by the driver is bracketed by enetPlatformEnter() and
 * enetPlatformLeave(). The platform functions act on the transport that is
 * active on the calling thread.
 */

#include "enet/enet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The one synthetic address ENet sees. Real addresses stay in WaterWall's routing context. */
enum
{
    kEnetPlatformPeerHost = 0x0A000001,
    kEnetPlatformPeerPort = 1
};

typedef struct enet_platform_transport_s enet_platform_transport_t;

struct enet_platform_transport_s
{
    /* Takes one complete outgoing datagram as gathered chunks. Returns false when it was dropped. */
    bool (*send)(enet_platform_transport_t *transport, const ENetBuffer *buffers, size_t buffer_count,
                 size_t total_length);
    const uint8_t *input; /* datagram offered to the next enet_socket_receive, or NULL */
    size_t         input_length;
    uint32_t       now_ms;      /* time reported by enet_time_get during this call */
    uint32_t       random_seed; /* value reported by enet_host_random_seed */
    uint64_t       dropped;     /* outgoing datagrams that send refused */
};

typedef void *(ENET_CALLBACK *EnetPlatformAllocate)(size_t size);
typedef void(ENET_CALLBACK *EnetPlatformRelease)(void *memory);

/* Routes ENet allocation to the given functions. The first call wins; later calls return true unchanged. */
bool enetPlatformInstall(EnetPlatformAllocate allocate, EnetPlatformRelease release);

/* Makes transport the target of ENet platform calls on this thread. Returns the previous target. */
enet_platform_transport_t *enetPlatformEnter(enet_platform_transport_t *transport);

/* Restores the target that the matching enetPlatformEnter returned. */
void enetPlatformLeave(enet_platform_transport_t *previous);
