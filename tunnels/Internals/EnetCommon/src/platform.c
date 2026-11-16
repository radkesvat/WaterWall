#include "platform.h"

#include "wdef.h"

#include <assert.h>
#include <string.h>

static thread_local enet_platform_transport_t *enet_platform_active    = NULL;
static bool                                    enet_platform_installed = false;

bool enetPlatformInstall(EnetPlatformAllocate allocate, EnetPlatformRelease release)
{
    if (enet_platform_installed)
    {
        return true;
    }
    ENetCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks)); /* a null no_memory keeps ENet's default, which aborts */
    callbacks.malloc = allocate;
    callbacks.free   = release;
    if (enet_initialize_with_callbacks(ENET_VERSION, &callbacks) != 0)
    {
        return false;
    }
    enet_platform_installed = true;
    return true;
}

enet_platform_transport_t *enetPlatformEnter(enet_platform_transport_t *transport)
{
    enet_platform_transport_t *previous = enet_platform_active;
    enet_platform_active                = transport;
    return previous;
}

void enetPlatformLeave(enet_platform_transport_t *previous)
{
    enet_platform_active = previous;
}

int enet_initialize(void)
{
    return 0;
}

void enet_deinitialize(void)
{
}

enet_uint32 enet_host_random_seed(void)
{
    assert(enet_platform_active != NULL);
    return enet_platform_active->random_seed;
}

enet_uint32 enet_time_get(void)
{
    assert(enet_platform_active != NULL);
    const enet_uint32 now = enet_platform_active->now_ms;
    /* ENet uses 0 as "unset" in several timestamps. */
    return now != 0 ? now : 1;
}

void enet_time_set(enet_uint32 new_time_base)
{
    discard new_time_base;
}

ENetSocket enet_socket_create(ENetSocketType type)
{
    discard type;
    return (ENetSocket) 1;
}

int enet_socket_bind(ENetSocket socket, const ENetAddress *address)
{
    discard socket;
    discard address;
    return 0;
}

int enet_socket_get_address(ENetSocket socket, ENetAddress *address)
{
    discard socket;
    discard address;
    return -1;
}

int enet_socket_set_option(ENetSocket socket, ENetSocketOption option, int value)
{
    discard socket;
    discard option;
    discard value;
    return 0;
}

void enet_socket_destroy(ENetSocket socket)
{
    discard socket;
}

int enet_socket_send(ENetSocket socket, const ENetAddress *address, const ENetBuffer *buffers, size_t buffer_count)
{
    discard                    socket;
    discard                    address;
    enet_platform_transport_t *transport = enet_platform_active;
    assert(transport != NULL);
    size_t total_length = 0;
    for (size_t i = 0; i < buffer_count; ++i)
    {
        total_length += buffers[i].dataLength;
    }
    if (! transport->send(transport, buffers, buffer_count, total_length))
    {
        /* A dropped datagram is ordinary loss: ENet retransmits reliable commands after its timeout. */
        transport->dropped += 1;
    }
    return (int) total_length;
}

int enet_socket_receive(ENetSocket socket, ENetAddress *address, ENetBuffer *buffers, size_t buffer_count)
{
    discard                    socket;
    enet_platform_transport_t *transport = enet_platform_active;
    assert(transport != NULL);
    if (transport->input == NULL)
    {
        return 0;
    }
    const uint8_t *input    = transport->input;
    const size_t   length   = transport->input_length;
    transport->input        = NULL;
    transport->input_length = 0;
    if (buffer_count == 0 || length > buffers[0].dataLength)
    {
        return -2; /* ENet skips a truncated datagram and asks again */
    }
    memcpy(buffers[0].data, input, length);
    if (address != NULL)
    {
        address->host = kEnetPlatformPeerHost;
        address->port = kEnetPlatformPeerPort;
    }
    return (int) length;
}

int enet_socket_wait(ENetSocket socket, enet_uint32 *condition, enet_uint32 timeout)
{
    discard socket;
    discard timeout;
    if (condition != NULL)
    {
        *condition = ENET_SOCKET_WAIT_NONE;
    }
    return 0;
}
