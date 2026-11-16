/* A plain ENet application for waterwall.enet_socket_interop_unit.
 *
 * It is the vendored protocol core with upstream's own socket layer (unix.c), so it opens real UDP sockets and uses
 * nothing of WaterWall. It is a separate program because that socket layer and EnetCommon's platform layer define
 * the same functions.
 *
 *     enet_stock_peer server                 bind a free loopback port, print it, echo one peer's packets
 *     enet_stock_peer client <port> <bytes>  connect, send <bytes> of the pattern, expect the same bytes back
 *
 * Exit status 0: the exchange was complete and the connection ended with an orderly disconnect. */

#include <enet/enet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    kDeadlineMs = 20000,
    kServiceMs  = 50
};

/* Every failure says why on standard error, which the test shares. */
static int fail(const char *reason)
{
    fprintf(stderr, "enet_stock_peer: %s\n", reason);
    return 1;
}

/* The same pattern as enet_socket_interop_test.c. */
static enet_uint8 patternByte(size_t offset)
{
    return (enet_uint8) (offset * 31U + (offset >> 8));
}

static int runServer(void)
{
    ENetAddress address;
    enet_address_set_host_ip(&address, "127.0.0.1");
    address.port   = 0;
    ENetHost *host = enet_host_create(&address, 1, 1, 0, 0);
    if (host == NULL || enet_socket_get_address(host->socket, &address) != 0)
    {
        return fail("no host on a loopback port");
    }
    printf("%u\n", (unsigned) address.port);
    fflush(stdout);

    size_t            echoed    = 0;
    int               connected = 0;
    const enet_uint32 start     = enet_time_get();
    while ((enet_uint32) (enet_time_get() - start) < kDeadlineMs)
    {
        ENetEvent event;
        if (enet_host_service(host, &event, kServiceMs) <= 0)
        {
            continue;
        }
        if (event.type == ENET_EVENT_TYPE_CONNECT)
        {
            connected = 1;
        }
        else if (event.type == ENET_EVENT_TYPE_RECEIVE)
        {
            ENetPacket *reply =
                enet_packet_create(event.packet->data, event.packet->dataLength, ENET_PACKET_FLAG_RELIABLE);
            if (reply == NULL || enet_peer_send(event.peer, 0, reply) != 0)
            {
                return fail("could not queue an echo packet");
            }
            echoed += event.packet->dataLength;
            enet_packet_destroy(event.packet);
        }
        else if (event.type == ENET_EVENT_TYPE_DISCONNECT)
        {
            enet_host_destroy(host);
            return connected && echoed > 0 ? 0 : fail("the peer disconnected before any exchange");
        }
    }
    return fail("no disconnect before the deadline");
}

static int runClient(enet_uint16 port, size_t total)
{
    /* Packets below one datagram, around one, and far above one, so ENet fragments some of them. */
    static const size_t sizes[] = {1, 37, 1200, 4000, 65536};
    ENetAddress         address;
    enet_address_set_host_ip(&address, "127.0.0.1");
    address.port   = port;
    ENetHost *host = enet_host_create(NULL, 1, 1, 0, 0);
    ENetPeer *peer = host != NULL ? enet_host_connect(host, &address, 1, 0) : NULL;
    if (peer == NULL)
    {
        return fail("no host or no connect request");
    }

    size_t            sent     = 0;
    size_t            received = 0;
    int               closing  = 0;
    const enet_uint32 start    = enet_time_get();
    while ((enet_uint32) (enet_time_get() - start) < kDeadlineMs)
    {
        ENetEvent event;
        if (enet_host_service(host, &event, kServiceMs) <= 0)
        {
            continue;
        }
        if (event.type == ENET_EVENT_TYPE_CONNECT)
        {
            for (size_t i = 0; sent < total; ++i)
            {
                size_t size = sizes[i % (sizeof(sizes) / sizeof(sizes[0]))];
                if (size > total - sent)
                {
                    size = total - sent;
                }
                ENetPacket *packet = enet_packet_create(NULL, size, ENET_PACKET_FLAG_RELIABLE);
                if (packet == NULL)
                {
                    return fail("out of memory for a packet");
                }
                for (size_t b = 0; b < size; ++b)
                {
                    packet->data[b] = patternByte(sent + b);
                }
                if (enet_peer_send(peer, 0, packet) != 0)
                {
                    return fail("could not queue a packet");
                }
                sent += size;
            }
        }
        else if (event.type == ENET_EVENT_TYPE_RECEIVE)
        {
            for (size_t b = 0; b < event.packet->dataLength; ++b)
            {
                if (received + b >= total || event.packet->data[b] != patternByte(received + b))
                {
                    return fail("the echo differs from the pattern or is too long");
                }
            }
            received += event.packet->dataLength;
            enet_packet_destroy(event.packet);
            if (received == total && ! closing)
            {
                closing = 1;
                enet_peer_disconnect_later(peer, 0);
            }
        }
        else if (event.type == ENET_EVENT_TYPE_DISCONNECT)
        {
            enet_host_destroy(host);
            return closing && received == total ? 0 : fail("disconnected before the echo was complete");
        }
    }
    fprintf(stderr, "enet_stock_peer: deadline with %zu of %zu bytes echoed\n", received, total);
    return 1;
}

int main(int argc, char **argv)
{
    if (enet_initialize() != 0)
    {
        return fail("ENet did not initialize");
    }
    if (argc == 2 && strcmp(argv[1], "server") == 0)
    {
        return runServer();
    }
    if (argc == 4 && strcmp(argv[1], "client") == 0)
    {
        return runClient((enet_uint16) strtoul(argv[2], NULL, 10), (size_t) strtoul(argv[3], NULL, 10));
    }
    fprintf(stderr, "usage: enet_stock_peer server | client <port> <bytes>\n");
    return 2;
}
