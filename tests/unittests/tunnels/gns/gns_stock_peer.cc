/* A plain GameNetworkingSockets application for waterwall.gns_socket_interop_unit.
 *
 * It is the library with upstream's own socket file, so it opens real UDP sockets and uses nothing of WaterWall. It
 * is a separate program because that file and WaterWall's external transport define the same functions.
 *
 *     gns_stock_peer server <port>          listen on the loopback port, print "ready", echo one peer's messages
 *     gns_stock_peer client <port> <bytes>  connect, send <bytes> of the pattern, expect the same bytes back
 *
 * Exit status 0: the exchange was complete and the connection ended with a close notice. */

#include <steam/isteamnetworkingutils.h>
#include <steam/steamnetworkingsockets.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace
{

constexpr int kDeadlineSeconds = 30;
/* The library sends at a fixed rate. Its default would take eight seconds for the test's two mebibytes. */
constexpr int32 kSendRate = 8 * 1024 * 1024;

HSteamNetConnection g_connection     = k_HSteamNetConnection_Invalid;
bool                g_connected      = false;
bool                g_closed_by_peer = false;
bool                g_failed         = false;

/* Every failure says why on standard error, which the test shares. */
int fail(const char *reason)
{
    std::fprintf(stderr, "gns_stock_peer: %s\n", reason);
    return 1;
}

/* The same pattern as gns_socket_interop_test.c. */
uint8_t patternByte(size_t offset)
{
    return (uint8_t) (offset * 31U + (offset >> 8));
}

void onStatusChanged(SteamNetConnectionStatusChangedCallback_t *change)
{
    ISteamNetworkingSockets *sockets = SteamNetworkingSockets();
    switch (change->m_info.m_eState)
    {
    case k_ESteamNetworkingConnectionState_Connecting:
        if (change->m_info.m_hListenSocket == k_HSteamListenSocket_Invalid)
        {
            break; /* this side's own connection attempt */
        }
        /* The echo serves one peer. */
        if (g_connection != k_HSteamNetConnection_Invalid || sockets->AcceptConnection(change->m_hConn) != k_EResultOK)
        {
            sockets->CloseConnection(change->m_hConn, 0, nullptr, false);
            break;
        }
        g_connection = change->m_hConn;
        break;
    case k_ESteamNetworkingConnectionState_Connected:
        g_connected = true;
        break;
    case k_ESteamNetworkingConnectionState_ClosedByPeer:
        g_closed_by_peer = true;
        break;
    case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
        g_failed = true;
        break;
    default:
        break;
    }
}

SteamNetworkingIPAddr loopback(uint16 port)
{
    SteamNetworkingIPAddr address;
    address.Clear();
    address.SetIPv4(0x7f000001, port);
    return address;
}

bool beforeDeadline(std::chrono::steady_clock::time_point start)
{
    return std::chrono::steady_clock::now() - start < std::chrono::seconds(kDeadlineSeconds);
}

void pause()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

int runServer(uint16 port)
{
    ISteamNetworkingSockets *sockets = SteamNetworkingSockets();
    const HSteamListenSocket listen  = sockets->CreateListenSocketIP(loopback(port), 0, nullptr);
    if (listen == k_HSteamListenSocket_Invalid)
    {
        return fail("no listen socket on the loopback port");
    }
    std::puts("ready");
    std::fflush(stdout);

    size_t                    echoed = 0;
    SteamNetworkingMessage_t *held   = nullptr; /* received and not yet accepted by the send buffer */
    const auto                start  = std::chrono::steady_clock::now();
    while (beforeDeadline(start))
    {
        sockets->RunCallbacks();
        if (g_failed)
        {
            return fail("the library gave the connection up");
        }
        while (g_connection != k_HSteamNetConnection_Invalid)
        {
            if (held == nullptr && sockets->ReceiveMessagesOnConnection(g_connection, &held, 1) != 1)
            {
                held = nullptr;
                break;
            }
            const EResult result = sockets->SendMessageToConnection(
                g_connection, held->m_pData, (uint32) held->m_cbSize, k_nSteamNetworkingSend_Reliable, nullptr);
            if (result == k_EResultLimitExceeded)
            {
                break; /* the send buffer is full: offer the same message again later */
            }
            if (result != k_EResultOK && ! g_closed_by_peer)
            {
                return fail("could not queue an echo message");
            }
            echoed += (size_t) held->m_cbSize;
            held->Release();
            held = nullptr;
        }
        if (g_closed_by_peer)
        {
            sockets->CloseConnection(g_connection, 0, nullptr, false);
            sockets->CloseListenSocket(listen);
            return g_connected && echoed > 0 ? 0 : fail("the peer closed before any exchange");
        }
        pause();
    }
    return fail("no close from the peer before the deadline");
}

int runClient(uint16 port, size_t total)
{
    /* Messages below one datagram, around one, and far above one, so the library splits some of them. */
    static const size_t      sizes[] = {1, 37, 1200, 4000, 65536};
    ISteamNetworkingSockets *sockets = SteamNetworkingSockets();
    g_connection                     = sockets->ConnectByIPAddress(loopback(port), 0, nullptr);
    if (g_connection == k_HSteamNetConnection_Invalid)
    {
        return fail("no connection attempt");
    }

    std::vector<uint8_t> message(65536);
    size_t               sent     = 0;
    size_t               received = 0;
    size_t               index    = 0;
    const auto           start    = std::chrono::steady_clock::now();
    while (beforeDeadline(start))
    {
        sockets->RunCallbacks();
        if (g_failed || g_closed_by_peer)
        {
            return fail("the connection ended before the echo was complete");
        }
        while (g_connected && sent < total)
        {
            size_t size = sizes[index % (sizeof(sizes) / sizeof(sizes[0]))];
            if (size > total - sent)
            {
                size = total - sent;
            }
            for (size_t b = 0; b < size; ++b)
            {
                message[b] = patternByte(sent + b);
            }
            const EResult result = sockets->SendMessageToConnection(
                g_connection, message.data(), (uint32) size, k_nSteamNetworkingSend_Reliable, nullptr);
            if (result == k_EResultLimitExceeded)
            {
                break; /* the send buffer is full: offer the same bytes again later */
            }
            if (result != k_EResultOK)
            {
                return fail("could not queue a message");
            }
            sent += size;
            ++index;
        }
        SteamNetworkingMessage_t *messages[16];
        int                       count;
        while ((count = sockets->ReceiveMessagesOnConnection(g_connection, messages, 16)) > 0)
        {
            bool intact = true;
            for (int i = 0; i < count; ++i)
            {
                const uint8_t *bytes = static_cast<const uint8_t *>(messages[i]->m_pData);
                for (int b = 0; b < messages[i]->m_cbSize; ++b)
                {
                    intact = intact && received + (size_t) b < total && bytes[b] == patternByte(received + (size_t) b);
                }
                received += (size_t) messages[i]->m_cbSize;
                messages[i]->Release();
            }
            if (! intact)
            {
                return fail("the echo differs from the pattern or is too long");
            }
        }
        if (received == total)
        {
            /* Everything was echoed, so nothing waits to be sent. The library writes its close notice inside this
             * call. */
            sockets->CloseConnection(g_connection, 0, nullptr, false);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            return 0;
        }
        pause();
    }
    std::fprintf(stderr, "gns_stock_peer: deadline with %zu of %zu bytes echoed\n", received, total);
    return 1;
}

} // namespace

int main(int argc, char **argv)
{
    const bool server = argc == 3 && std::strcmp(argv[1], "server") == 0;
    const bool client = argc == 4 && std::strcmp(argv[1], "client") == 0;
    if (! server && ! client)
    {
        std::fprintf(stderr, "usage: gns_stock_peer server <port> | client <port> <bytes>\n");
        return 2;
    }
    SteamNetworkingErrMsg error;
    if (! GameNetworkingSockets_Init(nullptr, error))
    {
        return fail(error);
    }
    ISteamNetworkingUtils *utils = SteamNetworkingUtils();
    utils->SetGlobalCallback_SteamNetConnectionStatusChanged(onStatusChanged);
    utils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_SendRateMin, kSendRate);
    utils->SetGlobalConfigValueInt32(k_ESteamNetworkingConfig_SendRateMax, kSendRate);
    const uint16 port   = (uint16) std::strtoul(argv[2], nullptr, 10);
    const int    result = server ? runServer(port) : runClient(port, (size_t) std::strtoul(argv[3], nullptr, 10));
    GameNetworkingSockets_Kill();
    return result;
}
