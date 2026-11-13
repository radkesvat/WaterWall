/*
 * GameNetworkingSockets over WaterWall's external transport, without WaterWall: two endpoints joined in memory.
 *
 * The library keeps its own service thread and reads its own clock, so this test runs in real time. A second thread
 * plays the wire: the send callbacks only copy a datagram into its queue, and it hands each one to the other
 * endpoint. Every wait has a generous deadline and no timing is asserted.
 */
#include <steam/isteamnetworkingutils.h>
#include <steam/steamnetworkingsockets.h>

#include "gns_external_transport.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

namespace
{

constexpr int      kSendRate     = 20 * 1000 * 1000;
constexpr uint32_t kMessageBytes = 65536;
constexpr size_t   kStreamBytes  = 1024 * 1024;
/* The library sends at its configured rate whatever the receiver can take. The sender therefore stays at most this
 * far ahead of what was received, so that an unoptimized or sanitized build is never flooded. */
constexpr size_t kWindowBytes = 4 * kMessageBytes;
constexpr int    kDeadlineMs  = 60000;

[[noreturn]] void failAt(const char *what, int line)
{
    std::fprintf(stderr, "gns_transport_test: line %d: %s\n", line, what);
    std::fflush(stderr);
    std::_Exit(1);
}

#define REQUIRE(condition)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! (condition))                                                                                             \
        {                                                                                                              \
            failAt(#condition, __LINE__);                                                                              \
        }                                                                                                              \
    } while (0)

gns_external_addr_t syntheticAddress(uint8_t host, uint16_t port)
{
    gns_external_addr_t address = {};
    address.ip[0]               = 0xfd;
    address.ip[15]              = host;
    address.port                = port;
    return address;
}

SteamNetworkingIPAddr libraryAddress(const gns_external_addr_t &address)
{
    SteamNetworkingIPAddr result;
    result.Clear();
    result.SetIPv6(address.ip, address.port);
    return result;
}

uint8_t patternByte(size_t offset, uint8_t seed)
{
    return (uint8_t) (offset * 31U + seed);
}

/* One endpoint and what its callbacks recorded. */
struct side_t
{
    gns_external_endpoint_t *endpoint = nullptr;
    bool                     released = false; /* the test released it before the link ends */
    std::atomic<int>         sent{0};
    std::atomic<int>         idle{0};
    std::atomic<int>         closed{0};
};

void ignoreSend(void *user, const uint8_t *data, size_t length, const gns_external_addr_t *to)
{
    (void) user;
    (void) data;
    (void) length;
    (void) to;
}

/* The wire between a listening and a connecting endpoint. */
class link_t
{
  public:
    link_t() : server_address(syntheticAddress(1, 4000)), client_address(syntheticAddress(2, 5000))
    {
        server.endpoint = gns_external_endpoint_create_listen(&server_address, serverSend, serverEvent, this);
        client.endpoint = gns_external_endpoint_create_connect(&server_address, clientSend, clientEvent, this);
        REQUIRE(server.endpoint != nullptr && client.endpoint != nullptr);
        wire = std::thread([this] { run(); });
    }

    /* The wire stops first, so no datagram is delivered to an endpoint that is being released. */
    ~link_t()
    {
        {
            std::lock_guard<std::mutex> guard(lock);
            stopping = true;
        }
        ready.notify_all();
        wire.join();
        if (! server.released)
        {
            gns_external_endpoint_release(server.endpoint);
        }
        if (! client.released)
        {
            gns_external_endpoint_release(client.endpoint);
        }
    }

    const gns_external_addr_t server_address;
    const gns_external_addr_t client_address;
    side_t                    server;
    side_t                    client;

  private:
    struct datagram_t
    {
        bool                 to_server;
        std::vector<uint8_t> bytes;
    };

    /* Callbacks run with library locks held: they copy and return. */
    void push(bool to_server, const uint8_t *data, size_t length)
    {
        {
            std::lock_guard<std::mutex> guard(lock);
            queue.push_back(datagram_t{to_server, std::vector<uint8_t>(data, data + length)});
        }
        ready.notify_one();
    }

    static void serverSend(void *user, const uint8_t *data, size_t length, const gns_external_addr_t *to)
    {
        link_t *link = static_cast<link_t *>(user);
        REQUIRE(std::memcmp(to, &link->client_address, sizeof(*to)) == 0);
        link->server.sent.fetch_add(1);
        link->push(false, data, length);
    }

    static void clientSend(void *user, const uint8_t *data, size_t length, const gns_external_addr_t *to)
    {
        link_t *link = static_cast<link_t *>(user);
        REQUIRE(std::memcmp(to, &link->server_address, sizeof(*to)) == 0);
        link->client.sent.fetch_add(1);
        link->push(true, data, length);
    }

    static void record(side_t &side, gns_external_event_t event)
    {
        if (event == GNS_EXTERNAL_EVENT_IDLE)
        {
            side.idle.fetch_add(1);
        }
        else if (event == GNS_EXTERNAL_EVENT_CLOSED)
        {
            side.closed.fetch_add(1);
        }
    }

    static void serverEvent(void *user, gns_external_event_t event)
    {
        record(static_cast<link_t *>(user)->server, event);
    }

    static void clientEvent(void *user, gns_external_event_t event)
    {
        record(static_cast<link_t *>(user)->client, event);
    }

    void run()
    {
        for (;;)
        {
            datagram_t datagram;
            {
                std::unique_lock<std::mutex> guard(lock);
                ready.wait(guard, [this] { return stopping || ! queue.empty(); });
                if (stopping)
                {
                    return;
                }
                datagram = std::move(queue.front());
                queue.pop_front();
            }
            /* A false result means that nothing is bound to the endpoint any more: the datagram is lost. */
            if (datagram.to_server)
            {
                gns_external_receive(server.endpoint, &client_address, datagram.bytes.data(), datagram.bytes.size());
            }
            else
            {
                gns_external_receive(client.endpoint, nullptr, datagram.bytes.data(), datagram.bytes.size());
            }
        }
    }

    std::mutex              lock;
    std::condition_variable ready;
    std::deque<datagram_t>  queue;
    bool                    stopping = false;
    std::thread             wire;
};

/* What the status callback saw. One connection pair exists at a time. */
struct status_t
{
    std::atomic<HSteamNetConnection> accepted{k_HSteamNetConnection_Invalid};
    std::atomic<int>                 connected{0};
    std::atomic<int>                 closed_by_peer{0};
    std::atomic<int>                 problems{0};
};

status_t         g_status;
std::atomic<int> g_library_bugs{0};

void onStatusChanged(SteamNetConnectionStatusChangedCallback_t *change)
{
    switch (change->m_info.m_eState)
    {
    case k_ESteamNetworkingConnectionState_Connecting:
        if (change->m_info.m_hListenSocket != k_HSteamListenSocket_Invalid)
        {
            REQUIRE(SteamNetworkingSockets()->AcceptConnection(change->m_hConn) == k_EResultOK);
            g_status.accepted.store(change->m_hConn);
        }
        break;
    case k_ESteamNetworkingConnectionState_Connected:
        g_status.connected.fetch_add(1);
        break;
    case k_ESteamNetworkingConnectionState_ClosedByPeer:
        g_status.closed_by_peer.fetch_add(1);
        break;
    case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
        g_status.problems.fetch_add(1);
        break;
    default:
        break;
    }
}

void onLibraryOutput(ESteamNetworkingSocketsDebugOutputType type, const char *message)
{
    if (type <= k_ESteamNetworkingSocketsDebugOutputType_Error)
    {
        g_library_bugs.fetch_add(1);
        std::fprintf(stderr, "gns_transport_test: library reported (type %d): %s\n", (int) type, message);
    }
}

template <typename predicate_t> void waitFor(predicate_t done, int line)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kDeadlineMs);
    while (! done())
    {
        if (std::chrono::steady_clock::now() > deadline)
        {
            failAt("a wait reached its deadline", line);
        }
        SteamNetworkingSockets()->RunCallbacks();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

#define WAIT_FOR(condition) waitFor([&] { return (condition); }, __LINE__)

void startLibrary()
{
    SteamNetworkingErrMsg error;
    if (! GameNetworkingSockets_Init(nullptr, error))
    {
        failAt(error, __LINE__);
    }
    SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_Warning, onLibraryOutput);
    g_status.accepted.store(k_HSteamNetConnection_Invalid);
    g_status.connected.store(0);
    g_status.closed_by_peer.store(0);
    g_status.problems.store(0);
}

/* Sends count bytes of the pattern from one connection and checks them on the other. One loop does both, so the
 * receiver is drained while the sender waits. */
void transfer(HSteamNetConnection from, HSteamNetConnection to, size_t count, uint8_t seed)
{
    ISteamNetworkingSockets *sockets = SteamNetworkingSockets();
    std::vector<uint8_t>     message(kMessageBytes);
    size_t                   sent     = 0;
    size_t                   received = 0;
    const auto               deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kDeadlineMs);
    while (received < count)
    {
        REQUIRE(std::chrono::steady_clock::now() < deadline);
        bool progress = false;
        if (sent < count && sent - received < kWindowBytes)
        {
            const uint32_t size = (uint32_t) (count - sent < kMessageBytes ? count - sent : kMessageBytes);
            for (uint32_t i = 0; i < size; ++i)
            {
                message[i] = patternByte(sent + i, seed);
            }
            const EResult result =
                sockets->SendMessageToConnection(from, message.data(), size, k_nSteamNetworkingSend_Reliable, nullptr);
            REQUIRE(result == k_EResultOK || result == k_EResultLimitExceeded);
            if (result == k_EResultOK)
            {
                sent += size;
                progress = true;
            }
        }
        SteamNetworkingMessage_t *messages[16];
        const int                 batch = sockets->ReceiveMessagesOnConnection(to, messages, 16);
        REQUIRE(batch >= 0);
        for (int i = 0; i < batch; ++i)
        {
            const uint8_t *bytes = static_cast<const uint8_t *>(messages[i]->m_pData);
            for (int offset = 0; offset < messages[i]->m_cbSize; ++offset)
            {
                REQUIRE(bytes[offset] == patternByte(received + (size_t) offset, seed));
            }
            received += (size_t) messages[i]->m_cbSize;
            messages[i]->Release();
            progress = true;
        }
        if (! progress)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    REQUIRE(received == count);
}

/* Connect through the ordinary public calls, move data both ways, close, and see what the transport reports. */
void caseTransferAndClose()
{
    startLibrary();
    ISteamNetworkingSockets *sockets = SteamNetworkingSockets();
    {
        link_t                       link;
        SteamNetworkingConfigValue_t options[3];
        options[0].SetPtr(k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged, (void *) onStatusChanged);
        options[1].SetInt32(k_ESteamNetworkingConfig_SendRateMin, kSendRate);
        options[2].SetInt32(k_ESteamNetworkingConfig_SendRateMax, kSendRate);

        /* Nothing is bound yet: a datagram for the endpoint is refused, and so is one that is too long. */
        const uint8_t stray[4] = {1, 2, 3, 4};
        REQUIRE(! gns_external_receive(link.server.endpoint, &link.client_address, stray, sizeof(stray)));
        /* An address can be registered once per role. */
        REQUIRE(gns_external_endpoint_create_listen(&link.server_address, ignoreSend, nullptr, nullptr) == nullptr);
        REQUIRE(gns_external_endpoint_create_connect(&link.server_address, ignoreSend, nullptr, nullptr) == nullptr);

        const SteamNetworkingIPAddr address = libraryAddress(link.server_address);
        const HSteamListenSocket    listen  = sockets->CreateListenSocketIP(address, 3, options);
        REQUIRE(listen != k_HSteamListenSocket_Invalid);
        std::vector<uint8_t> oversized(GNS_EXTERNAL_MAX_DATAGRAM + 1);
        REQUIRE(! gns_external_receive(link.server.endpoint, &link.client_address, oversized.data(), oversized.size()));

        const HSteamNetConnection client = sockets->ConnectByIPAddress(address, 3, options);
        REQUIRE(client != k_HSteamNetConnection_Invalid);
        WAIT_FOR(g_status.connected.load() == 2);
        const HSteamNetConnection server = g_status.accepted.load();
        REQUIRE(server != k_HSteamNetConnection_Invalid);

        transfer(client, server, kStreamBytes, 7);
        transfer(server, client, kStreamBytes, 91);

        /* The client closes after its data is delivered. The server sees it and closes its side, which leaves the
         * listen endpoint without a remote host. */
        REQUIRE(sockets->CloseConnection(client, 0, "done", true));
        WAIT_FOR(g_status.closed_by_peer.load() == 1);
        REQUIRE(link.server.idle.load() == 0);
        REQUIRE(sockets->CloseConnection(server, 0, nullptr, false));
        WAIT_FOR(link.server.idle.load() == 1);
        /* The library closes the client's endpoint when its connection is gone. */
        WAIT_FOR(link.client.closed.load() == 1);
        REQUIRE(link.server.closed.load() == 0);
        REQUIRE(sockets->CloseListenSocket(listen));
        WAIT_FOR(link.server.closed.load() == 1);
        REQUIRE(link.server.idle.load() == 1 && link.client.idle.load() == 0);
        REQUIRE(g_status.problems.load() == 0);
    }
    GameNetworkingSockets_Kill();
}

/* The owner may release an endpoint that the library still uses. Nothing is sent to it afterwards, and the library
 * frees the object when it closes it. */
void caseReleaseWhileBound()
{
    startLibrary();
    ISteamNetworkingSockets *sockets = SteamNetworkingSockets();
    {
        link_t                      link;
        const SteamNetworkingIPAddr address = libraryAddress(link.server_address);
        /* No listen socket: the connection keeps asking and never connects. */
        const HSteamNetConnection client = sockets->ConnectByIPAddress(address, 0, nullptr);
        REQUIRE(client != k_HSteamNetConnection_Invalid);
        WAIT_FOR(link.client.sent.load() >= 2);

        gns_external_endpoint_release(link.client.endpoint);
        link.client.released      = true;
        const int sent_at_release = link.client.sent.load();
        std::this_thread::sleep_for(std::chrono::milliseconds(1200)); /* two of the library's connect retries */
        REQUIRE(link.client.sent.load() == sent_at_release);
        REQUIRE(sockets->CloseConnection(client, 0, nullptr, false));
        REQUIRE(link.client.closed.load() == 0);
    }
    GameNetworkingSockets_Kill();
}

} // namespace

int main()
{
    /* Twice: the second pass starts the library and its service thread again after a complete shutdown. */
    for (int pass = 0; pass < 2; ++pass)
    {
        caseTransferAndClose();
        caseReleaseWhileBound();
    }
    REQUIRE(g_library_bugs.load() == 0);
    std::printf("gns_transport_test: ok\n");
    return 0;
}
