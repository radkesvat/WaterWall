/* CTest: waterwall.enet_socket_interop_unit.
 * A WaterWall ENet session against a plain ENet application over real UDP sockets on loopback, in both roles.
 * The application is enet_stock_peer.c in its own process: the vendored protocol core with upstream's own socket
 * layer. This side is the worker session that EnetClient and EnetServer use. The test stands where the UDP adapter
 * would be: it moves each datagram between the session and one socket, and ticks the session on the real clock.
 * Covers the native handshake, stream bytes in both directions across fragmented packets, the send hold, and an
 * orderly close started by either side. Linux only. */

#include "EnetCommon/driver.h"
#include "EnetCommon/session.h"

#include "enet_runtime.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

enum
{
    kTransferBytes = 2 * 1024 * 1024,
    kChunk         = 16384,
    kDeadlineMs    = 20000
};

typedef struct link_s
{
    enet_session_t       *session;
    int                   socket_fd;
    struct sockaddr_in    peer;
    bool                  peer_known;
    bool                  echo; /* offer every received byte back, as the application's server does */
    bool                  connected;
    bool                  paused;
    unsigned              terminal_calls;
    enet_session_result_t result;
    size_t                sent, received;
} link_t;

/* The same pattern as enet_stock_peer.c. */
static uint8_t patternByte(size_t offset)
{
    return (uint8_t) (offset * 31U + (offset >> 8));
}

static uint64_t linkNow(void *clock_user)
{
    discard clock_user;
    return getHRTimeUs() / 1000U;
}

static void linkEmit(void *user, sbuf_t *packet)
{
    link_t *link = user;
    if (link->peer_known)
    {
        /* A full socket buffer loses the datagram, as a UDP path can. ENet sends it again. */
        discard sendto(link->socket_fd,
                       sbufGetRawPtr(packet),
                       sbufGetLength(packet),
                       0,
                       (const struct sockaddr *) &link->peer,
                       sizeof(link->peer));
    }
    bufferpoolReuseBuffer(getWorkerBufferPool(0), packet);
}

static void linkPayload(void *user, sbuf_t *payload)
{
    link_t        *link   = user;
    const uint8_t *bytes  = sbufGetRawPtr(payload);
    const size_t   length = sbufGetLength(payload);
    for (size_t i = 0; i < length; ++i)
    {
        enetRequire(bytes[i] == patternByte(link->received + i), "the ENet application's bytes changed on the way");
    }
    link->received += length;
    bufferpoolReuseBuffer(getWorkerBufferPool(0), payload);
}

static void linkConnected(void *user)
{
    link_t *link    = user;
    link->connected = true;
}

static void linkPressure(void *user, bool paused)
{
    link_t *link = user;
    link->paused = paused;
}

static void linkTerminal(void *user, enet_session_result_t result)
{
    link_t *link = user;
    link->terminal_calls += 1;
    link->result = result;
}

static void linkOpen(link_t *link, bool client)
{
    memoryZero(link, sizeof(*link));
    link->echo      = ! client;
    link->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    enetRequire(link->socket_fd >= 0, "no UDP socket");
    const struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    enetRequire(bind(link->socket_fd, (const struct sockaddr *) &local, sizeof(local)) == 0,
                "the UDP socket did not bind to loopback");
    enet_settings_t settings;
    enetRequire(enetSettingsParse(&settings, NULL, client ? "EnetClient" : "EnetServer"),
                "the default settings were refused");
    const enet_session_config_t config = {
        .settings = settings,
        .client   = client,
        .pool     = getWorkerBufferPool(0),
        .now      = linkNow,
    };
    const enet_session_callbacks_t callbacks = {
        .emit      = linkEmit,
        .payload   = linkPayload,
        .connected = linkConnected,
        .pressure  = linkPressure,
        .terminal  = linkTerminal,
    };
    link->session = enetSessionCreate(&config, &callbacks, link);
    enetRequire(link->session != NULL, "session creation failed");
}

static void linkClose(link_t *link)
{
    enetSessionAbort(link->session, kEnetSessionAborted);
    enetSessionRelease(link->session);
    close(link->socket_fd);
}

/* Offers the pattern while the session accepts bytes, as a producer that honours Pause does. The client role
 * offers the whole transfer. The echo role offers back as many bytes as it has received, which are the same bytes. */
static void linkFeed(link_t *link)
{
    const size_t target = link->echo ? link->received : (size_t) kTransferBytes;
    while (link->connected && link->terminal_calls == 0 && ! link->paused && link->sent < target)
    {
        const size_t size    = min(target - link->sent, (size_t) kChunk);
        sbuf_t      *payload = bufferpoolGetBestFit(getWorkerBufferPool(0), (uint32_t) size, 0);
        for (size_t i = 0; i < size; ++i)
        {
            sbufGetMutablePtr(payload)[i] = patternByte(link->sent + i);
        }
        sbufSetLength(payload, (uint32_t) size);
        link->sent += size;
        enetSessionSend(link->session, payload);
    }
}

/* Moves datagrams from the socket into the session and ticks the session until done() or the deadline. */
static bool linkRun(link_t *link, bool (*done)(const link_t *link))
{
    const uint64_t deadline = linkNow(NULL) + kDeadlineMs;
    while (! done(link) && linkNow(NULL) < deadline)
    {
        struct pollfd wait = {.fd = link->socket_fd, .events = POLLIN};
        discard       poll(&wait, 1, 2);
        for (;;)
        {
            uint8_t            datagram[kEnetDriverHostMtuMax];
            struct sockaddr_in from;
            socklen_t          from_length = sizeof(from);
            const ssize_t      length      = recvfrom(
                link->socket_fd, datagram, sizeof(datagram), MSG_DONTWAIT, (struct sockaddr *) &from, &from_length);
            if (length <= 0)
            {
                break;
            }
            if (! link->peer_known)
            {
                link->peer       = from;
                link->peer_known = true;
            }
            sbuf_t *packet = bufferpoolGetBestFit(getWorkerBufferPool(0), (uint32_t) length, 0);
            memoryCopy(sbufGetMutablePtr(packet), datagram, (size_t) length);
            sbufSetLength(packet, (uint32_t) length);
            enetSessionInput(link->session, packet);
        }
        linkFeed(link);
        enetSessionTick(link->session, linkNow(NULL));
    }
    if (! done(link))
    {
        fprintf(stderr,
                "enet_socket_interop_test: deadline with sent=%zu received=%zu connected=%d paused=%d\n",
                link->sent,
                link->received,
                (int) link->connected,
                (int) link->paused);
    }
    return done(link);
}

static bool linkEnded(const link_t *link)
{
    return link->terminal_calls != 0;
}

static bool linkEchoComplete(const link_t *link)
{
    return link->received == kTransferBytes || link->terminal_calls != 0;
}

/* Starts the ENet application. Its standard output arrives on *output. */
static pid_t peerStart(const char *mode, const char *port, const char *bytes, int *output)
{
    int pipe_fds[2];
    enetRequire(pipe(pipe_fds) == 0, "no pipe for the ENet application");
    const pid_t child = fork();
    enetRequire(child >= 0, "the ENet application did not start");
    if (child == 0)
    {
        dup2(pipe_fds[1], STDOUT_FILENO);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        execl(ENET_STOCK_PEER, ENET_STOCK_PEER, mode, port, bytes, (char *) NULL);
        _exit(127);
    }
    close(pipe_fds[1]);
    *output = pipe_fds[0];
    return child;
}

static uint16_t peerReadPort(int output)
{
    char          text[16] = {0};
    size_t        used     = 0;
    struct pollfd wait     = {.fd = output, .events = POLLIN};
    while (used + 1 < sizeof(text) && memchr(text, '\n', used) == NULL)
    {
        enetRequire(poll(&wait, 1, 5000) == 1, "the ENet application did not report its port");
        const ssize_t got = read(output, text + used, sizeof(text) - 1 - used);
        enetRequire(got > 0, "the ENet application closed its output");
        used += (size_t) got;
    }
    return (uint16_t) strtoul(text, NULL, 10);
}

/* The application's exit status is its own verdict on the exchange. */
static void peerRequireSuccess(pid_t child)
{
    const uint64_t deadline = linkNow(NULL) + kDeadlineMs;
    int            status   = 0;
    pid_t          ended    = 0;
    while ((ended = waitpid(child, &status, WNOHANG)) == 0 && linkNow(NULL) < deadline)
    {
        usleep(10000);
    }
    if (ended == 0)
    {
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        enetRequire(false, "the ENet application did not exit");
    }
    enetRequire(ended == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "the ENet application reported a failed exchange");
}

/* EnetClient's role: the session connects to a native ENet server, sends, reads the echo and closes first. */
static void caseNativeServer(void)
{
    int         output = -1;
    const pid_t peer   = peerStart("server", NULL, NULL, &output);
    link_t      link;
    linkOpen(&link, true);
    link.peer = (struct sockaddr_in) {
        .sin_family = AF_INET, .sin_port = htons(peerReadPort(output)), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    link.peer_known = true;
    enetSessionStart(link.session);
    enetRequire(linkRun(&link, linkEchoComplete) && link.terminal_calls == 0,
                "the echo from the native ENet server was incomplete");
    TEST_EQUAL_SIZE(
        TEST_FAILURE_EXIT, link.sent, (size_t) kTransferBytes, "the session accepted less than the test offered");
    enetSessionAppFinish(link.session);
    enetRequire(linkRun(&link, linkEnded) && link.result == kEnetSessionClosed,
                "the native ENet server did not confirm the session's close");
    peerRequireSuccess(peer);
    linkClose(&link);
    close(output);
}

/* EnetServer's role: a native ENet client connects, sends, reads the session's echo and disconnects first. */
static void caseNativeClient(void)
{
    link_t link;
    linkOpen(&link, false);
    struct sockaddr_in local;
    socklen_t          local_length = sizeof(local);
    enetRequire(getsockname(link.socket_fd, (struct sockaddr *) &local, &local_length) == 0,
                "the UDP socket has no local address");
    char port[8];
    char bytes[16];
    snprintf(port, sizeof(port), "%u", (unsigned) ntohs(local.sin_port));
    snprintf(bytes, sizeof(bytes), "%u", (unsigned) kTransferBytes);
    int         output = -1;
    const pid_t peer   = peerStart("client", port, bytes, &output);
    enetSessionStart(link.session);
    enetRequire(linkRun(&link, linkEnded), "the native ENet client did not finish and disconnect");
    enetRequire(link.result == kEnetSessionPeerClosed,
                "the native client's disconnect was not reported as a peer close");
    TEST_EQUAL_SIZE(
        TEST_FAILURE_EXIT, link.received, (size_t) kTransferBytes, "the session received less than the client sent");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, link.sent, (size_t) kTransferBytes, "the session echoed less than it received");
    peerRequireSuccess(peer);
    linkClose(&link);
    close(output);
}

int main(void)
{
    enetRuntimeStart();
    enetRequire(enetDriverInstall(&memoryAllocate, &memoryFree), "ENet refused the WaterWall allocator");
    TEST_RUN_CASE(caseNativeServer);
    TEST_RUN_CASE(caseNativeClient);
    enetRuntimeStop();
    return 0;
}
