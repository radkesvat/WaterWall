/* CTest: waterwall.gns_socket_interop_unit.
 * A WaterWall GNS session against a plain GameNetworkingSockets application over real UDP sockets on loopback, in
 * both roles. The application is gns_stock_peer.cc in its own process: the library with upstream's own socket
 * file. This side is the worker session that GnsClient and GnsServer use. The test stands where the UDP adapter
 * would be: it moves each datagram between the session and one socket, and steps the worker loop.
 * Covers the native handshake, stream bytes in both directions across messages of many sizes, the send hold, and a
 * close started by either side. Linux only. */

#include "GnsCommon/port.h"
#include "GnsCommon/session.h"

#include "gns_runtime.h"

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
    kDeadlineMs    = 30000,
    kDatagramBytes = 2048, /* more than any datagram GNS sends */
};

typedef struct link_s
{
    gns_session_t       *session;
    int                  socket_fd;
    struct sockaddr_in   peer;
    bool                 peer_known;
    bool                 echo; /* offer every received byte back, as the application's server does */
    bool                 connected;
    bool                 paused;
    unsigned             terminal_calls;
    gns_session_result_t result;
    size_t               sent, received;
} link_t;

/* The same pattern as gns_stock_peer.cc. */
static uint8_t patternByte(size_t offset)
{
    return (uint8_t) (offset * 31U + (offset >> 8));
}

static void linkEmit(void *user, sbuf_t *packet)
{
    link_t *link = user;
    if (link->peer_known)
    {
        /* A full socket buffer loses the datagram, as a UDP path can. GNS sends it again. */
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
        gnsRequire(bytes[i] == patternByte(link->received + i), "the GNS application's bytes changed on the way");
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

static void linkTerminal(void *user, gns_session_result_t result)
{
    link_t *link = user;
    link->terminal_calls += 1;
    link->result = result;
}

static int loopbackSocket(uint16_t *port)
{
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    gnsRequire(fd >= 0, "no UDP socket");
    struct sockaddr_in local        = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t          local_length = sizeof(local);
    gnsRequire(bind(fd, (const struct sockaddr *) &local, sizeof(local)) == 0,
               "the UDP socket did not bind to loopback");
    gnsRequire(getsockname(fd, (struct sockaddr *) &local, &local_length) == 0, "the UDP socket has no local address");
    *port = ntohs(local.sin_port);
    return fd;
}

static void linkOpen(link_t *link, bool client, uint16_t *port)
{
    memoryZero(link, sizeof(*link));
    link->echo                  = ! client;
    link->socket_fd             = loopbackSocket(port);
    gns_session_config_t config = {
        .client = client,
        .wid    = 0,
        .pool   = getWorkerBufferPool(0),
        .loop   = getWorkerLoop(0),
    };
    /* The application sends at the same rate. At GNS's default the transfer would take eight seconds each way. */
    cJSON *json = cJSON_Parse("{\"send-rate\":8388608}");
    gnsRequire(json != NULL && gnsSettingsParse(&config.settings, json, client ? "GnsClient" : "GnsServer"),
               "the test's settings were refused");
    cJSON_Delete(json);
    const gns_session_callbacks_t callbacks = {
        .emit      = linkEmit,
        .payload   = linkPayload,
        .connected = linkConnected,
        .pressure  = linkPressure,
        .terminal  = linkTerminal,
    };
    link->session = gnsSessionCreate(&config, &callbacks, link);
    gnsRequire(link->session != NULL, "session creation failed");
}

static void linkClose(link_t *link)
{
    gnsSessionAbort(link->session, kGnsSessionAborted);
    gnsSessionRelease(link->session);
    close(link->socket_fd);
    /* Wakes that were on their way to the session find it gone. */
    gnsTestStep();
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
        gnsSessionSend(link->session, payload);
    }
}

/* Moves datagrams from the socket into the session and steps the worker until done() or the deadline. */
static bool linkRun(link_t *link, bool (*done)(const link_t *link))
{
    const uint64_t deadline = gnsTestNowMs() + kDeadlineMs;
    while (! done(link) && gnsTestNowMs() < deadline)
    {
        struct pollfd wait = {.fd = link->socket_fd, .events = POLLIN};
        discard       poll(&wait, 1, 2);
        while (link->terminal_calls == 0)
        {
            uint8_t            datagram[kDatagramBytes];
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
            gnsSessionInput(link->session, packet);
        }
        linkFeed(link);
        gnsTestStep();
    }
    if (! done(link))
    {
        fprintf(stderr,
                "gns_socket_interop_test: deadline with sent=%zu received=%zu connected=%d paused=%d\n",
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

/* Starts the GNS application. Its standard output arrives on *output. */
static pid_t peerStart(const char *mode, const char *port, const char *bytes, int *output)
{
    int pipe_fds[2];
    gnsRequire(pipe(pipe_fds) == 0, "no pipe for the GNS application");
    const pid_t child = fork();
    gnsRequire(child >= 0, "the GNS application did not start");
    if (child == 0)
    {
        dup2(pipe_fds[1], STDOUT_FILENO);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        execl(GNS_STOCK_PEER, GNS_STOCK_PEER, mode, port, bytes, (char *) NULL);
        _exit(127);
    }
    close(pipe_fds[1]);
    *output = pipe_fds[0];
    return child;
}

/* The application's server prints one line when its listen socket exists. */
static void peerWaitReady(int output)
{
    char          text[16] = {0};
    size_t        used     = 0;
    struct pollfd wait     = {.fd = output, .events = POLLIN};
    while (used + 1 < sizeof(text) && memchr(text, '\n', used) == NULL)
    {
        gnsRequire(poll(&wait, 1, 10000) == 1, "the GNS application did not report that it listens");
        const ssize_t got = read(output, text + used, sizeof(text) - 1 - used);
        gnsRequire(got > 0, "the GNS application closed its output");
        used += (size_t) got;
    }
}

/* The application's exit status is its own verdict on the exchange. */
static void peerRequireSuccess(pid_t child)
{
    const uint64_t deadline = gnsTestNowMs() + kDeadlineMs;
    int            status   = 0;
    pid_t          ended    = 0;
    while ((ended = waitpid(child, &status, WNOHANG)) == 0 && gnsTestNowMs() < deadline)
    {
        usleep(10000);
    }
    if (ended == 0)
    {
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        gnsRequire(false, "the GNS application did not exit");
    }
    gnsRequire(ended == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "the GNS application reported a failed exchange");
}

/* GnsClient's role: the session connects to a native GNS server, sends, reads the echo and closes first. */
static void caseNativeServer(void)
{
    /* The library cannot report a port it chose, so the test chooses one: the port a socket just had. */
    uint16_t  server_port = 0;
    const int probe       = loopbackSocket(&server_port);
    close(probe);
    char port[8];
    snprintf(port, sizeof(port), "%u", (unsigned) server_port);
    int         output = -1;
    const pid_t peer   = peerStart("server", port, NULL, &output);
    peerWaitReady(output);

    link_t   link;
    uint16_t local_port = 0;
    linkOpen(&link, true, &local_port);
    link.peer = (struct sockaddr_in) {
        .sin_family = AF_INET, .sin_port = htons(server_port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    link.peer_known = true;
    gnsSessionStart(link.session);
    gnsRequire(linkRun(&link, linkEchoComplete) && link.terminal_calls == 0,
               "the echo from the native GNS server was incomplete");
    TEST_EQUAL_SIZE(
        TEST_FAILURE_EXIT, link.sent, (size_t) kTransferBytes, "the session accepted less than the test offered");
    gnsSessionAppFinish(link.session);
    gnsRequire(linkRun(&link, linkEnded) && link.result == kGnsSessionClosed, "the session's close did not finish");
    /* The application exits with success only after it has seen the session's close notice. */
    peerRequireSuccess(peer);
    linkClose(&link);
    close(output);
}

/* GnsServer's role: a native GNS client connects, sends, reads the session's echo and closes first. */
static void caseNativeClient(void)
{
    link_t   link;
    uint16_t local_port = 0;
    linkOpen(&link, false, &local_port);
    char port[8];
    char bytes[16];
    snprintf(port, sizeof(port), "%u", (unsigned) local_port);
    snprintf(bytes, sizeof(bytes), "%u", (unsigned) kTransferBytes);
    int         output = -1;
    const pid_t peer   = peerStart("client", port, bytes, &output);
    gnsSessionStart(link.session);
    gnsRequire(linkRun(&link, linkEnded), "the native GNS client did not finish and close");
    gnsRequire(link.result == kGnsSessionPeerClosed, "the native client's close was not reported as a peer close");
    TEST_EQUAL_SIZE(
        TEST_FAILURE_EXIT, link.received, (size_t) kTransferBytes, "the session received less than the client sent");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, link.sent, (size_t) kTransferBytes, "the session echoed less than it received");
    peerRequireSuccess(peer);
    linkClose(&link);
    close(output);
}

int main(void)
{
    gnsTestRuntimeStart();
    gnsRequire(gnsRuntimeAcquire("GnsTest"), "GameNetworkingSockets did not start");
    TEST_RUN_CASE(caseNativeServer);
    TEST_RUN_CASE(caseNativeClient);
    gnsRuntimeRelease();
    gnsTestRuntimeStop();
    return 0;
}
