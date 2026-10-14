#include "tcp_socket_diag.h"

#include "test_assert.h"

#include <linux/inet_diag.h>
#include <linux/netlink.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef enum diagnostic_fault_e
{
    DIAG_FAULT_NONE,
    DIAG_FAULT_SOCKET_DENIED,
    DIAG_FAULT_SEND_DENIED,
    DIAG_FAULT_RECV_UNAVAILABLE,
    DIAG_FAULT_MISSING_SHUTDOWN,
    DIAG_FAULT_MALFORMED_REPLY
} diagnostic_fault_t;

static diagnostic_fault_t diagnostic_fault;
static int                diagnostic_fd = -1;
static bool               fault_injected;

int     __real_socket(int domain, int type, int protocol);
int     __wrap_socket(int domain, int type, int protocol);
ssize_t __real_sendto(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *address,
                      socklen_t address_size);
ssize_t __wrap_sendto(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *address,
                      socklen_t address_size);
ssize_t __real_recvmsg(int fd, struct msghdr *message, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags);

int __wrap_socket(int domain, int type, int protocol)
{
    if (domain != AF_NETLINK || protocol != NETLINK_SOCK_DIAG)
    {
        return __real_socket(domain, type, protocol);
    }
    if (diagnostic_fault == DIAG_FAULT_SOCKET_DENIED)
    {
        fault_injected = true;
        errno          = EPERM;
        return -1;
    }
    diagnostic_fd = __real_socket(domain, type, protocol);
    return diagnostic_fd;
}

ssize_t __wrap_sendto(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *address,
                      socklen_t address_size)
{
    if (fd == diagnostic_fd && diagnostic_fault == DIAG_FAULT_SEND_DENIED)
    {
        fault_injected = true;
        errno          = EPERM;
        return -1;
    }
    return __real_sendto(fd, buffer, size, flags, address, address_size);
}

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags)
{
    if (fd == diagnostic_fd && diagnostic_fault == DIAG_FAULT_RECV_UNAVAILABLE)
    {
        fault_injected = true;
        errno          = EAGAIN;
        return -1;
    }

    ssize_t received = __real_recvmsg(fd, message, flags);
    if (fd == diagnostic_fd &&
        (diagnostic_fault == DIAG_FAULT_MISSING_SHUTDOWN || diagnostic_fault == DIAG_FAULT_MALFORMED_REPLY))
    {
        require(received >= (ssize_t) NLMSG_LENGTH(sizeof(struct inet_diag_msg)),
                "diagnostic reply unavailable for fault injection");
        struct nlmsghdr *header = message->msg_iov[0].iov_base;
        if (diagnostic_fault == DIAG_FAULT_MISSING_SHUTDOWN)
        {
            header->nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_msg));
            received          = (ssize_t) header->nlmsg_len;
        }
        else
        {
            header->nlmsg_len = (uint32_t) received + 1;
        }
        fault_injected = true;
    }
    return received;
}

typedef struct tcp_pair_s
{
    int listener;
    int client;
    int server;
} tcp_pair_t;

static tcp_pair_t openPair(int server_family, int client_family, bool mapped)
{
    tcp_pair_t pair = {
        .listener = socket(server_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP), .client = -1, .server = -1};
    require(pair.listener >= 0, "listener socket failed");
    if (server_family == AF_INET6)
    {
        int only_v6 = mapped ? 0 : 1;
        require(setsockopt(pair.listener, IPPROTO_IPV6, IPV6_V6ONLY, &only_v6, sizeof(only_v6)) == 0,
                "listener IPv6 mode failed");
    }

    struct sockaddr_storage address = {0};
    socklen_t               length;
    if (server_family == AF_INET)
    {
        struct sockaddr_in *v4 = (struct sockaddr_in *) &address;
        v4->sin_family         = AF_INET;
        v4->sin_addr.s_addr    = htonl(INADDR_LOOPBACK);
        length                 = sizeof(*v4);
    }
    else
    {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) &address;
        v6->sin6_family         = AF_INET6;
        v6->sin6_addr           = mapped ? in6addr_any : in6addr_loopback;
        length                  = sizeof(*v6);
    }
    require(bind(pair.listener, (struct sockaddr *) &address, length) == 0, "listener bind failed");
    require(getsockname(pair.listener, (struct sockaddr *) &address, &length) == 0, "listener address failed");
    require(listen(pair.listener, 1) == 0, "listen failed");
    require(! tcpSocketPeerHasWriteShutdown(pair.listener), "listener was mistaken for a half-closed connection");

    uint16_t port = server_family == AF_INET ? ((struct sockaddr_in *) &address)->sin_port
                                             : ((struct sockaddr_in6 *) &address)->sin6_port;
    memset(&address, 0, sizeof(address));
    if (client_family == AF_INET)
    {
        struct sockaddr_in *v4 = (struct sockaddr_in *) &address;
        v4->sin_family         = AF_INET;
        v4->sin_addr.s_addr    = htonl(INADDR_LOOPBACK);
        v4->sin_port           = port;
        length                 = sizeof(*v4);
    }
    else
    {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) &address;
        v6->sin6_family         = AF_INET6;
        v6->sin6_port           = port;
        require(inet_pton(AF_INET6, mapped ? "::ffff:127.0.0.1" : "::1", &v6->sin6_addr) == 1, "IPv6 parse failed");
        length = sizeof(*v6);
    }
    pair.client = socket(client_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    require(pair.client >= 0, "client socket failed");
    require(connect(pair.client, (struct sockaddr *) &address, length) == 0, "connect failed");
    pair.server = accept4(pair.listener, NULL, NULL, SOCK_CLOEXEC);
    require(pair.server >= 0, "accept failed");
    struct timeval timeout = {.tv_sec = 2};
    require(setsockopt(pair.client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "receive timeout failed");
    return pair;
}

static void closePair(tcp_pair_t pair)
{
    if (pair.server >= 0)
    {
        close(pair.server);
    }
    close(pair.client);
    close(pair.listener);
}

static void expectEOF(int client)
{
    char byte;
    require(recv(client, &byte, sizeof(byte), 0) == 0, "target FIN was not received");
}

static void testShutdown(int server_family, int client_family, bool mapped)
{
    tcp_pair_t pair = openPair(server_family, client_family, mapped);
    require(! tcpSocketPeerHasWriteShutdown(pair.client), "open peer was reported as half-closed");
    require(shutdown(pair.server, SHUT_WR) == 0, "peer write shutdown failed");
    expectEOF(pair.client);
    require(tcpSocketPeerHasWriteShutdown(pair.client), "peer write-only shutdown was not recognized");
    require(shutdown(pair.server, SHUT_RD) == 0, "peer read shutdown failed");
    require(! tcpSocketPeerHasWriteShutdown(pair.client), "peer read shutdown was ignored");
    close(pair.server);
    pair.server = -1;
    require(! tcpSocketPeerHasWriteShutdown(pair.client), "closed peer was reported as receive-enabled");
    closePair(pair);

    pair = openPair(server_family, client_family, mapped);
    close(pair.server);
    pair.server = -1;
    expectEOF(pair.client);
    require(! tcpSocketPeerHasWriteShutdown(pair.client), "full close was mistaken for write-only shutdown");
    closePair(pair);
}

static void testDiagnosticFailures(void)
{
    tcp_pair_t pair = openPair(AF_INET, AF_INET, false);
    require(shutdown(pair.server, SHUT_WR) == 0, "peer write shutdown failed");
    expectEOF(pair.client);
    require(tcpSocketPeerHasWriteShutdown(pair.client), "failure fixture did not start half-closed");

    for (diagnostic_fault_t fault = DIAG_FAULT_SOCKET_DENIED; fault <= DIAG_FAULT_MALFORMED_REPLY; ++fault)
    {
        diagnostic_fault = fault;
        diagnostic_fd    = -1;
        fault_injected   = false;
        require(! tcpSocketPeerHasWriteShutdown(pair.client), "unavailable or invalid diagnostics reported half-close");
        require(fault_injected, "diagnostic failure path was not exercised");
        diagnostic_fault = DIAG_FAULT_NONE;
        require(tcpSocketPeerHasWriteShutdown(pair.client), "diagnostic failure prevented a later successful query");
    }
    closePair(pair);
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        const char *source = getenv("WATERWALL_TEST_SOURCE_DIR");
        require(source != NULL, "run through waterwall.tcp_socket_diag_unit");
        char wrapper[4096];
        int  written = snprintf(wrapper, sizeof(wrapper), "%s/tests/run_in_network_namespace.sh", source);
        require(written > 0 && (size_t) written < sizeof(wrapper), "namespace wrapper path overflow");
        execl("/bin/bash", "bash", wrapper, argv[0], "--isolated", (char *) NULL);
        require(false, "namespace wrapper exec failed");
    }
    require(argc == 2 && strcmp(argv[1], "--isolated") == 0, "unexpected test arguments");
    testCaseSet("tcp_socket_diag_test");
    require(! tcpSocketPeerHasWriteShutdown(-1), "invalid descriptor was accepted");
    testShutdown(AF_INET, AF_INET, false);
    testShutdown(AF_INET6, AF_INET6, false);
    testShutdown(AF_INET6, AF_INET, true);
    testShutdown(AF_INET, AF_INET6, true);
    testDiagnosticFailures();
    puts("tcp_socket_diag_test: all cases passed");
    return 0;
}
