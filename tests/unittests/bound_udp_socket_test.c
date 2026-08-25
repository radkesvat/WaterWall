#include "bound_udp_socket.h"
#include "tunnel_orderly_shutdown_harness.h"

#include <limits.h>

#if defined(OS_LINUX)
#include <errno.h>
#include <fcntl.h>

typedef struct bound_udp_socket_option_probe_s
{
    int      fail_option;
    int      last_failed_fd;
    uint32_t send_calls;
    uint32_t recv_calls;
    int      last_send_len;
    int      last_recv_len;
} bound_udp_socket_option_probe_t;

static bound_udp_socket_option_probe_t g_option_probe;

int __real_setsockopt(int sockfd, int level, int option_name, const void *option_value, socklen_t option_len);
int __wrap_setsockopt(int sockfd, int level, int option_name, const void *option_value, socklen_t option_len);

int __wrap_setsockopt(int sockfd, int level, int option_name, const void *option_value, socklen_t option_len)
{
    if (level == SOL_SOCKET && (option_name == SO_SNDBUF || option_name == SO_RCVBUF))
    {
        int value = 0;
        if (option_value != NULL && option_len == sizeof(value))
        {
            memoryCopy(&value, option_value, sizeof(value));
        }

        if (option_name == SO_SNDBUF)
        {
            ++g_option_probe.send_calls;
            g_option_probe.last_send_len = value;
        }
        else
        {
            ++g_option_probe.recv_calls;
            g_option_probe.last_recv_len = value;
        }

        if (g_option_probe.fail_option == option_name)
        {
            g_option_probe.last_failed_fd = sockfd;
            errno                         = ENOBUFS;
            return -1;
        }
    }

    return __real_setsockopt(sockfd, level, option_name, option_value, option_len);
}

static void resetOptionProbe(void)
{
    g_option_probe = (bound_udp_socket_option_probe_t) {.last_failed_fd = -1};
}
#endif

static void testBoundUdpSocketIpv4Ephemeral(void)
{
    twfSetCase("bound udp socket ipv4 ephemeral binding and port retrieval");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    bound_udp_config_t cfg = {
        .bind_address = "127.0.0.1",
        .port         = 0,
        .bind_policy  = kBoundUdpBindPolicyExclusive,
    };

    wio_t *wio = boundUdpSocketCreate(env.loop, &cfg);
    twfRequire(wio != NULL, "boundUdpSocketCreate failed for 127.0.0.1:0");
    twfRequire(wioGetFD(wio) >= 0, "wio fd must be valid");
    uint16_t port = sockaddrPort(wioGetLocaladdrU(wio));
    twfRequire(port > 0, "bound port must be > 0");

    ip_addr_t local_ip = {0};
    twfRequire(sockaddrToNormalizedIpAddr(wioGetLocaladdrU(wio), &local_ip), "failed to normalize local IP");
    twfRequire(local_ip.type == IPADDR_TYPE_V4, "local_ip must be IPv4");

    wioClose(wio);
    twfWorkerEnvTeardown(&env);
}

static void testBoundUdpSocketWildcard(void)
{
    twfSetCase("bound udp socket wildcard ephemeral binding");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    bound_udp_config_t cfg = {
        .bind_address = "0.0.0.0",
        .port         = 0,
        .bind_policy  = kBoundUdpBindPolicyExclusive,
    };

    wio_t *wio = boundUdpSocketCreate(env.loop, &cfg);
    twfRequire(wio != NULL, "boundUdpSocketCreate failed for 0.0.0.0:0");
    twfRequire(wioGetFD(wio) >= 0, "wio fd must be valid");
    uint16_t port = sockaddrPort(wioGetLocaladdrU(wio));
    twfRequire(port > 0, "bound port must be > 0");

    wioClose(wio);
    twfWorkerEnvTeardown(&env);
}

static void testBoundUdpSocketExclusiveBindCannotBeShared(void)
{
    twfSetCase("bound udp socket exclusive policy rejects a second bind to the same endpoint");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    bound_udp_config_t cfg = {
        .bind_address = "127.0.0.1",
        .port         = 0,
        .bind_policy  = kBoundUdpBindPolicyExclusive,
    };

    wio_t *first = boundUdpSocketCreate(env.loop, &cfg);
    twfRequire(first != NULL, "first exclusive UDP bind failed");
    cfg.port = sockaddrPort(wioGetLocaladdrU(first));
    twfRequire(cfg.port != 0, "first exclusive UDP bind did not receive a port");
    twfRequire(boundUdpSocketCreate(env.loop, &cfg) == NULL,
               "second exclusive UDP bind unexpectedly shared the endpoint");

    wioClose(first);
    twfWorkerEnvTeardown(&env);
}

static void testBoundUdpSocketIpv6Ephemeral(void)
{
    twfSetCase("bound udp socket ipv6 loopback ephemeral binding");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    bound_udp_config_t cfg = {
        .bind_address = "::1",
        .port         = 0,
        .bind_policy  = kBoundUdpBindPolicyExclusive,
    };

    wio_t *wio = boundUdpSocketCreate(env.loop, &cfg);
    if (wio != NULL)
    {
        twfRequire(wioGetFD(wio) >= 0, "wio fd must be valid");
        uint16_t port = sockaddrPort(wioGetLocaladdrU(wio));
        twfRequire(port > 0, "bound port must be > 0");
        ip_addr_t local_ip = {0};
        twfRequire(sockaddrToNormalizedIpAddr(wioGetLocaladdrU(wio), &local_ip), "failed to normalize local IP");
        twfRequire(local_ip.type == IPADDR_TYPE_V6, "local_ip must be IPv6");
        wioClose(wio);
    }

    twfWorkerEnvTeardown(&env);
}

static void testBoundUdpSocketNullInputs(void)
{
    twfSetCase("bound udp socket null input validation");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    twfRequire(boundUdpSocketCreate(NULL, NULL) == NULL, "NULL loop and config must fail");
    twfRequire(boundUdpSocketCreate(env.loop, NULL) == NULL, "NULL config must fail");

    twfWorkerEnvTeardown(&env);
}

static void testBoundUdpSocketRejectsUnrepresentableBufferRequest(void)
{
    twfSetCase("bound udp socket rejects a buffer option larger than int");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    const bound_udp_config_t cfg = {
        .bind_address     = "127.0.0.1",
        .port             = 0,
        .send_buffer_size = (uint32_t) INT_MAX + 1U,
        .bind_policy      = kBoundUdpBindPolicyExclusive,
    };
    twfRequire(boundUdpSocketCreate(env.loop, &cfg) == NULL,
               "unrepresentable UDP send buffer request must fail before socket publication");
    twfWorkerEnvTeardown(&env);
}

#if defined(OS_LINUX)
static void testBoundUdpSocketBufferOptionSemantics(void)
{
    twfSetCase("bound udp socket preserves zero buffer defaults and applies explicit requests");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    resetOptionProbe();
    bound_udp_config_t cfg = {
        .bind_address = "127.0.0.1",
        .port         = 0,
        .bind_policy  = kBoundUdpBindPolicyExclusive,
    };
    wio_t *wio = boundUdpSocketCreate(env.loop, &cfg);
    twfRequire(wio != NULL, "zero buffer request failed to bind a UDP socket");
    twfRequireEqualU32(
        g_option_probe.send_calls, 0, "zero send buffer request must leave the kernel default unchanged");
    twfRequireEqualU32(
        g_option_probe.recv_calls, 0, "zero receive buffer request must leave the kernel default unchanged");
    wioClose(wio);

    resetOptionProbe();
    cfg.send_buffer_size = kDefaultLargeSocketBufferSize;
    cfg.recv_buffer_size = kDefaultLargeSocketBufferSize;
    wio                  = boundUdpSocketCreate(env.loop, &cfg);
    twfRequire(wio != NULL, "WaterWall default large buffer request failed to bind a UDP socket");
    twfRequireEqualU32(g_option_probe.send_calls, 1, "default true send buffer request was not applied once");
    twfRequireEqualU32(g_option_probe.recv_calls, 1, "default true receive buffer request was not applied once");
    twfRequireEqualU32((uint32_t) g_option_probe.last_send_len,
                       kDefaultLargeSocketBufferSize,
                       "default true send buffer request used the wrong value");
    twfRequireEqualU32((uint32_t) g_option_probe.last_recv_len,
                       kDefaultLargeSocketBufferSize,
                       "default true receive buffer request used the wrong value");
    wioClose(wio);

    resetOptionProbe();
    cfg.send_buffer_size = 32768;
    cfg.recv_buffer_size = 65536;
    wio                  = boundUdpSocketCreate(env.loop, &cfg);
    twfRequire(wio != NULL, "explicit positive buffer request failed to bind a UDP socket");
    twfRequireEqualU32((uint32_t) g_option_probe.last_send_len, 32768, "explicit send buffer request changed");
    twfRequireEqualU32((uint32_t) g_option_probe.last_recv_len, 65536, "explicit receive buffer request changed");
    wioClose(wio);

    twfWorkerEnvTeardown(&env);
}

static void testBoundUdpSocketBufferOptionFailureClosesUnpublishedFd(void)
{
    twfSetCase("bound udp socket option failure closes an unpublished fd");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 0);

    bound_udp_config_t cfg = {
        .bind_address     = "127.0.0.1",
        .port             = 0,
        .send_buffer_size = 4096,
        .recv_buffer_size = 4096,
        .bind_policy      = kBoundUdpBindPolicyExclusive,
    };
    const uint32_t wios_before = masterpoolGetCheckedOut(env.wios_master);

    resetOptionProbe();
    g_option_probe.fail_option = SO_SNDBUF;
    twfRequire(boundUdpSocketCreate(env.loop, &cfg) == NULL, "send buffer option failure must fail UDP publication");
    twfRequire(g_option_probe.last_failed_fd >= 0, "send buffer failure did not observe a socket fd");
    twfRequire(fcntl(g_option_probe.last_failed_fd, F_GETFD) == -1 && errno == EBADF,
               "send buffer failure leaked an unpublished socket fd");
    twfRequireEqualU32(
        masterpoolGetCheckedOut(env.wios_master), wios_before, "send buffer failure published a WIO before cleanup");

    resetOptionProbe();
    g_option_probe.fail_option = SO_RCVBUF;
    twfRequire(boundUdpSocketCreate(env.loop, &cfg) == NULL, "receive buffer option failure must fail UDP publication");
    twfRequire(g_option_probe.last_failed_fd >= 0, "receive buffer failure did not observe a socket fd");
    twfRequire(fcntl(g_option_probe.last_failed_fd, F_GETFD) == -1 && errno == EBADF,
               "receive buffer failure leaked an unpublished socket fd");
    twfRequireEqualU32(
        masterpoolGetCheckedOut(env.wios_master), wios_before, "receive buffer failure published a WIO before cleanup");

    twfWorkerEnvTeardown(&env);
}
#endif

int main(void)
{
    testBoundUdpSocketIpv4Ephemeral();
    testBoundUdpSocketWildcard();
    testBoundUdpSocketExclusiveBindCannotBeShared();
    testBoundUdpSocketIpv6Ephemeral();
    testBoundUdpSocketNullInputs();
    testBoundUdpSocketRejectsUnrepresentableBufferRequest();
#if defined(OS_LINUX)
    testBoundUdpSocketBufferOptionSemantics();
    testBoundUdpSocketBufferOptionFailureClosesUnpublishedFd();
#endif

    puts("bound_udp_socket_test: all cases passed");
    return 0;
}
