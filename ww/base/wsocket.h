#ifndef WW_SOCKET_H_
#define WW_SOCKET_H_

/**
 * @file wsocket.h
 * @brief Cross-platform socket helpers for address handling and connection setup.
 *
 * Includes wrappers for resolving hostnames, building socket addresses,
 * creating/listening/connecting sockets, and common socket options.
 */

#include "wlibc.h"

#ifdef ENABLE_UDS
#ifdef OS_WIN
#include <afunix.h> // import struct sockaddr_un
#else
#include <sys/un.h> // import struct sockaddr_un
#endif
#endif

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define LOCALHOST "127.0.0.1"
#define ANYADDR   "0.0.0.0"

/**
 * @brief Get the last socket error code from the current thread.
 *
 * @return Platform-specific socket error number.
 */
WW_INLINE int socketERRNO(void)
{
#ifdef OS_WIN
    return WSAGetLastError();
#else
    return errno;
#endif
}
/**
 * @brief Convert a socket error code to a readable string.
 *
 * @param err Error code (positive or negative).
 * @return Pointer to an error string.
 */
WW_EXPORT const char *socketStrError(int err);

#ifdef OS_WIN

typedef SOCKET wsocket_t;
typedef int    socklen_t;

/**
 * @brief Initialize WinSock once per process.
 */
void WSAInit(void);
/**
 * @brief Deinitialize WinSock when no longer needed.
 */
void WSADeinit(void);

/**
 * @brief Set a socket descriptor to blocking mode.
 *
 * @param sockfd Socket descriptor.
 * @return `0` on success, otherwise socket error.
 */
WW_INLINE int blocking(int sockfd)
{
    unsigned long nb = 0;
    return ioctlsocket(sockfd, (long) FIONBIO, &nb);
}

/**
 * @brief Set a socket descriptor to non-blocking mode.
 *
 * @param sockfd Socket descriptor.
 * @return `0` on success, otherwise socket error.
 */
WW_INLINE int nonBlocking(int sockfd)
{
    unsigned long nb = 1;
    return ioctlsocket(sockfd, (long) FIONBIO, &nb);
}

#undef EAGAIN
#define EAGAIN WSAEWOULDBLOCK

#undef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS

#undef EINTR
#define EINTR WSAEINTR

#undef ENOTSOCK
#define ENOTSOCK WSAENOTSOCK

#undef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE

#else

typedef int wsocket_t;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

/**
 * @brief Set a socket descriptor to blocking mode.
 *
 * @param s Socket descriptor.
 * @return `0` on success, otherwise `-1`.
 */
WW_INLINE int blocking(int s)
{
    return fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
}

/**
 * @brief Set a socket descriptor to non-blocking mode.
 *
 * @param s Socket descriptor.
 * @return `0` on success, otherwise `-1`.
 */
WW_INLINE int nonBlocking(int s)
{
    return fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
}

/**
 * @brief Close a socket descriptor using POSIX close.
 *
 * @param sockfd Socket descriptor.
 * @return `0` on success, otherwise `-1`.
 */
WW_INLINE int closesocket(int sockfd)
{
    return close(sockfd);
}

#endif

#ifndef SAFE_CLOSESOCKET
#define SAFE_CLOSESOCKET(fd)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((fd) >= 0)                                                                                                 \
        {                                                                                                              \
            closesocket(fd);                                                                                           \
            (fd) = -1;                                                                                                 \
        }                                                                                                              \
    } while (0)
#endif

//-----------------------------sockaddr_u----------------------------------------------
typedef union {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
#ifdef ENABLE_UDS
    struct sockaddr_un sun;
#endif
} sockaddr_u;


/**
 * @brief Resolve a host string into a socket address.
 *
 * @param host Hostname or IP string.
 * @param addr Output socket address.
 * @return `0` on success, otherwise resolver error code.
 */
WW_EXPORT int resolveAddr(const char *host, sockaddr_u *addr);

/**
 * @brief Convert socket address IP part to text.
 *
 * @param addr Input socket address.
 * @param ip Output buffer for the IP string.
 * @param len Size of `ip` buffer.
 * @return Pointer to `ip`.
 */
WW_EXPORT const char *sockaddrIp(sockaddr_u *addr, char *ip, int len);
/**
 * @brief Extract port from a socket address.
 *
 * @param addr Input socket address.
 * @return Host-order port number.
 */
WW_EXPORT uint16_t    sockaddrPort(sockaddr_u *addr);
/**
 * @brief Set address family and IP from host string.
 *
 * @param addr Output socket address.
 * @param host Hostname/IP; empty means `INADDR_ANY`.
 * @return `0` on success, otherwise resolver error code.
 */
WW_EXPORT int         sockaddrSetIpAddress(sockaddr_u *addr, const char *host);
/**
 * @brief Set port on IPv4/IPv6 socket address.
 *
 * @param addr Socket address to update.
 * @param port Host-order port.
 */
WW_EXPORT void        sockaddrSetPort(sockaddr_u *addr, int port);
/**
 * @brief Set both host/IP and port on a socket address.
 *
 * @param addr Output socket address.
 * @param host Hostname/IP/path (UDS when enabled and `port < 0`).
 * @param port Host-order port.
 * @return `0` on success, otherwise resolver error code.
 */
WW_EXPORT int         sockaddrSetIpAddressPort(sockaddr_u *addr, const char *host, int port);
/**
 * @brief Get structure length suitable for `bind`/`connect`.
 *
 * @param addr Socket address.
 * @return Size in bytes of the concrete address structure.
 */
WW_EXPORT socklen_t   sockaddrLen(sockaddr_u *addr);
/**
 * @brief Render full socket address to string.
 *
 * @param addr Socket address.
 * @param buf Output buffer.
 * @param len Output buffer size.
 * @return Pointer to `buf`.
 */
WW_EXPORT const char *sockaddrStr(sockaddr_u *addr, char *buf, int len);

// #define INET_ADDRSTRLEN   16
// #define INET6_ADDRSTRLEN  46
#ifdef ENABLE_UDS
#define SOCKADDR_STRLEN sizeof(((struct sockaddr_un *) (NULL))->sun_path)
/**
 * @brief Fill a Unix domain socket address path.
 *
 * @param addr Output socket address.
 * @param path Filesystem/abstract socket path.
 */
WW_INLINE void sockaddr_set_path(sockaddr_u *addr, const char *path)
{
    addr->sa.sa_family = AF_UNIX;
#if defined(OS_UNIX)
    strncpy(addr->sun.sun_path, path, sizeof(addr->sun.sun_path) - 1);
#else
    strncpy_s(addr->sun.sun_path, sizeof(addr->sun.sun_path), path, sizeof(addr->sun.sun_path) - 1);
#endif
}
#else
#define SOCKADDR_STRLEN 64 // ipv4:port | [ipv6]:port
#endif

enum
{
    kDefaultLargeSocketBufferSize = 4 * 1024 * 1024
};

/**
 * @brief Print a socket address to stdout.
 *
 * @param addr Socket address to print.
 */
WW_INLINE void sockaddrPrint(sockaddr_u *addr)
{
    char buf[SOCKADDR_STRLEN] = {0};
    sockaddrStr(addr, buf, sizeof(buf));
    puts(buf);
}

#define SOCKADDR_LEN(addr)      sockaddrLen((sockaddr_u *) addr)
#define SOCKADDR_STR(addr, buf) sockaddrStr((sockaddr_u *) addr, buf, sizeof(buf))
#define SOCKADDR_PRINT(addr)    sockaddrPrint((sockaddr_u *) addr)
//=====================================================================================

/**
 * @brief Create and bind a socket.
 *
 * @param port Port to bind.
 * @param host Host/IP to bind (defaults to `ANYADDR`).
 * @param type Socket type (e.g. `SOCK_STREAM`, `SOCK_DGRAM`).
 * @return Socket fd on success, negative error on failure.
 */
WW_EXPORT int Bind(int port, const char *host DEFAULT(ANYADDR), int type DEFAULT(SOCK_STREAM));

/**
 * @brief Create a TCP listening socket.
 *
 * @param port Port to listen on.
 * @param host Host/IP to bind.
 * @return Listening socket fd on success, negative error on failure.
 */
WW_EXPORT int wwListen(int port, const char *host DEFAULT(ANYADDR));

/**
 * @brief Create and connect a TCP socket.
 *
 * @param host Remote host/IP.
 * @param port Remote port.
 * @param nonblock Non-zero to keep socket non-blocking.
 * @return Connected fd on success, negative error on failure.
 */
WW_EXPORT int wwConnect(const char *host, int port, int nonblock DEFAULT(0));
/**
 * @brief Connect in non-blocking mode.
 *
 * @param host Remote host/IP.
 * @param port Remote port.
 * @return Socket fd or negative error.
 */
WW_EXPORT int ConnectNonblock(const char *host, int port);
#define DEFAULT_CONNECT_TIMEOUT 10000 // ms
/**
 * @brief Connect with timeout, then restore blocking mode.
 *
 * @param host Remote host/IP.
 * @param port Remote port.
 * @param ms Timeout in milliseconds.
 * @return Connected fd on success, negative error on timeout/failure.
 */
WW_EXPORT int ConnectTimeout(const char *host, int port, int ms DEFAULT(DEFAULT_CONNECT_TIMEOUT));

#ifdef ENABLE_UDS
/**
 * @brief Create and bind a Unix domain socket.
 *
 * @param path Unix socket path.
 * @param type Socket type.
 * @return Socket fd or negative error.
 */
WW_EXPORT int BindUnix(const char *path, int type DEFAULT(SOCK_STREAM));
/**
 * @brief Create a Unix domain listening socket.
 *
 * @param path Unix socket path.
 * @return Listening socket fd or negative error.
 */
WW_EXPORT int wwListenUnix(const char *path);
/**
 * @brief Connect to a Unix domain socket.
 *
 * @param path Unix socket path.
 * @param nonblock Non-zero for non-blocking mode.
 * @return Connected fd or negative error.
 */
WW_EXPORT int ConnectUnix(const char *path, int nonblock DEFAULT(0));
/**
 * @brief Non-blocking Unix socket connect helper.
 *
 * @param path Unix socket path.
 * @return Socket fd or negative error.
 */
WW_EXPORT int ConnectUnixNonblock(const char *path);
/**
 * @brief Unix socket connect with timeout.
 *
 * @param path Unix socket path.
 * @param ms Timeout in milliseconds.
 * @return Connected fd or negative error.
 */
WW_EXPORT int ConnectUnixTimeout(const char *path, int ms DEFAULT(DEFAULT_CONNECT_TIMEOUT));
#endif

/**
 * @brief Create a connected socket pair.
 *
 * @param family Address family.
 * @param type Socket type.
 * @param protocol Protocol number.
 * @param sv Output pair of connected socket fds.
 * @return `0` on success, `-1` on failure.
 */
WW_EXPORT int createSocketPair(int family, int type, int protocol, int sv[2]);

/**
 * @brief Enable or disable `TCP_NODELAY`.
 *
 * @param sockfd Socket descriptor.
 * @param on Non-zero to disable Nagle's algorithm.
 * @return `setsockopt` result.
 */
WW_INLINE int tcpNoDelay(int sockfd, int on DEFAULT(1))
{
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &on, sizeof(int));
}

/**
 * @brief Enable TCP packet coalescing (`TCP_NOPUSH`/`TCP_CORK` where available).
 *
 * @param sockfd Socket descriptor.
 * @param on Non-zero to enable option.
 * @return `setsockopt` result or `0` when unsupported.
 */
WW_INLINE int tcpNoPush(int sockfd, int on DEFAULT(1))
{
#ifdef TCP_NOPUSH
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NOPUSH, (const char *) &on, sizeof(int));
#elif defined(TCP_CORK)
    return setsockopt(sockfd, IPPROTO_TCP, TCP_CORK, (const char *) &on, sizeof(int));
#else
    discard sockfd;
    discard on;
    return 0;
#endif
}

/**
 * @brief Configure TCP keepalive.
 *
 * @param sockfd Socket descriptor.
 * @param on Non-zero to enable keepalive.
 * @param delay Initial idle delay in seconds.
 * @return `setsockopt` result (or socket error code).
 */
WW_INLINE int tcpKeepAlive(int sockfd, int on DEFAULT(1), int delay DEFAULT(60))
{
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (const char *) &on, sizeof(int)) != 0)
    {
        return socketERRNO();
    }

#ifdef TCP_KEEPALIVE
    return setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE, (const char *) &delay, sizeof(int));
#elif defined(TCP_KEEPIDLE)
    // TCP_KEEPIDLE     => tcp_keepalive_time
    // TCP_KEEPCNT      => tcp_keepalive_probes
    // TCP_KEEPINTVL    => tcp_keepalive_intvl
    return setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, (const char *) &delay, sizeof(int));
#else
    discard sockfd;
    discard delay;

    return 0;
#endif
}

/**
 * @brief Enable or disable UDP broadcast.
 *
 * @param sockfd Socket descriptor.
 * @param on Non-zero to enable broadcast.
 * @return `setsockopt` result.
 */
WW_INLINE int udpBroadCast(int sockfd, int on DEFAULT(1))
{
    return setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char *) &on, sizeof(int));
}

/**
 * @brief Check whether this build exposes a device-binding socket option.
 *
 * @return true when `socketOptionBindToDevice()` can restrict a socket by interface name.
 */
WW_INLINE bool socketOptionBindToDeviceSupported(void)
{
#if defined(OS_LINUX) && defined(SO_BINDTODEVICE)
    return true;
#else
    return false;
#endif
}

/**
 * @brief Bind a socket to a network device when the platform supports it.
 *
 * @param sockfd Socket descriptor.
 * @param interface_name Interface/device name, for example `eth0`.
 * @return `setsockopt` result, or `0` on platforms without this option.
 */
WW_INLINE int socketOptionBindToDevice(int sockfd, const char *interface_name)
{
    if (interface_name == NULL || interface_name[0] == '\0')
    {
        return 0;
    }

#if defined(OS_LINUX) && defined(SO_BINDTODEVICE)
    return setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_name,
                      (socklen_t) (stringLength(interface_name) + 1));
#else
    discard sockfd;
    discard interface_name;
    return 0;
#endif
}

/**
 * @brief Apply a firewall mark to a socket when the platform supports it.
 *
 * @param sockfd Socket descriptor.
 * @param fwmark Mark value to apply.
 * @return `setsockopt` result, or `0` on platforms without this option.
 */
WW_INLINE int socketOptionSetFwMark(int sockfd, int fwmark)
{
#if defined(OS_LINUX) && defined(SO_MARK)
    return setsockopt(sockfd, SOL_SOCKET, SO_MARK, (const char *) &fwmark, sizeof(fwmark));
#else
    discard sockfd;
    discard fwmark;
    return 0;
#endif
}

/**
 * @brief Read a socket's firewall mark (SO_MARK) when the platform supports it.
 *
 * Reading SO_MARK is unprivileged (only setting requires CAP_NET_ADMIN), so this can be used to decide whether
 * a mark change is actually needed before calling the privileged setter.
 *
 * @param sockfd Socket descriptor.
 * @param out_fwmark Receives the current mark on success.
 * @return `true` on success, `false` when unsupported or the read failed.
 */
WW_INLINE bool socketOptionGetFwMark(int sockfd, int *out_fwmark)
{
#if defined(OS_LINUX) && defined(SO_MARK)
    int       value = 0;
    socklen_t len   = sizeof(value);
    if (getsockopt(sockfd, SOL_SOCKET, SO_MARK, (char *) &value, &len) != 0)
    {
        return false;
    }
    *out_fwmark = value;
    return true;
#else
    discard sockfd;
    discard out_fwmark;
    return false;
#endif
}

/**
 * @brief Restrict an IPv6 socket to IPv6 only.
 *
 * @param sockfd Socket descriptor.
 * @param on Non-zero to enable IPv6-only mode.
 * @return `setsockopt` result or `0` when unsupported.
 */
WW_INLINE int ipV6Only(int sockfd, int on DEFAULT(1))
{
#ifdef IPV6_V6ONLY
    return setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *) &on, sizeof(int));
#else
    return 0;
#endif
}

/**
 * @brief Set send timeout.
 *
 * @param sockfd Socket descriptor.
 * @param timeout Timeout in milliseconds.
 * @return `setsockopt` result.
 */
WW_INLINE int socketOptionSNDTIME(int sockfd, int timeout)
{
#ifdef OS_WIN
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout, sizeof(int));
#else
    struct timeval tv = {timeout / 1000, (timeout % 1000) * 1000};
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

/**
 * @brief Set receive timeout.
 *
 * @param sockfd Socket descriptor.
 * @param timeout Timeout in milliseconds.
 * @return `setsockopt` result.
 */
WW_INLINE int socketOptionRecvTime(int sockfd, int timeout)
{
#ifdef OS_WIN
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(int));
#else
    struct timeval tv = {timeout / 1000, (timeout % 1000) * 1000};
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

/**
 * @brief Set socket send buffer size.
 *
 * @param sockfd Socket descriptor.
 * @param len Buffer size in bytes.
 * @return `setsockopt` result.
 */
WW_INLINE int socketOptionSendBuf(int sockfd, int len)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *) &len, sizeof(int));
}

/**
 * @brief Set socket receive buffer size.
 *
 * @param sockfd Socket descriptor.
 * @param len Buffer size in bytes.
 * @return `setsockopt` result.
 */
WW_INLINE int socketOptionRecvBuf(int sockfd, int len)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *) &len, sizeof(int));
}

WW_INLINE bool socketOptionApplySendBuffer(int sockfd, int len)
{
    return len <= 0 || socketOptionSendBuf(sockfd, len) == 0;
}

WW_INLINE bool socketOptionApplyRecvBuffer(int sockfd, int len)
{
    return len <= 0 || socketOptionRecvBuf(sockfd, len) == 0;
}

/**
 * @brief Enable/disable `SO_REUSEADDR`.
 *
 * @param sockfd Socket descriptor.
 * @param on Non-zero to enable.
 * @return `setsockopt` result or `0` when unsupported.
 */
WW_INLINE int socketOptionReuseAddr(int sockfd, int on DEFAULT(1))
{
#ifdef SO_REUSEADDR
    // NOTE: SO_REUSEADDR allow to reuse sockaddr of TIME_WAIT status
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(int));
#else
    return 0;
#endif
}

/**
 * @brief Enable/disable `SO_REUSEPORT`.
 *
 * @param sockfd Socket descriptor.
 * @param on Non-zero to enable.
 * @return `setsockopt` result or `0` when unsupported.
 */
WW_INLINE int socketOptionReusePort(int sockfd, int on DEFAULT(1))
{
#ifdef SO_REUSEPORT
    // NOTE: SO_REUSEPORT allow multiple sockets to bind same port
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char *) &on, sizeof(int));
#else
    discard sockfd;
    discard on;
    return 0;
#endif
}

/**
 * @brief Configure `SO_LINGER`.
 *
 * @param sockfd Socket descriptor.
 * @param timeout Linger seconds; negative disables linger.
 * @return `setsockopt` result or `0` when unsupported.
 */
WW_INLINE int socketOptionLinger(int sockfd, int timeout DEFAULT(1))
{
#ifdef SO_LINGER
    struct linger linger;
    if (timeout >= 0)
    {
        linger.l_onoff  = 1;
        linger.l_linger = (unsigned short) timeout;
    }
    else
    {
        linger.l_onoff  = 0;
        linger.l_linger = 0;
    }
    // NOTE: SO_LINGER change the default behavior of close, send RST, avoid TIME_WAIT
    return setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char *) &linger, sizeof(linger));
#else
    return 0;
#endif
}

/**
 * @brief Copy IP bytes from one socket address to another.
 *
 * @param dest Destination address.
 * @param source Source address.
 */
static inline void sockaddrCopy(sockaddr_u *restrict dest, const sockaddr_u *restrict source)
{
    if (source->sa.sa_family == AF_INET)
    {
        memoryCopy(&(dest->sin.sin_addr.s_addr), &(source->sin.sin_addr.s_addr), sizeof(source->sin.sin_addr.s_addr));
        return;
    }
    memoryCopy(&(dest->sin6.sin6_addr.s6_addr), &(source->sin6.sin6_addr.s6_addr),
               sizeof(source->sin6.sin6_addr.s6_addr));
}

/**
 * @brief Compare two IPv4 socket addresses by IP.
 *
 * @param addr1 First address.
 * @param addr2 Second address.
 * @return `true` when IP addresses are equal.
 */
static inline bool sockaddrCmpIPV4(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2)
{
    return (addr1->sin.sin_addr.s_addr == addr2->sin.sin_addr.s_addr);
}

/**
 * @brief Compare two IPv6 socket addresses by IP/flow/scope.
 *
 * @param addr1 First address.
 * @param addr2 Second address.
 * @return `true` when all compared IPv6 fields are equal.
 */
static inline bool sockaddrCmpIPV6(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2)
{
    int r = memcmp(addr1->sin6.sin6_addr.s6_addr, addr2->sin6.sin6_addr.s6_addr, sizeof(addr1->sin6.sin6_addr.s6_addr));
    if (r != 0)
    {
        return false;
    }
    if (addr1->sin6.sin6_flowinfo != addr2->sin6.sin6_flowinfo)
    {
        return false;
    }
    if (addr1->sin6.sin6_scope_id != addr2->sin6.sin6_scope_id)
    {
        return false;
    }
    return true;
}

/**
 * @brief Compare two socket addresses by family and IP fields.
 *
 * @param addr1 First address.
 * @param addr2 Second address.
 * @return `true` when addresses match for supported families.
 */
static inline bool sockaddrCmpIP(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2)
{

    if (addr1->sa.sa_family != addr2->sa.sa_family)
    {
        return false;
    }
    if (addr1->sa.sa_family == AF_INET)
    {
        return sockaddrCmpIPV4(addr1, addr2);
    }

    if (addr1->sa.sa_family == AF_INET6)
    {
        return sockaddrCmpIPV6(addr1, addr2);
    }

    assert(! "unknown sa_family");

    return false;
}

/**
 * @brief Compute hash from an IP address without port.
 *
 * @param addr IP address.
 * @return Hash value.
 */
static inline hash_t ipaddrCalcHashNoPort(const ip_addr_t addr)
{
    hash_t result;
    if (addr.type == IPADDR_TYPE_V4)
    {
        result = calcHashBytes(&(addr.u_addr.ip4), sizeof(addr.u_addr.ip4.addr));
    }
    else if (addr.type == IPADDR_TYPE_V6)
    {
        result = calcHashBytes(&(addr.u_addr.ip6), sizeof(addr.u_addr.ip6.addr));
    }
    else
    {
        assert(false);
        printError("ipaddrCalcHashNoPort");
        terminateProgram(1);
    }

    return result;
}

/**
 * @brief Compute hash from socket address including port.
 *
 * @param saddr Socket address.
 * @return Hash value.
 */
static inline hash_t sockaddrCalcHashWithPort(const sockaddr_u *saddr)
{
    hash_t result;
    if (saddr->sa.sa_family == AF_INET)
    {
        result = calcHashBytesSeed(&(saddr->sin.sin_addr), sizeof(struct sockaddr_in), saddr->sin.sin_port);
    }
    else if (saddr->sa.sa_family == AF_INET6)
    {
        result = calcHashBytesSeed(&(saddr->sin6.sin6_addr), sizeof(struct sockaddr_in6), saddr->sin6.sin6_port);
    }
    else
    {
        assert(false);
        printError("sockaddrCalcHashWithPort");
        terminateProgram(1);
    }
    return result;
}


/**
 * @brief Parse `ip/prefix` string and derive subnet mask.
 *
 * @param ip_str Input CIDR string.
 * @param ip Output IP address.
 * @param subnet_mask Output subnet mask.
 * @return `4` for IPv4, `6` for IPv6, `ERR_ARG` on failure.
 */
static inline int parseIPWithSubnetMask(const char *ip_str, ip_addr_t *ip, ip_addr_t *subnet_mask)
{
    char ip_part[40];
    int  prefix_len = 0;

    if (sscanf(ip_str, "%39[^/]/%d", ip_part, &prefix_len) != 2)
    {
        return ERR_ARG;
    }

    if (ipaddr_aton(ip_part, ip))
    {
        if (prefix_len < 0 || prefix_len > 32)
        {
            return ERR_ARG;
        }

        subnet_mask->type = IPADDR_TYPE_V4;
        // Calculate the subnet mask for IPv4
        u32_t subnet_mask_value = (prefix_len == 0) ? 0U : (0xFFFFFFFFU << (32 - prefix_len));
        IP4_ADDR(&subnet_mask->u_addr.ip4, (subnet_mask_value >> 24) & 0xFF, (subnet_mask_value >> 16) & 0xFF,
                 (subnet_mask_value >> 8) & 0xFF, subnet_mask_value & 0xFF);

        return 4;
    }

    ip6_addr_t ip6;
    if (ip6addr_aton(ip_part, &ip6))
    {
        if (prefix_len < 0 || prefix_len > 128)
        {
            return ERR_ARG;
        }

        ip->type       = IPADDR_TYPE_V6;
        ip->u_addr.ip6 = ip6;

        subnet_mask->type = IPADDR_TYPE_V6;
        memset(&subnet_mask->u_addr.ip6.addr, 0, sizeof(subnet_mask->u_addr.ip6.addr));

        for (int i = 0; i < prefix_len / 32; i++)
        {
            subnet_mask->u_addr.ip6.addr[i] = 0xFFFFFFFF;
        }
        int remaining_bits = prefix_len % 32;
        if (remaining_bits > 0)
        {
            subnet_mask->u_addr.ip6.addr[prefix_len / 32] = htonl(0xFFFFFFFF << (32 - remaining_bits));
        }

        return 6;
    }

    return ERR_ARG;
}

/**
 * @brief Check whether an IPv4 address is inside a subnet.
 *
 * @param test_addr Address to test.
 * @param base_addr Subnet base address.
 * @param subnet_mask Subnet mask.
 * @return `1` when in range, otherwise `0`.
 */
static inline int checkIPRange4(const ip4_addr_t test_addr, const ip4_addr_t base_addr, const ip4_addr_t subnet_mask)
{
    if ((test_addr.addr & subnet_mask.addr) == (base_addr.addr & subnet_mask.addr))
    {
        return 1;
    }
    return 0;
}

/**
 * @brief Check whether an IPv6 address is inside a subnet.
 *
 * @param test_addr Address to test.
 * @param base_addr Subnet base address.
 * @param subnet_mask Subnet mask.
 * @return `1` when in range, otherwise `0`.
 */
static inline int checkIPRange6(const ip6_addr_t test_addr, const ip6_addr_t base_addr, const ip6_addr_t subnet_mask)
{

    // way 1 , appropriate for all platform
    ip6_addr_t masked_test_addr;
    ip6_addr_t masked_base_addr;

    for (int i = 0; i < 4; i++)
    {
        masked_test_addr.addr[i] = test_addr.addr[i] & subnet_mask.addr[i];
        masked_base_addr.addr[i] = base_addr.addr[i] & subnet_mask.addr[i];
    }

    if (memcmp(&masked_test_addr.addr[0], &masked_base_addr.addr[0], sizeof(struct in6_addr)) == 0)
    {
        return 1;
    }
    return 0;

    // way 2 , maybe dont use it
    // uint64_t *test_addr_p   = (uint64_t *) &(test_addr.s6_addr[0]);
    // uint64_t *base_addr_p   = (uint64_t *) &(base_addr.s6_addr[0]);
    // uint64_t *subnet_mask_p = (uint64_t *) &(subnet_mask.s6_addr[0]);

    // if ((base_addr_p[0] & subnet_mask_p[0]) != test_addr_p[0] || (base_addr_p[1] & subnet_mask_p[1]) !=
    // test_addr_p[1])
    // {
    //     return 0;
    // }
    // return 1;

    // way 3 , appropriate for all platform
    // ip6_addr_net_eq( &test_addr, &base_addr, &subnet_mask);
}

/**
 * @brief Copy sockaddr (IPv4 or IPv6) to ip_addr_t.
 *
 * @param src Source socket address.
 * @param dest Output IP address.
 * @return `true` when conversion is supported and successful.
 */
static inline bool sockaddrToIpAddr(const sockaddr_u *src, ip_addr_t *dest)
{
    assert(src != NULL && dest != NULL);
    if (src->sa.sa_family == AF_INET)
    {
        const struct sockaddr_in *src_in = (const struct sockaddr_in *) src;
        dest->u_addr.ip4.addr            = src_in->sin_addr.s_addr;
        dest->type                       = IPADDR_TYPE_V4;
        return true;
    }

    if (src->sa.sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *src_in6 = (const struct sockaddr_in6 *) src;
        memoryCopy(&dest->u_addr.ip6, &src_in6->sin6_addr.s6_addr, sizeof(dest->u_addr.ip6));
        dest->type = IPADDR_TYPE_V6;
        return true;
    }
    return false;
}

/**
 * @brief Validate `ip:port` string format.
 *
 * @param ipc Input string to validate.
 * @return `true` when the value is valid.
 */
bool verifyIPPort(const char *ipc);
/**
 * @brief Validate CIDR string in `ip/prefix` format.
 *
 * @param ipc Input CIDR string.
 * @return `true` when the value is valid.
 */
bool verifyIPCdir(const char *ipc);

/**
 * @brief Get IPv4 address for a local network interface.
 *
 * @param if_name Interface name.
 * @param ip_buffer Output IPv4 address.
 * @param buflen Size constraint used by platform branches.
 * @return `true` on success, otherwise `false`.
 */
bool getInterfaceIp(const char *if_name, ip4_addr_t *ip_buffer, size_t buflen);
/**
 * @brief Get IPv4 address text for a local network interface.
 *
 * @param if_name Interface name.
 * @param host_buffer Output string buffer.
 * @param host_buffer_len Output buffer size.
 * @return `true` on success, otherwise `false`.
 */
bool getInterfaceIpString(const char *if_name, char *host_buffer, size_t host_buffer_len);



#endif // WW_SOCKET_H_
