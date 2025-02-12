#ifndef WW_SOCKET_H_
#define WW_SOCKET_H_

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

WW_INLINE int socketERRNO(void)
{
#ifdef OS_WIN
    return WSAGetLastError();
#else
    return errno;
#endif
}
WW_EXPORT const char *socketStrError(int err);

#ifdef OS_WIN

typedef SOCKET hsocket_t;
typedef int    socklen_t;

void WSAInit(void);
void WSADeinit(void);

WW_INLINE int blocking(int sockfd)
{
    unsigned long nb = 0;
    return ioctlsocket(sockfd, FIONBIO, &nb);
}

WW_INLINE int nonBlocking(int sockfd)
{
    unsigned long nb = 1;
    return ioctlsocket(sockfd, FIONBIO, &nb);
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

typedef int hsocket_t;

#ifndef SOCKET
#define SOCKET int
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

WW_INLINE int blocking(int s)
{
    return fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
}

WW_INLINE int nonBlocking(int s)
{
    return fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
}

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

WW_EXPORT bool isIPVer4(const char *host);
WW_EXPORT bool isIPVer6(const char *host);
WW_INLINE bool isIpAddr(const char *host)
{
    return isIPVer4(host) || isIPVer6(host);
}

// @param host: domain or ip
// @retval 0:succeed
WW_EXPORT int resolveAddr(const char *host, sockaddr_u *addr);

WW_EXPORT const char *sockaddrIp(sockaddr_u *addr, char *ip, int len);
WW_EXPORT uint16_t    sockaddrPort(sockaddr_u *addr);
WW_EXPORT int         sockaddrSetIp(sockaddr_u *addr, const char *host);
WW_EXPORT void        sockaddrSetPort(sockaddr_u *addr, int port);
WW_EXPORT int         sockaddrSetIpPort(sockaddr_u *addr, const char *host, int port);
WW_EXPORT socklen_t   sockaddrLen(sockaddr_u *addr);
WW_EXPORT const char *sockaddrStr(sockaddr_u *addr, char *buf, int len);

// #define INET_ADDRSTRLEN   16
// #define INET6_ADDRSTRLEN  46
#ifdef ENABLE_UDS
#define SOCKADDR_STRLEN sizeof(((struct sockaddr_un *) (NULL))->sun_path)
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

// socket -> setsockopt -> bind
// @param type: SOCK_STREAM(tcp) SOCK_DGRAM(udp)
// @return sockfd
WW_EXPORT int Bind(int port, const char *host DEFAULT(ANYADDR), int type DEFAULT(SOCK_STREAM));

// Bind -> listen
// @return listenfd
WW_EXPORT int wwListen(int port, const char *host DEFAULT(ANYADDR));

// @return connfd
// resolveAddr -> socket -> nonblocking -> connect
WW_EXPORT int wwConnect(const char *host, int port, int nonblock DEFAULT(0));
// wwConnect(host, port, 1)
WW_EXPORT int ConnectNonblock(const char *host, int port);
// wwConnect(host, port, 1) -> select -> blocking
#define DEFAULT_CONNECT_TIMEOUT 10000 // ms
WW_EXPORT int ConnectTimeout(const char *host, int port, int ms DEFAULT(DEFAULT_CONNECT_TIMEOUT));

#ifdef ENABLE_UDS
WW_EXPORT int BindUnix(const char *path, int type DEFAULT(SOCK_STREAM));
WW_EXPORT int wwListenUnix(const char *path);
WW_EXPORT int ConnectUnix(const char *path, int nonblock DEFAULT(0));
WW_EXPORT int ConnectUnixNonblock(const char *path);
WW_EXPORT int ConnectUnixTimeout(const char *path, int ms DEFAULT(DEFAULT_CONNECT_TIMEOUT));
#endif

// Just implement createSocketPair(AF_INET, SOCK_STREAM, 0, sv);
WW_EXPORT int createSocketPair(int family, int type, int protocol, int sv[2]);

WW_INLINE int tcpNoDelay(int sockfd, int on DEFAULT(1))
{
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &on, sizeof(int));
}

WW_INLINE int tcpNoPush(int sockfd, int on DEFAULT(1))
{
#ifdef TCP_NOPUSH
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NOPUSH, (const char *) &on, sizeof(int));
#elif defined(TCP_CORK)
    return setsockopt(sockfd, IPPROTO_TCP, TCP_CORK, (const char *) &on, sizeof(int));
#else
    (void) sockfd;
    (void) on;
    return 0;
#endif
}

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
    return 0;
#endif
}

WW_INLINE int udpBroadCast(int sockfd, int on DEFAULT(1))
{
    return setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char *) &on, sizeof(int));
}

WW_INLINE int ipV6Only(int sockfd, int on DEFAULT(1))
{
#ifdef IPV6_V6ONLY
    return setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *) &on, sizeof(int));
#else
    return 0;
#endif
}

// send timeout
WW_INLINE int socketOptionSNDTIME(int sockfd, int timeout)
{
#ifdef OS_WIN
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout, sizeof(int));
#else
    struct timeval tv = {timeout / 1000, (timeout % 1000) * 1000};
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// recv timeout
WW_INLINE int socketOptionRecvTime(int sockfd, int timeout)
{
#ifdef OS_WIN
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(int));
#else
    struct timeval tv = {timeout / 1000, (timeout % 1000) * 1000};
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

// send buffer size
WW_INLINE int socketOptionSNDBUF(int sockfd, int len)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *) &len, sizeof(int));
}

// recv buffer size
WW_INLINE int socketOptionRecvBuf(int sockfd, int len)
{
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char *) &len, sizeof(int));
}

WW_INLINE int socketOptionReuseAddr(int sockfd, int on DEFAULT(1))
{
#ifdef SO_REUSEADDR
    // NOTE: SO_REUSEADDR allow to reuse sockaddr of TIME_WAIT status
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(int));
#else
    return 0;
#endif
}

WW_INLINE int socketOptionReusePort(int sockfd, int on DEFAULT(1))
{
#ifdef SO_REUSEPORT
    // NOTE: SO_REUSEPORT allow multiple sockets to bind same port
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char *) &on, sizeof(int));
#else
    (void) sockfd;
    (void) on;
    return 0;
#endif
}

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

static inline void sockaddrCopy(sockaddr_u *restrict dest, const sockaddr_u *restrict source)
{
    if (source->sa.sa_family == AF_INET)
    {
        memoryCopy(&(dest->sin.sin_addr.s_addr), &(source->sin.sin_addr.s_addr), sizeof(source->sin.sin_addr.s_addr));
        return;
    }
    memoryCopy(&(dest->sin6.sin6_addr.s6_addr), &(source->sin6.sin6_addr.s6_addr), sizeof(source->sin6.sin6_addr.s6_addr));
}

static inline bool sockaddrCmpIPV4(const sockaddr_u *restrict addr1, const sockaddr_u *restrict addr2)
{
    return (addr1->sin.sin_addr.s_addr == addr2->sin.sin_addr.s_addr);
}

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

static inline hash_t sockaddrCalcHashNoPort(const sockaddr_u *saddr)
{
    hash_t result;
    if (saddr->sa.sa_family == AF_INET)
    {
        result = calcHashBytes(&(saddr->sin.sin_addr), sizeof(struct sockaddr_in));
    }
    else if (saddr->sa.sa_family == AF_INET6)
    {
        result = calcHashBytes(&(saddr->sin6.sin6_addr), sizeof(struct sockaddr_in6));
    }
    else
    {
        assert(false);
        printError("sockaddrCalcHashNoPort");
        exit(1);
    }
    return result;
}

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
        exit(1);
    }
    return result;
}

static inline int parseIPWithSubnetMask( const char *input,struct in6_addr *base_addr, struct in6_addr *subnet_mask)
{
    char *slash;
    char *ip_part;
    char *subnet_part;
    char  input_copy[100];
    strcpy(input_copy, input);

    slash = strchr(input_copy, '/');
    if (slash == NULL)
    {
        printError("Invalid input format.\n");
        return -1;
    }

    *slash      = '\0';
    ip_part     = input_copy;
    subnet_part = slash + 1;

    if (inet_pton(AF_INET, ip_part, base_addr) == 1)
    {
        // IPv4 address
        int prefix_length = atoi(subnet_part);
        if (prefix_length < 0 || prefix_length > 32)
        {
            printError("Invalid subnet mask length.\n");
            return -1;
        }
        uint32_t       mask      = prefix_length > 0 ? htonl((uint32_t)~((1 << (32 - prefix_length)) - 1)) : 0;
        struct in_addr mask_addr = {.s_addr = mask};
        memoryCopy(subnet_mask, &mask_addr, 4);
        return 4;
    }

    if (inet_pton(AF_INET6, ip_part, base_addr) == 1)
    {
        // IPv6 address
        int prefix_length = atoi(subnet_part);
        if (prefix_length < 0 || prefix_length > 128)
        {
            printError("Invalid subnet mask length.\n");
            return -1;
        }

        for (int i = 0; i < 16; i++)
        {
            int bits                     = prefix_length >= 8 ? 8 : prefix_length;
            ((uint8_t *) subnet_mask)[i] = bits == 0 ? 0 : (uint8_t)(0xFF << (8 - bits));
            prefix_length -= bits;
        }

        return 6;
    }

    printError("Invalid IP address.\n");
    return -1;
}


static inline int checkIPRange4(const struct in_addr test_addr, const struct in_addr base_addr,
                                const struct in_addr subnet_mask)
{
    if ((test_addr.s_addr & subnet_mask.s_addr) == (base_addr.s_addr & subnet_mask.s_addr))
    {
        return 1;
    }
    return 0;
}

static inline int checkIPRange6(const struct in6_addr test_addr, const struct in6_addr base_addr,
                                const struct in6_addr subnet_mask)
{

    // uint64_t *test_addr_p   = (uint64_t *) &(test_addr.s6_addr[0]);
    // uint64_t *base_addr_p   = (uint64_t *) &(base_addr.s6_addr[0]);
    // uint64_t *subnet_mask_p = (uint64_t *) &(subnet_mask.s6_addr[0]);

    // if ((base_addr_p[0] & subnet_mask_p[0]) != test_addr_p[0] || (base_addr_p[1] & subnet_mask_p[1]) !=
    // test_addr_p[1])
    // {
    //     return 0;
    // }
    // return 1;

    struct in6_addr masked_test_addr;
    struct in6_addr masked_base_addr;

    for (int i = 0; i < 16; i++)
    {
        masked_test_addr.s6_addr[i] = test_addr.s6_addr[i] & subnet_mask.s6_addr[i];
        masked_base_addr.s6_addr[i] = base_addr.s6_addr[i] & subnet_mask.s6_addr[i];
    }

    if (memcmp(&masked_test_addr, &masked_base_addr, sizeof(struct in6_addr)) == 0)
    {
        return 1;
    }
    return 0;
}

bool verifyIPPort(const char *ipc);
bool verifyIPCdir(const char *ipc);


#endif // WW_SOCKET_H_
