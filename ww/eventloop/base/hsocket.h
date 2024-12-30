#ifndef HV_SOCKET_H_
#define HV_SOCKET_H_

#include "hexport.h"
#include "hplatform.h"

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

#define LOCALHOST   "127.0.0.1"
#define ANYADDR     "0.0.0.0"

BEGIN_EXTERN_C

HV_INLINE int socketERRNO(void) {
#ifdef OS_WIN
    return WSAGetLastError();
#else
    return errno;
#endif
}
HV_EXPORT const char* socketStrError(int err);

#ifdef OS_WIN

typedef SOCKET  hsocket_t;
typedef int     socklen_t;

void WSAInit(void);
void WSADeinit(void);

HV_INLINE int blocking(int sockfd) {
    unsigned long nb = 0;
    return ioctlsocket(sockfd, FIONBIO, &nb);
}

HV_INLINE int nonBlocking(int sockfd) {
    unsigned long nb = 1;
    return ioctlsocket(sockfd, FIONBIO, &nb);
}

#undef  EAGAIN
#define EAGAIN      WSAEWOULDBLOCK

#undef  EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS

#undef  EINTR
#define EINTR       WSAEINTR

#undef  ENOTSOCK
#define ENOTSOCK    WSAENOTSOCK

#undef  EMSGSIZE
#define EMSGSIZE    WSAEMSGSIZE

#else

typedef int     hsocket_t;

#ifndef SOCKET
#define SOCKET int
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET  -1
#endif

HV_INLINE int blocking(int s) {
    return fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
}

HV_INLINE int nonBlocking(int s) {
    return fcntl(s, F_SETFL, fcntl(s, F_GETFL) |  O_NONBLOCK);
}

HV_INLINE int closesocket(int sockfd) {
    return close(sockfd);
}

#endif

#ifndef SAFE_CLOSESOCKET
#define SAFE_CLOSESOCKET(fd)  do {if ((fd) >= 0) {closesocket(fd); (fd) = -1;}} while(0)
#endif

//-----------------------------sockaddr_u----------------------------------------------
typedef union {
    struct sockaddr     sa;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
#ifdef ENABLE_UDS
    struct sockaddr_un  sun;
#endif
} sockaddr_u;

HV_EXPORT bool isIpV4(const char* host);
HV_EXPORT bool isIpV6(const char* host);
HV_INLINE bool isIpAddr(const char* host) {
    return isIpV4(host) || isIpV6(host);
}

// @param host: domain or ip
// @retval 0:succeed
HV_EXPORT int resolveAddr(const char* host, sockaddr_u* addr);

HV_EXPORT const char* sockaddrIp(sockaddr_u* addr, char *ip, int len);
HV_EXPORT uint16_t sockaddrPort(sockaddr_u* addr);
HV_EXPORT int sockaddrSetIp(sockaddr_u* addr, const char* host);
HV_EXPORT void sockaddrSetPort(sockaddr_u* addr, int port);
HV_EXPORT int sockaddrSetIpPort(sockaddr_u* addr, const char* host, int port);
HV_EXPORT socklen_t sockaddrLen(sockaddr_u* addr);
HV_EXPORT const char* sockaddrStr(sockaddr_u* addr, char* buf, int len);

//#define INET_ADDRSTRLEN   16
//#define INET6_ADDRSTRLEN  46
#ifdef ENABLE_UDS
#define SOCKADDR_STRLEN     sizeof(((struct sockaddr_un*)(NULL))->sun_path)
HV_INLINE void sockaddr_set_path(sockaddr_u* addr, const char* path) {
    addr->sa.sa_family = AF_UNIX;
#if defined(OS_UNIX)
    strncpy(addr->sun.sun_path, path, sizeof(addr->sun.sun_path) - 1);
#else
    strncpy_s(addr->sun.sun_path, sizeof(addr->sun.sun_path), path, sizeof(addr->sun.sun_path) - 1);
#endif
}
#else
#define SOCKADDR_STRLEN     64 // ipv4:port | [ipv6]:port
#endif

HV_INLINE void sockaddrPrint(sockaddr_u* addr) {
    char buf[SOCKADDR_STRLEN] = {0};
    sockaddrStr(addr, buf, sizeof(buf));
    puts(buf);
}

#define SOCKADDR_LEN(addr)      sockaddrLen((sockaddr_u*)addr)
#define SOCKADDR_STR(addr, buf) sockaddrStr((sockaddr_u*)addr, buf, sizeof(buf))
#define SOCKADDR_PRINT(addr)    sockaddrPrint((sockaddr_u*)addr)
//=====================================================================================

// socket -> setsockopt -> bind
// @param type: SOCK_STREAM(tcp) SOCK_DGRAM(udp)
// @return sockfd
HV_EXPORT int wwBind(int port, const char* host DEFAULT(ANYADDR), int type DEFAULT(SOCK_STREAM));

// wwBind -> listen
// @return listenfd
HV_EXPORT int wwListen(int port, const char* host DEFAULT(ANYADDR));

// @return connfd
// resolveAddr -> socket -> nonblocking -> connect
HV_EXPORT int wwConnect(const char* host, int port, int nonblock DEFAULT(0));
// wwConnect(host, port, 1)
HV_EXPORT int wwConnectNonblock(const char* host, int port);
// wwConnect(host, port, 1) -> select -> blocking
#define DEFAULT_CONNECT_TIMEOUT 10000 // ms
HV_EXPORT int wwConnectTimeout(const char* host, int port, int ms DEFAULT(DEFAULT_CONNECT_TIMEOUT));

#ifdef ENABLE_UDS
HV_EXPORT int wwBindUnix(const char* path, int type DEFAULT(SOCK_STREAM));
HV_EXPORT int wwListenUnix(const char* path);
HV_EXPORT int wwConnectUnix(const char* path, int nonblock DEFAULT(0));
HV_EXPORT int wwConnectUnixNonblock(const char* path);
HV_EXPORT int wwConnectUnixTimeout(const char* path, int ms DEFAULT(DEFAULT_CONNECT_TIMEOUT));
#endif

// Just implement createSocketPair(AF_INET, SOCK_STREAM, 0, sv);
HV_EXPORT int createSocketPair(int family, int type, int protocol, int sv[2]);

HV_INLINE int tcpNoDelay(int sockfd, int on DEFAULT(1)) {
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char*)&on, sizeof(int));
}

HV_INLINE int tcpNoPush(int sockfd, int on DEFAULT(1)) {
#ifdef TCP_NOPUSH
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NOPUSH, (const char*)&on, sizeof(int));
#elif defined(TCP_CORK)
    return setsockopt(sockfd, IPPROTO_TCP, TCP_CORK, (const char*)&on, sizeof(int));
#else
    (void)sockfd;
    (void)on;
    return 0;
#endif
}

HV_INLINE int tcpKeepAlive(int sockfd, int on DEFAULT(1), int delay DEFAULT(60)) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&on, sizeof(int)) != 0) {
        return socketERRNO();
    }

#ifdef TCP_KEEPALIVE
    return setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE, (const char*)&delay, sizeof(int));
#elif defined(TCP_KEEPIDLE)
    // TCP_KEEPIDLE     => tcp_keepalive_time
    // TCP_KEEPCNT      => tcp_keepalive_probes
    // TCP_KEEPINTVL    => tcp_keepalive_intvl
    return setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, (const char*)&delay, sizeof(int));
#else
    return 0;
#endif
}

HV_INLINE int udpBroadCast(int sockfd, int on DEFAULT(1)) {
    return setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof(int));
}

HV_INLINE int ipV6Only(int sockfd, int on DEFAULT(1)) {
#ifdef IPV6_V6ONLY
    return setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(int));
#else
    return 0;
#endif
}

// send timeout
HV_INLINE int socketOptionSNDTIME(int sockfd, int timeout) {
#ifdef OS_WIN
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(int));
#else
    struct timeval tv = {timeout/1000, (timeout%1000)*1000};
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// recv timeout
HV_INLINE int socketOptionRecvTime(int sockfd, int timeout) {
#ifdef OS_WIN
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(int));
#else
    struct timeval tv = {timeout/1000, (timeout%1000)*1000};
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

// send buffer size
HV_INLINE int socketOptionSNDBUF(int sockfd, int len) {
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char*)&len, sizeof(int));
}

// recv buffer size
HV_INLINE int socketOptionRecvBuf(int sockfd, int len) {
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (const char*)&len, sizeof(int));
}

HV_INLINE int socketOptionReuseAddr(int sockfd, int on DEFAULT(1)) {
#ifdef SO_REUSEADDR
    // NOTE: SO_REUSEADDR allow to reuse sockaddr of TIME_WAIT status
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(int));
#else
    return 0;
#endif
}

HV_INLINE int socketOptionReusePort(int sockfd, int on DEFAULT(1)) {
#ifdef SO_REUSEPORT
    // NOTE: SO_REUSEPORT allow multiple sockets to bind same port
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&on, sizeof(int));
#else
    (void) sockfd;
    (void) on;
    return 0;
#endif
}

HV_INLINE int socketOptionLinger(int sockfd, int timeout DEFAULT(1)) {
#ifdef SO_LINGER
    struct linger linger;
    if (timeout >= 0) {
        linger.l_onoff = 1;
        linger.l_linger = timeout;
    } else {
        linger.l_onoff = 0;
        linger.l_linger = 0;
    }
    // NOTE: SO_LINGER change the default behavior of close, send RST, avoid TIME_WAIT
    return setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char*)&linger, sizeof(linger));
#else
    return 0;
#endif
}

END_EXTERN_C

#endif // HV_SOCKET_H_
