#pragma once

#include "wevent.h"

// MinGW's Winsock alignment macros define a struct inside offsetof, which Clang flags in C11.
#if defined(__clang__) && defined(__MINGW32__)
#define UDP_WIN_CMSG(expression) __extension__(expression)
#else
#define UDP_WIN_CMSG(expression) (expression)
#endif

// Receive operations submitted to IOCP retain this storage until completion.
typedef union {
    WSACMSGHDR aligned;
    char       bytes[UDP_WIN_CMSG(WSA_CMSG_SPACE(sizeof(IN_PKTINFO)) + WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)))];
} udp_win_control_t;

typedef struct
{
    WSAMSG            message;
    udp_win_control_t control;
} udp_win_receive_t;

static inline bool udpWinIsTruncationError(int error)
{
    return error == WSAEMSGSIZE || error == ERROR_MORE_DATA;
}

void udpWinPrepareReceive(udp_win_receive_t *receive, WSABUF *buffer, struct sockaddr *peer, int peer_size);
void udpWinReadLocalAddress(wio_t *io, udp_win_receive_t *receive);
int  udpWinReadDatagram(wio_t *io, void *bytes, unsigned int length);
int  udpWinSendFrom(int fd, const void *bytes, size_t length, const sockaddr_u *peer, const sockaddr_u *local);
