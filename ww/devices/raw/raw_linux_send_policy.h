#pragma once

#include <errno.h>
#include <stdbool.h>

typedef enum raw_linux_send_action_e
{
    kRawLinuxSendRetryImmediately = 0,
    kRawLinuxSendWaitWritable,
    kRawLinuxSendDiscardPacket,
    kRawLinuxSendTerminal
} raw_linux_send_action_t;

/*
 * Raw-socket send failures are classified by what they say about the exact
 * operation:
 *
 * - EINTR retries the same operation.
 * - EAGAIN/EWOULDBLOCK waits for socket writability.
 * - kernel resource pressure and packet/destination errors discard only the
 *   first unsent message in the sendmmsg() batch.
 * - an unknown error is terminal. Retrying unknown failures is what leaves a
 *   broken descriptor advertised as healthy while every packet is discarded.
 */
static inline raw_linux_send_action_t rawLinuxClassifySendError(int send_errno)
{
    switch (send_errno)
    {
    case EINTR:
        return kRawLinuxSendRetryImmediately;
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
        return kRawLinuxSendWaitWritable;
    case ENOBUFS:
    case ENOMEM:
    case EMSGSIZE:
    case EINVAL:
    case EACCES:
    case EPERM:
    case EADDRNOTAVAIL:
#if defined(EHOSTDOWN) && EHOSTDOWN != EHOSTUNREACH
    case EHOSTDOWN:
#endif
    case EHOSTUNREACH:
    case ENETUNREACH:
    case ECONNREFUSED:
        return kRawLinuxSendDiscardPacket;
    default:
        return kRawLinuxSendTerminal;
    }
}

static inline bool rawLinuxSendErrorIsResourcePressure(int send_errno)
{
    return send_errno == ENOBUFS || send_errno == ENOMEM;
}
