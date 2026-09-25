#pragma once
#include "buffer_pool.h"
#include "wsocket.h"

typedef struct udp_send_result_s
{
    int  bytes;  /* Whole logical datagram length, or -1 on failure; never a partial success. */
    int  error;  /* Captured socket error; zero on success. */
    bool retire; /* Pending assembly is uncertain: close the socket before any further send. */
} udp_send_result_t;

/* Synchronous, nonblocking UDP send to an immutable explicit destination.
 * Caller runs on the socket owner worker, serializes ALL writes through completion,
 * and owns buf on every result. This helper does not transfer socket ownership.
 * pool belongs to the socket owner and supplies temporary materialization buffers.
 * Consumes accepted splice prefixes and actual pipe bytes, including on failure. No callbacks,
 * input recycling, FD closure, connection changes, or retry queue. retry_eintr preserves
 * the stateless adapter's ordinary-send/priming EINTR policy; assembly is never retried.
 * A retire result requires owner-mediated socket closure before returning it to use.
 * Ordinary buffers keep sendto semantics; supported splice bodies use MSG_MORE,
 * splice(SPLICE_F_MORE), then an empty sendto to commit exactly one datagram.
 */
udp_send_result_t udpSendBuffer(int fd, buffer_pool_t *pool, sbuf_t *buf, const sockaddr_u *peer, bool retry_eintr);
