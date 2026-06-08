#pragma once

/*
 * Socket manager interfaces for TCP/UDP listener registration and dispatch.
 */

#include "shiftbuffer.h"
#include "socket_filter_option.h"
#include "tunnel.h"
#include "widle_table.h"
#include "wlibc.h"
#include "wloop.h"
#include "worker.h"
#include "wsocket.h"

struct balance_group_s;

// if you asked for tcp, you'll get such struct when someone connects and passes all filters
typedef struct socket_accept_result_s
{
    wio_t    *io;
    tunnel_t *tunnel;
    uint8_t   protocol;
    wid_t     wid;
    uint16_t  real_localport;

} socket_accept_result_t;

typedef void (*onAccept)(wevent_t *ev);

typedef struct udpsock_s
{
    wio_t        *io;
    idle_table_t *table;

} udpsock_t;

// if you asked for udp, you'll get such struct when a udp packet is received and passes all filters
typedef struct udp_payload_s
{
    udpsock_t *sock;
    tunnel_t  *tunnel;
    sbuf_t    *buf;
    sockaddr_u peer_addr;
    uint16_t   real_localport;
    wid_t      wid;

} udp_payload_t;

// Function declarations
/**
 * @brief Release an accepted-socket dispatch object back to pools.
 *
 * @param sar Result object.
 */
void socketacceptresultDestroy(socket_accept_result_t *sar);

/**
 * @brief Release a UDP payload dispatch object back to pools.
 *
 * @param upl UDP payload object.
 */
void udppayloadDestroy(udp_payload_t *upl);

/**
 * @brief Get global socket manager state pointer.
 *
 * @return struct socket_manager_s* Current socket manager.
 */
struct socket_manager_s *socketmanagerGet(void);

/**
 * @brief Create and initialize global socket manager.
 *
 * @return struct socket_manager_s* Created socket manager state.
 */
struct socket_manager_s *socketmanagerCreate(void);

/**
 * @brief Destroy socket manager, listeners, and internal pools.
 */
void socketmanagerDestroy(void);

/**
 * @brief Close listener sockets attached to a loop before that loop frees its IO storage.
 *
 * @param loop Event loop that is about to be destroyed.
 */
void socketmanagerCloseListenersForLoop(wloop_t *loop);

/**
 * @brief Drain UDP idle entries owned by a worker before its line pools are destroyed.
 *
 * @param wid Worker whose UDP listener lines should be drained.
 */
void socketmanagerDrainUdpIdleForWorker(wid_t wid);

/**
 * @brief Set global socket manager state.
 *
 * @param state External socket manager state.
 */
void socketmanagerSet(struct socket_manager_s *state);

/**
 * @brief Start listening sockets for all registered filters.
 */
void socketmanagerStart(void);

/**
 * @brief Register one socket accept/filter rule for a tunnel.
 *
 * @param tunnel Target tunnel for accepted traffic.
 * @param option Filter/listen options.
 * @param cb Callback invoked on accepted payload/socket events.
 */
void socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);

/**
 * @brief Update send/receive buffer options for filters registered by a tunnel.
 *
 * This is used by tunnels that need finalized-chain metadata before deciding
 * their effective accepted-socket buffer defaults.
 */
void socketacceptorUpdateBufferOptions(tunnel_t *tunnel, int send_buffer_size, int recv_buffer_size);

/**
 * @brief Post an asynchronous UDP write to socket-manager worker context.
 *
 * @param socket_io UDP socket wrapper.
 * @param wid_from Source worker id.
 * @param buf Payload buffer.
 * @param peer_addr Peer address.
 */
void postUdpWrite(udpsock_t *socket_io, wid_t wid_from, sbuf_t *buf, sockaddr_u peer_addr);
