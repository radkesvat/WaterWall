#pragma once

#include "basic_types.h"
#include "hloop.h"
#include "hsocket.h"
#include "idle_table.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "ww.h"
#include <stddef.h>
#include <stdint.h>

typedef enum
{
    kMultiportBackendNothing,
    kMultiportBackendDefault,
    kMultiportBackendIptables,
    kMultiportBackendSockets
} multiport_backend_t;

struct balance_group_s;

/*
    socket_filter_option_t provides information about which forxample protocol (tcp ? udp?)
    which ports (single? range?)
    which balance option?

    the acceptor wants, they fill the information and register it by calling registerSocketAcceptor

*/
typedef struct socket_filter_option_s
{
    char                        *host;
    char                       **white_list_raddr;
    char                       **black_list_raddr;
    char                        *balance_group_name;
    enum socket_address_protocol protocol;
    multiport_backend_t          multiport_backend;
    uint16_t                     port_min;
    uint16_t                     port_max;
    bool                         fast_open;
    bool                         no_delay;
    unsigned int                 balance_group_interval;

    // private
    unsigned int white_list_parsed_length;
    struct
    {
        struct in6_addr ip_bytes_buf;
        struct in6_addr mask_bytes_buf;
    } *white_list_parsed;

    idle_table_t *shared_balance_table;

} socket_filter_option_t;

// if you asked for tcp, youll get such struct when somone connects and passed all filters
typedef struct socket_accept_result_s
{
    hio_t                       *io;
    tunnel_t                    *tunnel;
    enum socket_address_protocol protocol;
    uint8_t                      tid;
    uint16_t                     real_localport;

} socket_accept_result_t;

typedef void (*onAccept)(hevent_t *ev);

void destroySocketAcceptResult(socket_accept_result_t *);

typedef struct udpsock_s
{
    hio_t        *io;
    idle_table_t *table;

} udpsock_t;

// if you asked for udp, you'll get such struct when a udp packet received and passed all filters
typedef struct udp_payload_s
{
    udpsock_t      *sock;
    tunnel_t       *tunnel;
    shift_buffer_t *buf;
    sockaddr_u      peer_addr;
    uint16_t        real_localport;
    uint8_t         tid;

} udp_payload_t;

void destroyUdpPayload(udp_payload_t *);

struct socket_manager_s *getSocketManager(void);
struct socket_manager_s *createSocketManager(void);
void                     setSocketManager(struct socket_manager_s *state);
void                     startSocketManager(void);
void                     registerSocketAcceptor(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);
void                     postUdpWrite(udpsock_t *socket_io, uint8_t tid_from, shift_buffer_t *buf);
