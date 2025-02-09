#pragma once

#include "shiftbuffer.h"
#include "tunnel.h"
#include "widle_table.h"
#include "wlibc.h"
#include "wloop.h"
#include "worker.h"
#include "wsocket.h"

typedef enum
{
    kMultiportBackendNone, // Changed from 'Nothing' for consistency
    kMultiportBackendDefault,
    kMultiportBackendIptables,
    kMultiportBackendSockets
} multiport_backend_t;

struct balance_group_s;


/*
    socket_filter_option_t provides information about which protocol (tcp? udp?)
    which ports (single? range?)
    which balance option?

    the acceptor wants, they fill the information and register it by calling socketacceptorRegister
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

    // Internal use
    unsigned int white_list_parsed_length;
    struct
    {
        struct in6_addr ip_bytes_buf;
        struct in6_addr mask_bytes_buf;
    } *white_list_parsed;

    widle_table_t *shared_balance_table;

} socket_filter_option_t;

// if you asked for tcp, you'll get such struct when someone connects and passes all filters
typedef struct socket_accept_result_s
{
    wio_t                       *io;
    tunnel_t                    *tunnel;
    enum socket_address_protocol protocol;
    wid_t                        wid;
    uint16_t                     real_localport;

} socket_accept_result_t;

typedef void (*onAccept)(wevent_t *ev);

typedef struct udpsock_s
{
    wio_t         *io;
    widle_table_t *table;

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
void                     socketacceptresultDestroy(socket_accept_result_t *);
void                     udppayloadDestroy(udp_payload_t *);
struct socket_manager_s *socketmanagerGet(void);
struct socket_manager_s *socketmanagerCreate(void);
void                     socketmanagerDestroy(void);
void                     socketmanagerSet(struct socket_manager_s *state);
void                     socketmanagerStart(void);
void                     socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);
void                     postUdpWrite(udpsock_t *socket_io, wid_t wid_from, sbuf_t *buf);
