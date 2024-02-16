#pragma once

#include "tunnel.h"

typedef enum
{
    socket_protocol_invalid,
    socket_protocol_tcp,
    socket_protocol_udp,
    socket_protocol_icmp
} socket_protocol_t;

typedef enum
{
    multiport_backend_nothing,
    multiport_backend_iptables,
    multiport_backend_sockets
} multiport_backend_t;

typedef struct socket_filter_option_s
{
    char *host;
    socket_protocol_t proto;
    multiport_backend_t multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    char **white_list_raddr;
    char **black_list_raddr;
    bool fast_open;

} socket_filter_option_t;

//user data of accept event
typedef struct socket_accept_result_s
{
    hio_t *io;
    tunnel_t *tunnel;
    socket_protocol_t proto;

} socket_accept_result_t;

typedef void (*onAccept)(hevent_t *ev);

void registerSocketAcceptor(hloop_t **loops, tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);

void initSocketDispatcher(hloop_t *loop);

void startSocketDispatcher();
