#pragma once

#include "tunnel.h"
#include "hv/hmutex.h"

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

// user data of accept event
typedef struct socket_accept_result_s
{
    hio_t *io; // it also has the owner loop
    tunnel_t *tunnel;
    socket_protocol_t proto;

} socket_accept_result_t;

typedef void (*onAccept)(hevent_t *ev);




typedef struct socket_filter_s
{
    hio_t *listen_io;

    socket_filter_option_t option;
    hloop_t **loops;
    tunnel_t *tunnel;
    onAccept cb;
} socket_filter_t;

#define i_key socket_filter_t *
#define i_type filters_t
#define i_use_cmp // enable sorting/searhing using default <, == operators
#include "stc/vec.h"


typedef struct socket_dispatcher_state_s
{
    hmutex_t mutex;
    filters_t filters;

} socket_dispatcher_state_t;



void registerSocketAcceptor(socket_dispatcher_state_t *state, hloop_t **loops, tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);

socket_dispatcher_state_t *createSocketDispatcher();

void startSocketDispatcher(socket_dispatcher_state_t *state);
