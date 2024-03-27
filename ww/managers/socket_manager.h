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
    multiport_backend_default,
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
    bool no_delay;

} socket_filter_option_t;

// user data of accept event
typedef struct socket_accept_result_s
{
    hio_t *io; // it also has the owner loop
    tunnel_t *tunnel;
    socket_protocol_t proto;
    size_t tid;
    uint16_t realport;

} socket_accept_result_t;

typedef void (*onAccept)(hevent_t *ev);


typedef struct socket_filter_s
{
    hio_t *listen_io;
    socket_filter_option_t option;
    tunnel_t *tunnel;
    onAccept cb;
} socket_filter_t;



void registerSocketAcceptor(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);

struct socket_manager_s *getSocketManager();

void setSocketManager(struct socket_manager_s * state);
struct socket_manager_s *createSocketManager();

void startSocketManager();
