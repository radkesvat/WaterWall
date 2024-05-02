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

typedef struct socket_filter_option_s
{
    char                        *host;
    enum socket_address_protocol proto;
    multiport_backend_t          multiport_backend;
    uint16_t                     port_min;
    uint16_t                     port_max;
    char                       **white_list_raddr;
    char                       **black_list_raddr;
    bool                         fast_open;
    bool                         no_delay;

} socket_filter_option_t;

// user data of accept event
typedef struct socket_accept_result_s
{
    hio_t                       *io; // it also has the owner loop
    tunnel_t                    *tunnel;
    enum socket_address_protocol proto;
    uint8_t                      tid;
    uint16_t                     real_localport;

} socket_accept_result_t;

typedef void (*onAccept)(hevent_t *ev);

typedef struct udpsock_s
{
    hio_t        *io;
    idle_table_t *udp_table;

} udpsock_t;

typedef struct udp_payload_s
{
    udpsock_t      *sock;
    tunnel_t       *tunnel;
    uint8_t         tid;
    sockaddr_u      peer_addr;
    uint16_t        real_localport;
    shift_buffer_t *buf;

} udp_payload_t;
void postUdpWrite(hio_t *socket_io, shift_buffer_t *buf);

void registerSocketAcceptor(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);

struct socket_manager_s *getSocketManager();
struct socket_manager_s *createSocketManager();
void                     setSocketManager(struct socket_manager_s *state);
void                     startSocketManager();
