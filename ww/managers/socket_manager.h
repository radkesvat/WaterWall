#pragma once

#include "basic_types.h"
#include "hloop.h"
#include "hsocket.h"
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
    size_t                       tid;
    uint16_t                     real_localport;

} socket_accept_result_t;

typedef void (*onAccept)(hevent_t *ev);

typedef struct udpcon_s
{
    sockaddr_u address_local;
    sockaddr_u address_peer;
    void (*closecb)(struct udpcon_s udp_con);
    void (*readcb)(struct shift_buffer_s *buf);
    void *userdata;

} udpcon_t;

void registerSocketAcceptor(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);

struct socket_manager_s *getSocketManager();

void                     setSocketManager(struct socket_manager_s *state);
struct socket_manager_s *createSocketManager();

void startSocketManager();
