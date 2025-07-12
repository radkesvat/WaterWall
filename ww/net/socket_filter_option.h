#pragma once

#include "net/address_context.h"
#include "widle_table.h"
#include "wlibc.h"
#include "wsocket.h"


#define i_type vec_ipmask_t, ipmask_t
#include "stc/vec.h"

typedef enum
{
    kMultiportBackendNone, // Changed from 'Nothing' for consistency
    kMultiportBackendDefault,
    kMultiportBackendIptables,
    kMultiportBackendSockets
} multiport_backend_t;

/*
    socket_filter_option_t provides information about which protocol (tcp? udp?)
    which ports (single? range?)
    which balance option?

    the acceptor wants, they fill the information and register it by calling socketacceptorRegister
*/
typedef struct socket_filter_option_s
{
    char *host;
    // char                       **black_list_raddr;
    char                        *balance_group_name;
    char                        *interface;
    enum socket_address_protocol protocol;
    multiport_backend_t          multiport_backend;
    uint16_t                     port_min;
    uint16_t                     port_max;
    bool                         fast_open;
    bool                         no_delay;
    unsigned int                 balance_group_interval;

    vec_ipmask_t white_list;
    vec_ipmask_t black_list;
    // Internal use

    widle_table_t *shared_balance_table;

} socket_filter_option_t;

void socketfilteroptionInit(socket_filter_option_t *sfo);
void socketfilteroptionDeInit(socket_filter_option_t *sfo);
