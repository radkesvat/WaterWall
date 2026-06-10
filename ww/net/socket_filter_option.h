#pragma once

/*
 * Defines listener socket filter options, port ranges, and ACL lists.
 */

#include "wlibc.h"
#include "widle_table.h"


#define i_type vec_ipmask_t, ipmask_t
#include "stc/vec.h"

#define i_type vec_listener_port_t, uint16_t
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
    char               *balance_group_name;
    char               *interface_name;
    uint8_t             protocol;
    multiport_backend_t multiport_backend;
    uint16_t            port_min;
    uint16_t            port_max;
    vec_listener_port_t ports;
    bool                fast_open;
    bool                no_delay;
    int                 fwmark;
    int                 send_buffer_size;
    int                 recv_buffer_size;
    unsigned int        balance_group_interval;

    vec_ipmask_t white_list;
    vec_ipmask_t black_list;
    // Internal use

    idle_table_t *shared_balance_table;

} socket_filter_option_t;

/**
 * @brief Initialize a socket filter option with default values and vectors.
 *
 * @param sfo Filter option object to initialize.
 */
void socketfilteroptionInit(socket_filter_option_t *sfo);

/**
 * @brief Release dynamically managed resources in a socket filter option.
 *
 * @param sfo Filter option object to deinitialize.
 */
void socketfilteroptionDeInit(socket_filter_option_t *sfo);
