#include "socket_filter_option.h"

/*
 * Initializes and tears down socket filter option dynamic members.
 */

void socketfilteroptionInit(socket_filter_option_t *sfo)
{
    memoryZero(sfo, sizeof(*sfo));
    sfo->white_list         = vec_ipmask_t_with_capacity(8);
    sfo->black_list         = vec_ipmask_t_with_capacity(8);
    sfo->ports              = vec_listener_port_t_with_capacity(4);
    sfo->balance_group_name = NULL;
    sfo->interface_name     = NULL;
    sfo->fwmark             = -1;
}

void socketfilteroptionDeInit(socket_filter_option_t *sfo)
{
    vec_ipmask_t_drop(&sfo->white_list);
    vec_ipmask_t_drop(&sfo->black_list);
    vec_listener_port_t_drop(&sfo->ports);
    if (sfo->balance_group_name != NULL)
    {
        memoryFree(sfo->balance_group_name);
    }
    if (sfo->interface_name != NULL)
    {
        memoryFree(sfo->interface_name);
    }
}
