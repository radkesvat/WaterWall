#include "socket_filter_option.h"

void socketfilteroptionInit(socket_filter_option_t *sfo)
{
    memorySet(sfo, 0, sizeof(*sfo));
    sfo->white_list         = vec_ipmask_t_with_capacity(8);
    sfo->black_list         = vec_ipmask_t_with_capacity(8);
    sfo->balance_group_name = NULL;
    sfo->interface_name     = NULL;
}

void socketfilteroptionDeInit(socket_filter_option_t *sfo)
{
    vec_ipmask_t_drop(&sfo->white_list);
    vec_ipmask_t_drop(&sfo->black_list);
}
