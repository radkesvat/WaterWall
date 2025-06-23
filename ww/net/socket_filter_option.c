#include "socket_filter_option.h"

void socketfilteroptionInit(socket_filter_option_t* sfo){
    sfo->white_list = vec_ipmask_t_with_capacity(8);
    sfo->black_list = vec_ipmask_t_with_capacity(8);

    
}


