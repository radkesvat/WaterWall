#pragma once

#include "buffer_dispatcher.h"
#include "socket_dispatcher.h"
#include "node_dispatcher.h"


typedef dispatchers_state_s{
    socket_dispatcher_state_t * socket_disp_state; //threadsafe
    socket_dispatcher_state_t * socket_disp_state; //threadsafe
} dispatchers_state_t