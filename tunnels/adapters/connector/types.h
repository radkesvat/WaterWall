#pragma once
#include "api.h"



typedef struct connector_state_s
{
    tunnel_t *tcp_connector;
    tunnel_t *udp_connector;

} connector_state_t;

typedef struct connector_con_state_s
{

} connector_con_state_t;



