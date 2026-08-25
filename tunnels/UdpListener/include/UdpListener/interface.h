#pragma once

#include "wwapi.h"

typedef struct udplistener_dynamic_endpoint_handle_s
{
    wid_t    owner_wid;
    uint64_t generation;
} udplistener_dynamic_endpoint_handle_t;

static inline bool udplistenerDynamicEndpointHandleIsValid(udplistener_dynamic_endpoint_handle_t handle)
{
    return handle.owner_wid != kInvalidWID && handle.generation != 0;
}

static inline bool udplistenerDynamicEndpointHandleEquals(udplistener_dynamic_endpoint_handle_t left,
                                                          udplistener_dynamic_endpoint_handle_t right)
{
    return left.owner_wid == right.owner_wid && left.generation == right.generation;
}

typedef struct udplistener_dynamic_endpoint_open_request_s
{
    ip_addr_t expected_peer_ip;
    uint16_t  expected_source_port; // 0 if wild / unpinned until first received datagram
} udplistener_dynamic_endpoint_open_request_t;

typedef struct udplistener_dynamic_endpoint_open_result_s
{
    udplistener_dynamic_endpoint_handle_t handle;
    sockaddr_u                            bound_local_addr;
    uint16_t                              bound_local_port;
} udplistener_dynamic_endpoint_open_result_t;

typedef struct udplistener_dynamic_line_info_s
{
    udplistener_dynamic_endpoint_handle_t handle;
    wid_t                                 expected_wid;
    uint64_t                              generation;
    uint16_t                              bound_local_port;
    bool                                  is_dynamic;
} udplistener_dynamic_line_info_t;

typedef struct udplistener_dynamic_provider_s
{
    tunnel_t *instance;
    bool (*open)(tunnel_t *listener, wid_t wid, const udplistener_dynamic_endpoint_open_request_t *req,
                 udplistener_dynamic_endpoint_open_result_t *res_out);
    bool (*activate)(tunnel_t *listener, udplistener_dynamic_endpoint_handle_t handle);
    void (*close)(tunnel_t *listener, udplistener_dynamic_endpoint_handle_t handle);
    bool (*get_line_info)(tunnel_t *listener, const line_t *line, udplistener_dynamic_line_info_t *info_out);
} udplistener_dynamic_provider_t;

WW_EXPORT node_t                         nodeUdpListenerGet(void);
WW_EXPORT udplistener_dynamic_provider_t udplistenerGetDynamicProvider(tunnel_t *t);
