#pragma once

#include "interface.h"
#include "wwapi.h"

#include <stdatomic.h>

typedef enum udplistener_source_kind_e
{
    kUdpListenerSourceStatic  = 0,
    kUdpListenerSourceDynamic = 1,
} udplistener_source_kind_t;

typedef enum udplistener_dynamic_endpoint_state_e
{
    kDynamicEndpointPrepared = 0,
    kDynamicEndpointActive   = 1,
    kDynamicEndpointClosing  = 2,
} udplistener_dynamic_endpoint_state_t;

typedef struct udplistener_dynamic_endpoint_s
{
    udplistener_dynamic_endpoint_handle_t handle;
    udplistener_dynamic_endpoint_state_t  state;
    wio_t                                *wio;
    sockaddr_u                            bound_local_addr;
    uint16_t                              bound_local_port;
    ip_addr_t                             expected_peer_ip;
    uint16_t                              expected_source_port;
    bool                                  source_port_pinned;
    sockaddr_u                            pinned_peer_addr;
    line_t                               *line;   // Owned dynamic normal line once datagram arrives
    tunnel_t                             *tunnel; // Owning UdpListener tunnel instance
} udplistener_dynamic_endpoint_t;

#define i_type udplistener_endpoint_map_t       // NOLINT
#define i_key  uint64_t                         // NOLINT (handle.generation)
#define i_val  udplistener_dynamic_endpoint_t * // NOLINT
#include "stc/hmap.h"

typedef struct udplistener_worker_registry_s
{
    udplistener_endpoint_map_t endpoints;
    uint64_t                   next_generation;
} udplistener_worker_registry_t;

typedef struct udplistener_tstate_s
{
    char                          *listen_address;           // address to listen on
    char                          *interface_name;           // optional interface name
    int                            fwmark;                   // optional fwmark (-1 if none)
    vec_ipmask_t                   white_list;               // white list of client addresses (if any)
    vec_ipmask_t                   black_list;               // black list of client addresses (if any)
    int                            listen_multiport_backend; // multiport backend (iptable? sockets?)
    uint16_t                       listen_port_min;          // min port to listen on (minimum of the range)
    uint16_t                       listen_port_max;          // max port to listen on (maximum of the range)
    int                            send_buffer_size;         // optional socket SO_SNDBUF size
    int                            recv_buffer_size;         // optional socket SO_RCVBUF size
    wid_t                          workers_count;
    udplistener_worker_registry_t *worker_registries; // worker-local dynamic endpoint registries
    atomic_bool                    dynamic_admission_open;
} udplistener_tstate_t;

typedef struct udplistener_lstate_s
{
    tunnel_t                             *tunnel; // reference to the tunnel (UdpListener)
    line_t                               *line;   // reference to the line
    udplistener_source_kind_t             source_kind;
    udplistener_dynamic_endpoint_handle_t dynamic_handle;
    uint16_t                              bound_local_port;
    udpsock_t                            *uio; // IO handle for static connection (socket)
    local_idle_item_t                    *idle_handle;
    int                                   listener_fd;
    sockaddr_u                            peer_addr;  // peer address of the connection
    sockaddr_u                            local_addr; // local destination snapshot used for idle identity
    bool                                  read_paused : 1;
} udplistener_lstate_t;

enum
{
    kTunnelStateSize    = sizeof(udplistener_tstate_t),
    kLineStateSize      = sizeof(udplistener_lstate_t),
    kPauseQueueCapacity = 2,
    kUdpInitExpireTime  = 30 * 1000,
    kUdpKeepExpireTime  = 300 * 1000
};

WW_EXPORT void         udplistenerTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *udplistenerTunnelCreate(node_t *node);
WW_EXPORT api_result_t udplistenerTunnelApi(tunnel_t *instance, sbuf_t *message);

void udplistenerTunnelOnPrepair(tunnel_t *t);
void udplistenerTunnelOnStart(tunnel_t *t);
void udplistenerTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void udplistenerTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void udplistenerTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void udplistenerTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);

void udplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l);
void udplistenerTunnelDownStreamResume(tunnel_t *t, line_t *l);

void udplistenerLinestateInitialize(udplistener_lstate_t *ls, line_t *l, tunnel_t *t, udpsock_t *uio,
                                    uint16_t real_localport, const sockaddr_u *peer_addr, const sockaddr_u *local_addr);
void udplistenerLinestateDestroy(udplistener_lstate_t *ls);
void udplistenerRequireCurrentLineWorker(const line_t *l, const char *callback_name);

#ifdef UDPLISTENER_CREATE_TEST_HOOKS
bool udplistenerTestCopyIpMaskList(vec_ipmask_t *dst, const vec_ipmask_t *src);
bool udplistenerTestFailAclCopyReserve(void);
#endif

#ifdef UDPLISTENER_DYNAMIC_ENDPOINT_TEST_HOOKS
typedef enum udplistener_dynamic_endpoint_test_fault_e
{
    kUdpListenerDynamicEndpointTestFaultNone = 0,
    kUdpListenerDynamicEndpointTestFaultAllocateEndpoint,
    kUdpListenerDynamicEndpointTestFaultPublishEndpoint,
} udplistener_dynamic_endpoint_test_fault_t;

bool udplistenerDynamicEndpointTestShouldFail(udplistener_dynamic_endpoint_test_fault_t fault);
#endif

void udplistenerOnConnectionExpire(local_idle_item_t *idle_udp);
void onUdpListenerFilteredPayloadReceived(wevent_t *ev);

// Dynamic provider implementation functions
bool udplistenerDynamicEndpointOpen(tunnel_t *t, wid_t wid, const udplistener_dynamic_endpoint_open_request_t *req,
                                    udplistener_dynamic_endpoint_open_result_t *res_out);
bool udplistenerDynamicEndpointActivate(tunnel_t *t, udplistener_dynamic_endpoint_handle_t handle);
void udplistenerDynamicEndpointClose(tunnel_t *t, udplistener_dynamic_endpoint_handle_t handle);
udplistener_dynamic_endpoint_t *udplistenerFindDynamicEndpoint(tunnel_t                             *t,
                                                               udplistener_dynamic_endpoint_handle_t handle);
bool udplistenerGetLineInfo(tunnel_t *t, const line_t *line, udplistener_dynamic_line_info_t *info_out);
void udplistenerOnDynamicEndpointRead(wio_t *io, sbuf_t *buf);
