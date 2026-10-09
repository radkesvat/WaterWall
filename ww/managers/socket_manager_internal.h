#pragma once

/* Private listener ownership and selection types; not an external-node API. */
#include "socket_manager.h"

enum
{
    kFilterLevels               = 4,
    kMaxBalanceSelections       = 64,
    kDefaultBalanceInterval     = 60 * 1000,
    kDispatchTierExact          = 0,
    kDispatchTierWildcardFamily = 1,
    kDispatchTierWildcardDual   = 2,
    kDispatchTierCount          = 3
};

typedef struct socket_filter_s
{
    socket_filter_option_t option;
    tunnel_t              *tunnel;
    onAccept               cb;
    idle_table_t          *balance_table;
    ip_addr_t              bind_addr;
    uint8_t                bind_family;
    bool                   bind_is_wildcard;
    bool                   bind_endpoint_ready;
} socket_filter_t;

#define i_type filters_t
#define i_key  socket_filter_t *
#define i_use_cmp
#include "stc/vec.h"

/* Separately allocated: WIO userdata and UDP owner slots survive vector growth.
 * The manager retains each endpoint and its side-data until workers settle. */
typedef struct listener_endpoint_s
{
    uint8_t    protocol;
    uint8_t    family;
    bool       is_wildcard;
    ip_addr_t  bind_addr;
    uint16_t   port;
    char      *interface_scope;
    wio_t     *listen_io;
    udpsock_t *udp_socket;
    int        fwmark;
    int        send_buffer_size;
    int        recv_buffer_size;
} listener_endpoint_t;

#define i_type endpoint_registry_t, listener_endpoint_t *
#include "stc/vec.h"

/* Borrows immutable ingress identity. Addresses and port are logical arrival
 * metadata, which can differ from the bound socket after a redirect. */
typedef struct listener_arrival_s
{
    const listener_endpoint_t *endpoint;
    ip_addr_t                  peer_addr;
    ip_addr_t                  local_addr;
    uint16_t                   local_port;
    uint8_t                    protocol;
} listener_arrival_t;

typedef struct listener_selection_s
{
    socket_filter_t *filter;
    hash_t           sticky_key;
    bool             pending_sticky;
} listener_selection_t;

static inline const char *filterInterfaceScope(const socket_filter_t *filter)
{
    const char *name = filter->option.interface_name;
    return name != NULL && name[0] != '\0' && socketOptionBindToDeviceSupported() ? name : NULL;
}

/* Run on the SocketManager owner worker. Selection refreshes cached hits;
 * adapters commit a new sticky entry only after transport setup succeeds. */
listener_selection_t socketManagerSelect(const filters_t filters[kFilterLevels], wid_t wid,
                                         const listener_arrival_t *arrival);
void                 socketManagerCommitSelection(wid_t wid, const listener_selection_t *selection);
hash_t               socketManagerArrivalBalanceHash(const listener_arrival_t *arrival, int tier);
