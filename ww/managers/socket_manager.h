#pragma once

/*
 * Socket manager interfaces for TCP/UDP listener registration and dispatch.
 */

#include "shiftbuffer.h"
#include "local_widle_table.h"
#include "socket_filter_option.h"
#include "tunnel.h"
#include "widle_table.h"
#include "wlibc.h"
#include "wloop.h"
#include "worker.h"
#include "wsocket.h"

struct balance_group_s;

/*
 * TCP accept result delivered to the selected listener tunnel after filtering.
 */
typedef struct socket_accept_result_s
{
    wio_t    *io;
    tunnel_t *tunnel;
    uint8_t   protocol;
    wid_t     wid;
    uint16_t  real_localport;

} socket_accept_result_t;

typedef void (*onAccept)(wevent_t *ev);

typedef struct udpsock_s
{
    wio_t               *io;
    local_idle_table_t **idle_tables;

} udpsock_t;

/**
 * @brief Get the current worker's UDP idle table for a listener socket.
 */
local_idle_table_t *udpsockGetWorkerIdleTable(udpsock_t *socket);

/*
 * UDP packet result delivered to the selected listener tunnel after filtering.
 */
typedef struct udp_payload_s
{
    udpsock_t *sock;
    tunnel_t  *tunnel;
    sbuf_t    *buf;
    sockaddr_u peer_addr;
    // Local destination snapshot for listen-aware UDP dispatch; wildcard sockets may report a wildcard address.
    sockaddr_u real_localaddr;
    uint16_t   real_localport;
    wid_t      wid;

} udp_payload_t;

/**
 * @brief Release an accepted-socket dispatch object back to pools.
 *
 * @param sar Result object.
 */
void socketacceptresultDestroy(socket_accept_result_t *sar);

/**
 * @brief Release a UDP payload dispatch object back to pools.
 *
 * @param upl UDP payload object.
 */
void udppayloadDestroy(udp_payload_t *upl);

/**
 * @brief Get global socket manager state pointer.
 *
 * @return struct socket_manager_s* Current socket manager.
 */
struct socket_manager_s *socketmanagerGet(void);

/**
 * @brief Create and initialize global socket manager.
 *
 * @return struct socket_manager_s* Created socket manager state.
 */
struct socket_manager_s *socketmanagerCreate(void);

/**
 * @brief Destroy socket manager, listeners, and internal pools.
 */
void socketmanagerDestroy(void);

/**
 * @brief Close listener sockets attached to a loop before that loop frees its IO storage.
 *
 * @param loop Event loop that is about to be destroyed.
 */
void socketmanagerCloseListenersForLoop(wloop_t *loop);

/**
 * @brief Drain UDP idle entries owned by a worker before its line pools are destroyed.
 *
 * @param wid Worker whose UDP listener lines should be drained.
 */
void socketmanagerDrainUdpIdleForWorker(wid_t wid);

/**
 * @brief Set global socket manager state.
 *
 * @param state External socket manager state.
 */
void socketmanagerSet(struct socket_manager_s *state);

/**
 * @brief Start listening sockets for all registered filters.
 */
void socketmanagerStart(void);

/**
 * @brief Register one socket accept/filter rule for a tunnel.
 *
 * @param tunnel Target tunnel for accepted traffic.
 * @param option Filter/listen options.
 * @param cb Callback invoked on accepted payload/socket events.
 */
void socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb);

/**
 * @brief Update send/receive buffer options for filters registered by a tunnel.
 *
 * This is used by tunnels that need finalized-chain metadata before deciding
 * their effective accepted-socket buffer defaults.
 */
void socketacceptorUpdateBufferOptions(tunnel_t *tunnel, int send_buffer_size, int recv_buffer_size);

/**
 * @brief Check a peer address against same-family CIDR entries in an ACL.
 *
 * IPv4-mapped IPv6 peers are normalized to IPv4 before matching.
 */
bool socketManagerIpMatchesAcl(ip_addr_t addr, const vec_ipmask_t *acl);

/**
 * @brief Whether a wildcard listener serves a destination at a given dispatch tier (specificity ordering).
 *
 * Exposed for unit tests of exact, same-family wildcard, and dual-stack fallback dispatch.
 */
bool socketManagerWildcardMatchesTier(bool bind_is_v6_wildcard, bool dest_is_v4, int tier);

/**
 * @brief Fold the full matched endpoint scope into a balance stickiness hash.
 *
 * Keeps sticky balancing scoped to the listener endpoint that actually matched. Exposed for unit tests.
 */
hash_t socketManagerCombineBalanceLocalHash(hash_t src_hash, const ip_addr_t *local_addr, uint16_t local_port,
                                            int match_tier);

/**
 * @brief Compute the install-order rank for a NAT redirect rule.
 *
 * Lower ranks install first so specific-address and interface-scoped rules win over wildcard rules.
 *
 * @return 0: specific+interface, 1: specific, 2: wildcard+interface, 3: wildcard.
 */
int socketManagerComputeRedirectRuleRank(bool has_specific_dest, bool has_interface);

typedef enum socket_manager_iptables_chain_action_e
{
    kSocketManagerIptablesCreateChain,
    kSocketManagerIptablesAddJump,
    kSocketManagerIptablesDeleteJump,
    kSocketManagerIptablesFlushChain,
    kSocketManagerIptablesDeleteChain
} socket_manager_iptables_chain_action_t;

/**
 * @brief Build one command that manages a socket-manager-owned NAT chain.
 *
 * The create/flush/delete actions always name the private chain. Jump actions add/remove only that chain's
 * PREROUTING reference. Exposed for unit tests of firewall ownership boundaries.
 */
void socketManagerBuildOwnedChainCommand(char *out, size_t out_len, const char *tool,
                                         socket_manager_iptables_chain_action_t action, const char *chain_name);

/**
 * @brief Build one iptables/ip6tables REDIRECT command in a socket-manager-owned chain.
 *
 * Wildcard destinations must pass has_dest=false so no "-d" match is emitted (never "-d 0.0.0.0" / "-d ::").
 * Interface-scoped rules add "-i <iface>". Exposed for unit tests.
 */
void socketManagerBuildRedirectCommand(char *out, size_t out_len, const char *tool, const char *chain_name,
                                       const char *proto_token, bool has_dest, const char *dest, const char *iface_name,
                                       uint16_t port_min, uint16_t port_max, uint16_t to_port);

/**
 * @brief Post an asynchronous UDP write to socket-manager worker context.
 *
 * @param socket_io UDP socket wrapper.
 * @param wid_from Source worker id.
 * @param buf Payload buffer.
 * @param peer_addr Peer address.
 */
void postUdpWrite(udpsock_t *socket_io, wid_t wid_from, sbuf_t *buf, sockaddr_u peer_addr);
