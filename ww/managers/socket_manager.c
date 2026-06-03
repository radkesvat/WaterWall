/*
 * Socket listener manager for filtered TCP/UDP accept and worker dispatch.
 */

#include "socket_manager.h"

#include "global_state.h"
#include "loggers/internal_logger.h"
#include "stc/common.h"
#include "threadsafe_generic_pool.h"
#include "tunnel.h"
#include "widle_table.h"
#include "wloop.h"
#include "wmutex.h"
#include "wproc.h"

#define i_type balancegroup_registry_t // NOLINT
#define i_key  hash_t                  // NOLINT
#define i_val  idle_table_t *         // NOLINT

#include "stc/hmap.h"

typedef struct socket_filter_s
{

    wio_t                **listen_ios;
    wio_t                 *listen_io;
    socket_filter_option_t option;
    tunnel_t              *tunnel;
    onAccept               cb;
    bool                   v6_dualstack;

} socket_filter_t;

#define i_type    filters_t         // NOLINT
#define i_key     socket_filter_t * // NOLINT
#define i_use_cmp                   // NOLINT
#include "stc/vec.h"

#define SUPPORT_V6 true

enum
{
    kSoOriginalDest         = 80,
    kFilterLevels           = 4,
    kMaxBalanceSelections   = 64,
    kDefaultBalanceInterval = 60 * 1000
};

typedef struct socket_manager_s
{
    filters_t filters[kFilterLevels];

    threadsafe_generic_pool_t **udp_pools; /* holds udp_payload_t */
    threadsafe_generic_pool_t **tcp_pools; /* holds socket_accept_result_t */

    master_pool_t *mp_udp;
    master_pool_t *mp_tcp;

    wmutex_t                mutex;
    balancegroup_registry_t balance_groups;
    worker_t               *worker;
    wid_t                   wid;

    bool iptables_installed;
    bool ip6tables_installed;
    bool lsof_installed;
    bool iptable_cleaned;
    bool iptables_used;
    bool started;

} socket_manager_state_t;

static socket_manager_state_t *socketmanager_gstate = NULL;

/**
 * @brief Forward declaration for TCP socket dispatch.
 */
static void distributeTcpSocket(wio_t *io, uint16_t local_port);

/**
 * @brief Forward declaration for UDP payload dispatch.
 */
static void distributeUdpPayload(udp_payload_t pl);

/**
 * @brief Allocate pooled TCP accept result object.
 *
 * @param pool Pool instance.
 * @return pool_item_t* Allocated object.
 */
static pool_item_t *allocTcpResultObjectPoolHandle(generic_pool_t *pool)
{
    discard pool;
    return memoryAllocate(sizeof(socket_accept_result_t));
}

/**
 * @brief Destroy pooled TCP accept result object.
 *
 * @param pool Pool instance.
 * @param item Item to destroy.
 */
static void destroyTcpResultObjectPoolHandle(generic_pool_t *pool, pool_item_t *item)
{
    discard pool;
    memoryFree(item);
}

/**
 * @brief Allocate pooled UDP payload wrapper.
 *
 * @param pool Pool instance.
 * @return pool_item_t* Allocated object.
 */
static pool_item_t *allocUdpPayloadPoolHandle(generic_pool_t *pool)
{
    discard pool;
    return memoryAllocate(sizeof(udp_payload_t));
}

/**
 * @brief Destroy pooled UDP payload wrapper.
 *
 * @param pool Pool instance.
 * @param item Item to destroy.
 */
static void destroyUdpPayloadPoolHandle(generic_pool_t *pool, pool_item_t *item)
{
    discard pool;
    memoryFree(item);
}

void socketacceptresultDestroy(socket_accept_result_t *sar)
{
    const wid_t wid = sar->wid;

    threadsafegenericpoolReuseItem(socketmanager_gstate->tcp_pools[wid], sar);
}

/**
 * @brief Acquire a UDP payload object from worker-specific pool.
 *
 * @param wid Worker id.
 * @return udp_payload_t* Pooled payload object.
 */
static udp_payload_t *newUdpPayload(wid_t wid)
{
    udp_payload_t *item = threadsafegenericpoolGetItem(socketmanager_gstate->udp_pools[wid]);
    return item;
}

void udppayloadDestroy(udp_payload_t *upl)
{
    const wid_t wid = upl->wid;

    threadsafegenericpoolReuseItem(socketmanager_gstate->udp_pools[wid], upl);
}

/**
 * @brief Execute one iptables/ip6tables redirect rule.
 *
 * @param protocol Protocol token.
 * @param port_min Range start.
 * @param port_max Range end.
 * @param to_port Redirect target port.
 * @return true Command succeeded.
 * @return false Command failed.
 */
static bool executeIptablesRule(const char *protocol, unsigned int port_min, unsigned int port_max,
                                unsigned int to_port)
{
    char command[256];
    bool result = true;

    if (strcasecmp(protocol, "TCP") != 0 && strcasecmp(protocol, "UDP") != 0)
    {
        return false;
    }

    if (port_min == port_max)
    {
        snprintf(command, sizeof(command), "iptables -t nat -A PREROUTING -p %s --dport %u -j REDIRECT --to-port %u", protocol, port_min,
                to_port);
    }
    else
    {
        snprintf(command, sizeof(command), "iptables -t nat -A PREROUTING -p %s --dport %u:%u -j REDIRECT --to-port %u", protocol,
                port_min, port_max, to_port);
    }
    result = execCmd(command).exit_code == 0;

#if SUPPORT_V6
    if (socketmanager_gstate->ip6tables_installed)
    {
        if (port_min == port_max)
        {
            snprintf(command, sizeof(command), "ip6tables -t nat -A PREROUTING -p %s --dport %u -j REDIRECT --to-port %u", protocol,
                    port_min, to_port);
        }
        else
        {
            snprintf(command, sizeof(command), "ip6tables -t nat -A PREROUTING -p %s --dport %u:%u -j REDIRECT --to-port %u", protocol,
                    port_min, port_max, to_port);
        }
        result = result && execCmd(command).exit_code == 0;
    }
#endif
    return result;
}


/**
 * @brief Install TCP redirect rule for one range.
 */
static bool redirectPortRangeTcp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    return executeIptablesRule("TCP", pmin, pmax, to);
}

/**
 * @brief Install UDP redirect rule for one range.
 */
static bool redirectPortRangeUdp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    return executeIptablesRule("UDP", pmin, pmax, to);
}

/**
 * @brief Install TCP redirect rule for one port.
 */
static bool redirectPortTcp(unsigned int port, unsigned int to)
{
    return executeIptablesRule("TCP", port, port, to);
}

/**
 * @brief Install UDP redirect rule for one port.
 */
static bool redirectPortUdp(unsigned int port, unsigned int to)
{
    return executeIptablesRule("UDP", port, port, to);
}

/**
 * @brief Flush NAT redirect rules from iptables/ip6tables.
 *
 * @param safe_mode True to print via write(), false to log normally.
 * @return true Rules cleared.
 * @return false At least one command failed.
 */
static bool resetIptables(bool safe_mode)
{
    if (safe_mode)
    {
        char    msg[] = "SocketManager: clearing iptables nat rules\n";
        ssize_t _     = write(STDOUT_FILENO, msg, sizeof(msg));
        discard _;
    }
    else
    {
        char msg[] = "SocketManager: clearing iptables nat rules";
        LOGD(msg);
    }

    bool result = true;
    result      = result && execCmd("iptables -t nat -F").exit_code == 0;
    result      = result && execCmd("iptables -t nat -X").exit_code == 0;
#if SUPPORT_V6
    if (socketmanager_gstate->ip6tables_installed)
    {
        result = result && execCmd("ip6tables -t nat -F").exit_code == 0;
        result = result && execCmd("ip6tables -t nat -X").exit_code == 0;
    }
#endif

    return result;
}

/**
 * @brief Detect IPv4-mapped IPv6 addresses that should use IPv4 checks.
 *
 * @param addr IPv6 address.
 * @return true Address uses IPv4-mapped strategy.
 * @return false Native IPv6 address.
 */
static inline bool needsV4SocketStrategy(const ip6_addr_t addr)
{
    uint16_t segments[8];
    memoryCopy(segments, addr.addr, sizeof(segments));
    return (segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 &&
            segments[5] == 0xFFFF);
}

/**
 * @brief Calculate filter processing priority from option complexity.
 *
 * @param option Socket filter option.
 * @return unsigned int Priority level.
 */
static unsigned int calculateFilterPriority(const socket_filter_option_t option)
{
    unsigned int priority = 0;

    if (option.multiport_backend == kMultiportBackendNone)
    {
        priority++;
    }
    if (vec_ipmask_t_size(&option.white_list) > 0)
    {
        priority++;
    }
    if (vec_ipmask_t_size(&option.black_list))
    {
        priority++;
    }

    return priority;
}

/**
 * @brief Get or create shared balance table for a balance group name.
 *
 * @param balance_group_name Group name.
 * @return idle_table_t* Shared balance table.
 */
static idle_table_t *getOrCreateBalanceTable(const char *balance_group_name)
{
    hash_t         name_hash = calcHashBytes(balance_group_name, stringLength(balance_group_name));
    idle_table_t *b_table   = NULL;

    mutexLock(&(socketmanager_gstate->mutex));

    balancegroup_registry_t_iter find_result = balancegroup_registry_t_find(&(socketmanager_gstate->balance_groups), name_hash);

    if (find_result.ref == balancegroup_registry_t_end(&(socketmanager_gstate->balance_groups)).ref)
    {
        b_table = idleTableCreate(socketmanager_gstate->worker->loop);
        balancegroup_registry_t_insert(&(socketmanager_gstate->balance_groups), name_hash, b_table);
    }
    else
    {
        b_table = (find_result.ref->second);
    }

    mutexUnlock(&(socketmanager_gstate->mutex));

    return b_table;
}

void socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{
    if (socketmanager_gstate->started)
    {
        LOGF("SocketManager: cannot register after accept thread starts");
        terminateProgram(1);
    }

    socket_filter_t *filter   = memoryAllocate(sizeof(socket_filter_t));
    unsigned int     priority = calculateFilterPriority(option);

    if (option.balance_group_name)
    {
        option.shared_balance_table = getOrCreateBalanceTable(option.balance_group_name);
    }

    *filter = (socket_filter_t) {.tunnel = tunnel, .option = option, .cb = cb, .listen_io = NULL};

    mutexLock(&(socketmanager_gstate->mutex));
    filters_t_push(&(socketmanager_gstate->filters[priority]), filter);
    mutexUnlock(&(socketmanager_gstate->mutex));
}

void socketacceptorUpdateBufferOptions(tunnel_t *tunnel, int send_buffer_size, int recv_buffer_size)
{
    mutexLock(&(socketmanager_gstate->mutex));
    for (size_t i = 0; i < kFilterLevels; ++i)
    {
        c_foreach(filter, filters_t, socketmanager_gstate->filters[i])
        {
            socket_filter_t *f = *filter.ref;
            if (f->tunnel == tunnel)
            {
                f->option.send_buffer_size = send_buffer_size;
                f->option.recv_buffer_size = recv_buffer_size;
            }
        }
    }
    mutexUnlock(&(socketmanager_gstate->mutex));
}

/**
 * @brief Forward accepted socket to selected worker and tunnel callback.
 *
 * @param io Accepted socket.
 * @param filter Selected filter.
 * @param local_port Original local port.
 */
static void distributeSocket(void *io, socket_filter_t *filter, uint16_t local_port)
{
    wioDetach(io);

    wid_t wid = getNextDistributionWID();

    socket_accept_result_t *result = threadsafegenericpoolGetItem(socketmanager_gstate->tcp_pools[wid]);

    *result = (socket_accept_result_t) {
        .io             = io,
        .tunnel         = filter->tunnel,
        .real_localport = local_port,
        .wid            = wid,
    };

    wloop_t *worker_loop = getWorkerLoop(wid);
    wevent_t ev          = (wevent_t) {.loop = worker_loop, .cb = filter->cb};

    ev.userdata = result;

    if (wid == socketmanager_gstate->wid)
    {
        filter->cb(&ev);
    }
    else
    {
        if (UNLIKELY(! wloopPostEvent(worker_loop, &ev)))
        {
            wioClose(io);
            socketacceptresultDestroy(result);
        }
    }
}

static bool applyAcceptedTcpSocketOptions(wio_t *io, const socket_filter_option_t *option)
{
    if (option->no_delay)
    {
        tcpNoDelay(wioGetFD(io), 1);
    }

    if (! socketOptionApplySendBuffer(wioGetFD(io), option->send_buffer_size))
    {
        LOGE("SocketManager: set TCP socket send buffer failed");
        return false;
    }

    if (! socketOptionApplyRecvBuffer(wioGetFD(io), option->recv_buffer_size))
    {
        LOGE("SocketManager: set TCP socket recv buffer failed");
        return false;
    }

    return true;
}

/**
 * @brief Log and close TCP socket when no filter matched.
 *
 * @param io Socket handle.
 */
static void noTcpSocketConsumerFound(wio_t *io)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGE("SocketManager: could not find consumer for Tcp socket FD:%x [%s] <= [%s]", wioGetFD(io),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
    wioClose(io);
}

/**
 * @brief Check IPv4 address against whitelist.
 */
static bool checkIpv4WhiteList(const ip4_addr_t ipv4_addr, const socket_filter_option_t option)
{
    for (int i = 0; i < vec_ipmask_t_size(&option.white_list); i++)
    {
        if (checkIPRange4(ipv4_addr, vec_ipmask_t_at(&option.white_list, i)->ip.u_addr.ip4,
                          vec_ipmask_t_at(&option.white_list, i)->mask.u_addr.ip4))
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Check IPv6 address against whitelist.
 */
static bool checkIpv6WhiteList(const ip6_addr_t ipv6_addr, const socket_filter_option_t option)
{
    for (int i = 0; i < vec_ipmask_t_size(&option.white_list); i++)
    {
        if (checkIPRange6(ipv6_addr, vec_ipmask_t_at(&option.white_list, i)->ip.u_addr.ip6,
                          vec_ipmask_t_at(&option.white_list, i)->mask.u_addr.ip6))
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Check IPv4 address against blacklist.
 */
static bool checkIpv4BlackList(const ip4_addr_t ipv4_addr, const socket_filter_option_t option)
{
    for (int i = 0; i < vec_ipmask_t_size(&option.black_list); i++)
    {
        if (checkIPRange4(ipv4_addr, vec_ipmask_t_at(&option.black_list, i)->ip.u_addr.ip4,
                          vec_ipmask_t_at(&option.black_list, i)->mask.u_addr.ip4))
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Check IPv6 address against blacklist.
 */
static bool checkIpv6BlackList(const ip6_addr_t ipv6_addr, const socket_filter_option_t option)
{
    for (int i = 0; i < vec_ipmask_t_size(&option.black_list); i++)
    {
        if (checkIPRange6(ipv6_addr, vec_ipmask_t_at(&option.black_list, i)->ip.u_addr.ip6,
                          vec_ipmask_t_at(&option.black_list, i)->mask.u_addr.ip6))
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Check peer IP against whitelist strategy for dual-stack handling.
 */
static bool checkIpIsWhiteList(const ip_addr_t addr, const socket_filter_option_t option)
{
    const bool is_v4 = addr.type == IPADDR_TYPE_V4;
    ip4_addr_t ipv4_addr;

    if (is_v4)
    {
        ip4_addr_copy(ipv4_addr, addr.u_addr.ip4);
        return checkIpv4WhiteList(ipv4_addr, option);
    }

    if (needsV4SocketStrategy(addr.u_addr.ip6))
    {
        memoryCopy(&ipv4_addr, &(addr.u_addr.ip6.addr[3]), sizeof(ipv4_addr.addr));
        return checkIpv4WhiteList(ipv4_addr, option);
    }
    return checkIpv6WhiteList(addr.u_addr.ip6, option);
}

/**
 * @brief Check peer IP against blacklist strategy for dual-stack handling.
 */
static bool checkIpIsBlackList(const ip_addr_t addr, const socket_filter_option_t option)
{
    const bool is_v4 = addr.type == IPADDR_TYPE_V4;
    ip4_addr_t ipv4_addr;

    if (is_v4)
    {
        ip4_addr_copy(ipv4_addr, addr.u_addr.ip4);
        return checkIpv4BlackList(ipv4_addr, option);
    }

    if (needsV4SocketStrategy(addr.u_addr.ip6))
    {
        memoryCopy(&ipv4_addr, &(addr.u_addr.ip6.addr[3]), sizeof(ipv4_addr.addr));
        return checkIpv4BlackList(ipv4_addr, option);
    }
    return checkIpv6BlackList(addr.u_addr.ip6, option);
}

/**
 * @brief Handle TCP balancing logic for filters with shared balance table.
 *
 * @param filter Candidate filter.
 * @param option Filter option.
 * @param io Accepted socket.
 * @param local_port Local port.
 * @param src_hash Cached source hash.
 * @param src_hashed Whether source hash is ready.
 * @param balance_selection_filters Candidate fallback filters.
 * @param balance_selection_filters_length Candidate count.
 * @param selected_balance_table Selected table guard.
 * @return true Socket was dispatched.
 * @return false Continue evaluating filters.
 */
static bool handleBalancedFilter(socket_filter_t *filter, const socket_filter_option_t option, wio_t *io,
                                 uint16_t local_port, hash_t *src_hash, bool *src_hashed,
                                 socket_filter_t **balance_selection_filters, uint8_t *balance_selection_filters_length,
                                 idle_table_t **selected_balance_table)
{
    if (*selected_balance_table != NULL && option.shared_balance_table != *selected_balance_table)
    {
        return false;
    }

    if (! *src_hashed)
    {
        ip_addr_t paddr;
        sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr);
        *src_hash   = ipaddrCalcHashNoPort(paddr);
        *src_hashed = true;
    }

    idle_item_t *idle_item = idletableGetIdleItemByHash(socketmanager_gstate->wid, option.shared_balance_table, *src_hash);

    if (idle_item)
    {
        socket_filter_t *target_filter = idle_item->userdata;
        idletableKeepIdleItemForAtleast(option.shared_balance_table, idle_item,
                                        option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                           : option.balance_group_interval);
        if (! applyAcceptedTcpSocketOptions(io, &target_filter->option))
        {
            wioClose(io);
            return true;
        }
        distributeSocket(io, target_filter, local_port);
        return true;
    }

    if (UNLIKELY(*balance_selection_filters_length >= kMaxBalanceSelections))
    {
        LOGW("SocketManager: balance between more than %d tunnels is not supported", kMaxBalanceSelections);
        return false;
    }
    balance_selection_filters[(*balance_selection_filters_length)++] = filter;
    *selected_balance_table                                          = option.shared_balance_table;
    return false;
}

/**
 * @brief Finalize TCP dispatch when only balanced candidates remain.
 */
static void finalizeTcpDistribution(socket_filter_t **balance_selection_filters,
                                    uint8_t balance_selection_filters_length, wio_t *io, uint16_t local_port,
                                    hash_t src_hash)
{
    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        if (! applyAcceptedTcpSocketOptions(io, &filter->option))
        {
            wioClose(io);
            return;
        }
        idletableCreateItem(filter->option.shared_balance_table, src_hash, filter, NULL, socketmanager_gstate->wid,
                            filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                       : filter->option.balance_group_interval);
        distributeSocket(io, filter, local_port);
    }
    else
    {
        noTcpSocketConsumerFound(io);
    }
}

/**
 * @brief Evaluate whether filter matches TCP packet metadata and ACL rules.
 */
static bool processFilterMatch(const socket_filter_option_t option, uint16_t local_port, const ip_addr_t paddr)
{
    if (option.protocol != IPPROTO_TCP || option.port_min > local_port || option.port_max < local_port)
    {
        return false;
    }

    if (vec_ipmask_t_size(&option.white_list) > 0)
    {
        if (! checkIpIsWhiteList(paddr, option))
        {
            return false;
        }
    }
    if (vec_ipmask_t_size(&option.black_list) > 0)
    {
        if (checkIpIsBlackList(paddr, option))
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Route accepted TCP socket through filter chain.
 */
static void distributeTcpSocket(wio_t *io, uint16_t local_port)
{
    ip_addr_t paddr;
    sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr);

    static socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t                 balance_selection_filters_length = 0;
    idle_table_t          *selected_balance_table           = NULL;
    hash_t                  src_hash                         = 0x0;
    bool                    src_hashed                       = false;

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
        {
            socket_filter_t       *filter = *(k.ref);
            socket_filter_option_t option = filter->option;

            if (! processFilterMatch(option, local_port, paddr))
            {
                continue;
            }

            if (option.shared_balance_table)
            {
                if (handleBalancedFilter(filter, option, io, local_port, &src_hash, &src_hashed,
                                         balance_selection_filters, &balance_selection_filters_length,
                                         &selected_balance_table))
                {
                    return;
                }
            }
            else
            {
                if (! applyAcceptedTcpSocketOptions(io, &filter->option))
                {
                    wioClose(io);
                    return;
                }
                distributeSocket(io, filter, local_port);
                return;
            }
        }
    }

    finalizeTcpDistribution(balance_selection_filters, balance_selection_filters_length, io, local_port, src_hash);
}

/**
 * @brief TCP accept callback for single-port listeners.
 */
static void onAcceptTcpSinglePort(wio_t *io)
{
    distributeTcpSocket(io, sockaddrPort(wioGetLocaladdrU(io)));
}

/**
 * @brief TCP accept callback for redirected multi-port listeners.
 */
static void onAcceptTcpMultiPort(wio_t *io)
{
#ifdef OS_UNIX
    ip_addr_t paddr;
    if (! sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr))
    {
        LOGE("SocketManger: address parse failure");
        wioClose(io);
        return;
    }

    bool          use_v4_strategy = paddr.type == IPADDR_TYPE_V6 ? needsV4SocketStrategy(paddr.u_addr.ip6) : true;
    unsigned char pbuf[28]        = {0};
    socklen_t     size            = use_v4_strategy ? 16 : 24;

    int level = use_v4_strategy ? IPPROTO_IP : IPPROTO_IPV6;
    if (getsockopt(wioGetFD(io), level, kSoOriginalDest, &(pbuf[0]), &size) < 0)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGE("SocketManger: multiport failure getting origin port FD:%x [%s] <= [%s]", wioGetFD(io),
             SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
        wioClose(io);
        return;
    }

    distributeTcpSocket(io, (uint16_t) ((pbuf[2] << 8) | pbuf[3]));
#else
    onAcceptTcpSinglePort(io);
#endif
}

/**
 * @brief Pick default multi-port backend from detected capabilities.
 */
static multiport_backend_t getDefaultMultiPortBackend(void)
{
    if (socketmanager_gstate->iptables_installed)
    {
        return kMultiportBackendIptables;
    }
    return kMultiportBackendSockets;
}

/**
 * @brief Resolve interface name to host string.
 */
static bool getInterfaceHostString(const char *if_name, char *host_if)
{
    if (! getInterfaceIpString(if_name, host_if, INET_ADDRSTRLEN))
    {
        LOGF("SocketManager: Could not get interface \"%s\" ip", if_name);
        terminateProgram(1);
        return false;
    }
    return true;
}

/**
 * @brief Choose bind host while preserving device binding when supported.
 */
static const char *getSocketBindHost(socket_filter_t *filter, const char *host, char *host_if)
{
    if (filter->option.interface_name == NULL || socketOptionBindToDeviceSupported())
    {
        return host;
    }

    getInterfaceHostString(filter->option.interface_name, host_if);
    return host_if;
}

/**
 * @brief Create TCP listener with configured socket options.
 */
static wio_t *createTcpServerWithSocketOptions(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                               void (*callback)(wio_t *))
{
    char        host_if[INET_ADDRSTRLEN] = {0};
    const char *bind_host                = getSocketBindHost(filter, host, host_if);
    return wloopCreateTcpServerWithOptions(loop, bind_host, port, callback, filter->option.interface_name,
                                           filter->option.fwmark);
}

/**
 * @brief Create UDP listener with configured socket options.
 */
static wio_t *createUdpServerWithSocketOptions(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port)
{
    char        host_if[INET_ADDRSTRLEN] = {0};
    const char *bind_host                = getSocketBindHost(filter, host, host_if);
    wio_t      *io                       =
        wloopCreateUdpServerWithBufferOptions(loop, bind_host, port, filter->option.interface_name,
                                              filter->option.fwmark, filter->option.send_buffer_size,
                                              filter->option.recv_buffer_size);

    if (io == NULL)
    {
        return NULL;
    }

    return io;
}

/**
 * @brief Select one listening port used as redirect target for iptables mode.
 */
static uint16_t selectMainPortForIptables(socket_filter_t *filter, wloop_t *loop, char *host, uint16_t port_min,
                                          uint16_t port_max, uint8_t *ports_overlapped)
{
    for (int main_port = (int) port_max; main_port >= (int) port_min; --main_port)
    {
        if (ports_overlapped[(uint16_t) main_port] == 1)
        {
            continue;
        }

        filter->listen_io =
            createTcpServerWithSocketOptions(loop, filter, host, (uint16_t) main_port, onAcceptTcpMultiPort);
        if (filter->listen_io == NULL)
        {
            continue;
        }

        ports_overlapped[(uint16_t) main_port] = 1;
        filter->v6_dualstack                   = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;
        return (uint16_t) main_port;
    }

    LOGF("SocketManager: stopping due to null socket handle");
    terminateProgram(1);
    return 0;
}

/**
 * @brief Validate and initialize iptables state on first use.
 */
static void initializeIptablesIfNeeded(void)
{
    if (! socketmanager_gstate->iptables_installed)
    {
        LOGF("SocketManager: multi port backend \"iptables\" colud not start, error: not installed");
        terminateProgram(1);
    }
#if SUPPORT_V6
    if (! socketmanager_gstate->ip6tables_installed)
    {
        LOGW("SocketManager: ip6tables is not installed, ipv6 nat redirect rules will be skipped");
    }
#endif

    socketmanager_gstate->iptables_used = true;
    if (! socketmanager_gstate->iptable_cleaned)
    {
        if (! resetIptables(false))
        {
            LOGF("SocketManager: could not clear iptables rules");
            terminateProgram(1);
        }
        socketmanager_gstate->iptable_cleaned = true;
    }
}

/**
 * @brief Listen TCP on range via iptables redirect backend.
 */
static void listenTcpMultiPortIptables(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                       uint8_t *ports_overlapped, uint16_t port_max)
{
    initializeIptablesIfNeeded();

    uint16_t main_port = selectMainPortForIptables(filter, loop, host, port_min, port_max, ports_overlapped);

    if (! redirectPortRangeTcp(port_min, port_max, main_port))
    {
        LOGF("SocketManager: failed to add iptables rules for tcp range %u-%u", port_min, port_max);
        terminateProgram(1);
    }
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "TCP");
}

/**
 * @brief Listen TCP on each port in range via socket-per-port backend.
 */
static void listenTcpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      uint8_t *ports_overlapped, uint16_t port_max)
{
    const int length = (int) (port_max - port_min + 1);
    filter->listen_ios = (wio_t **) memoryAllocate(sizeof(wio_t *) * ((size_t) length + 1));
    memorySet(filter->listen_ios, 0, sizeof(wio_t *) * ((size_t) length + 1));
    int i = 0;

    for (uint16_t p = port_min; p <= port_max; p++)
    {
        if (ports_overlapped[p] == 1)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        ports_overlapped[p] = 1;

        filter->listen_ios[i] = createTcpServerWithSocketOptions(loop, filter, host, p, onAcceptTcpSinglePort);

        if (filter->listen_ios[i] == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        filter->v6_dualstack = wioGetLocaladdr(filter->listen_ios[i])->sa_family == AF_INET6;

        i++;
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "TCP");
    }
}

/**
 * @brief Listen TCP on single port.
 */
static void listenTcpSinglePort(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                uint8_t *ports_overlapped)
{
    if (ports_overlapped[port] == 1)
    {
        return;
    }
    ports_overlapped[port] = 1;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "TCP");

    filter->listen_io = createTcpServerWithSocketOptions(loop, filter, host, port, onAcceptTcpSinglePort);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        terminateProgram(1);
    }
    filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;
}

/**
 * @brief Build TCP listeners for all registered TCP filters.
 */
static void listenTcp(wloop_t *loop, uint8_t *ports_overlapped)
{
    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
        {
            socket_filter_t *filter = *(k.ref);
            if (filter->option.multiport_backend == kMultiportBackendDefault)
            {
                filter->option.multiport_backend = getDefaultMultiPortBackend();
                // iptable backend dose not work with udp sockets
                filter->option.multiport_backend = kMultiportBackendSockets;
            }

            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;
            if (port_min > port_max)
            {
                LOGF("SocketManager: port min must be lower than port max");
                terminateProgram(1);
            }
            else if (port_min == port_max)
            {
                option.multiport_backend = kMultiportBackendNone;
            }
            if (option.protocol == IPPROTO_TCP)
            {
                if (option.multiport_backend == kMultiportBackendIptables)
                {
                    listenTcpMultiPortIptables(loop, filter, option.host, port_min, ports_overlapped, port_max);
                }
                else if (option.multiport_backend == kMultiportBackendSockets)
                {
                    listenTcpMultiPortSockets(loop, filter, option.host, port_min, ports_overlapped, port_max);
                }
                else
                {
                    listenTcpSinglePort(loop, filter, option.host, port_min, ports_overlapped);
                }
            }
        }
    }
}

/**
 * @brief Log dropped UDP payload when no filter matched.
 */
static void noUdpSocketConsumerFound(const udp_payload_t upl)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};
    LOGE("SocketManager: could not find consumer for Udp socket  [%s] <= [%s]",
         SOCKADDR_STR(wioGetLocaladdrU(upl.sock->io), localaddrstr),
         SOCKADDR_STR((sockaddr_u *) &upl.peer_addr, peeraddrstr));
}

/**
 * @brief Post one UDP payload object to target filter callback.
 */
static void postUdpPayload(udp_payload_t post_pl, socket_filter_t *filter)
{
    udp_payload_t *pl = threadsafegenericpoolGetItem(socketmanager_gstate->udp_pools[post_pl.wid]);
    *pl = post_pl;

    pl->tunnel           = filter->tunnel;
    wloop_t *worker_loop = getWorkerLoop(pl->wid);
    wevent_t ev          = (wevent_t) {.loop = worker_loop, .cb = filter->cb};
    ev.userdata          = (void *) pl;

    if (pl->wid == socketmanager_gstate->wid)
    {
        filter->cb(&ev);
        return;
    }
    if (UNLIKELY(! wloopPostEvent(worker_loop, &ev)))
    {
        sbufDestroy(pl->buf);
        udppayloadDestroy(pl);
    }
}

/**
 * @brief Evaluate whether filter matches UDP packet metadata and ACL rules.
 */
static bool processUdpFilterMatch(const socket_filter_option_t option, uint16_t local_port, const ip_addr_t paddr)
{
    if (option.protocol != IPPROTO_UDP || option.port_min > local_port || option.port_max < local_port)
    {
        return false;
    }

    if (vec_ipmask_t_size(&option.white_list) > 0)
    {
        if (! checkIpIsWhiteList(paddr, option))
        {
            return false;
        }
    }
    if (vec_ipmask_t_size(&option.black_list) > 0)
    {
        if (checkIpIsBlackList(paddr, option))
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Handle UDP balancing logic for filters with shared balance table.
 */
static bool handleUdpBalancedFilter(socket_filter_t *filter, const socket_filter_option_t option,
                                    const udp_payload_t pl, hash_t *src_hash, bool *src_hashed,
                                    socket_filter_t **balance_selection_filters,
                                    uint8_t *balance_selection_filters_length, idle_table_t **selected_balance_table)
{
    if (*selected_balance_table != NULL && option.shared_balance_table != *selected_balance_table)
    {
        return false;
    }

    if (! *src_hashed)
    {
        ip_addr_t paddr;
        sockaddrToIpAddr((sockaddr_u *) &pl.peer_addr, &paddr);
        *src_hash   = ipaddrCalcHashNoPort(paddr);
        *src_hashed = true;
    }

    idle_item_t *idle_item = idletableGetIdleItemByHash(socketmanager_gstate->wid, option.shared_balance_table, *src_hash);

    if (idle_item)
    {
        socket_filter_t *target_filter = idle_item->userdata;
        idletableKeepIdleItemForAtleast(option.shared_balance_table, idle_item,
                                        option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                           : option.balance_group_interval);
        postUdpPayload(pl, target_filter);
        return true;
    }

    if (UNLIKELY(*balance_selection_filters_length >= kMaxBalanceSelections))
    {
        LOGW("SocketManager: balance between more than %d tunnels is not supported", kMaxBalanceSelections);
        return false;
    }
    balance_selection_filters[(*balance_selection_filters_length)++] = filter;
    *selected_balance_table                                          = option.shared_balance_table;
    return false;
}

/**
 * @brief Finalize UDP dispatch when only balanced candidates remain.
 */
static void finalizeUdpDistribution(socket_filter_t **balance_selection_filters,
                                    uint8_t balance_selection_filters_length, const udp_payload_t pl, hash_t src_hash)
{
    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        idletableCreateItem(filter->option.shared_balance_table, src_hash, filter, NULL, socketmanager_gstate->wid,
                            filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                       : filter->option.balance_group_interval);
        postUdpPayload(pl, filter);
    }
    else
    {
        noUdpSocketConsumerFound(pl);
    }
}

/**
 * @brief Route received UDP payload through filter chain.
 */
static void distributeUdpPayload(const udp_payload_t pl)
{
    ip_addr_t paddr;
    // Use the per-packet snapshot: the shared listener socket peer address can change before worker dispatch runs.
    sockaddrToIpAddr((sockaddr_u *) &pl.peer_addr, &paddr);

    uint16_t local_port = pl.real_localport;

    static socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t                 balance_selection_filters_length = 0;
    idle_table_t          *selected_balance_table           = NULL;
    hash_t                  src_hash                         = 0x0;
    bool                    src_hashed                       = false;

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
        {
            socket_filter_t       *filter = *(k.ref);
            socket_filter_option_t option = filter->option;

            if (! processUdpFilterMatch(option, local_port, paddr))
            {
                continue;
            }

            if (option.shared_balance_table)
            {
                if (handleUdpBalancedFilter(filter, option, pl, &src_hash, &src_hashed, balance_selection_filters,
                                            &balance_selection_filters_length, &selected_balance_table))
                {
                    return;
                }
            }
            else
            {
                postUdpPayload(pl, filter);
                return;
            }
        }
    }

    finalizeUdpDistribution(balance_selection_filters, balance_selection_filters_length, pl, src_hash);
}

/**
 * @brief UDP read callback for single-port listeners.
 */
static void onUdpPacketReceived(wio_t *io, sbuf_t *buf)
{
    udpsock_t *socket      = weventGetUserdata(io);
    uint16_t   local_port  = sockaddrPort(wioGetLocaladdrU(io));
    uint16_t   remote_port = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid  = (wid_t) remote_port % (getWorkersCount());

    if (UNLIKELY(isApplicationTerminating()))
    {
        sbufDestroy(buf);
        return;
    }

    udp_payload_t item = (udp_payload_t) {
        .sock = socket, .buf = buf, .wid = target_wid, .peer_addr = *wioGetPeerAddrU(io), .real_localport = local_port};

    distributeUdpPayload(item);
}

// sad: this dose not work (getsockopt fails)
/**
 * @brief UDP read callback for redirected multi-port listeners.
 */
static void onUdpPacketReceivedMultiPort(wio_t *io, sbuf_t *buf)
{

#ifdef OS_UNIX
    udpsock_t *socket      = weventGetUserdata(io);
    uint16_t   remote_port = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid  = (wid_t) remote_port % (getWorkersCount());
    uint16_t   real_local_port = sockaddrPort(wioGetLocaladdrU(io)); // default fallback

    if (UNLIKELY(isApplicationTerminating()))
    {
        sbufDestroy(buf);
        return;
    }

    // Get the original destination port using SO_ORIGINAL_DST
    ip_addr_t paddr;
    if (sockaddrToIpAddr(wioGetPeerAddrU(io), &paddr))
    {
        bool          use_v4_strategy = paddr.type == IPADDR_TYPE_V6 ? needsV4SocketStrategy(paddr.u_addr.ip6) : true;
        unsigned char pbuf[28]        = {0};
        socklen_t     size            = use_v4_strategy ? 16 : 24;

        int level = use_v4_strategy ? IPPROTO_IP : IPPROTO_IPV6;
        if (getsockopt(wioGetFD(io), level, kSoOriginalDest, &(pbuf[0]), &size) >= 0)
        {
            real_local_port = (uint16_t) ((pbuf[2] << 8) | pbuf[3]);
        }
        else
        {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN]  = {0};
            LOGW("SocketManager: UDP multiport failure getting origin port FD:%x [%s] <= [%s], using fallback port", 
                 wioGetFD(io), SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr), 
                 SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
        }
    }

    udp_payload_t item = (udp_payload_t) {
        .sock = socket, .buf = buf, .wid = target_wid, .peer_addr = *wioGetPeerAddrU(io), .real_localport = real_local_port};

    distributeUdpPayload(item);
#else
    onUdpPacketReceived(io, buf);
#endif
}

/**
 * @brief Listen UDP on single port.
 */
static void listenUdpSinglePort(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                uint8_t *ports_overlapped)
{
    if (ports_overlapped[port] == 1)
    {
        return;
    }
    ports_overlapped[port] = 1;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "UDP");
    filter->listen_io = createUdpServerWithSocketOptions(loop, filter, host, port);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        terminateProgram(1);
    }
    udpsock_t *socket = memoryAllocate(sizeof(udpsock_t));
    *socket           = (udpsock_t) {.io = filter->listen_io, .table = idleTableCreate(loop)};
    weventSetUserData(filter->listen_io, socket);
    wioSetCallBackRead(filter->listen_io, onUdpPacketReceived);
    wioRead(filter->listen_io);
}

/**
 * @brief Listen UDP on range via iptables redirect backend.
 */
static void listenUdpMultiPortIptables(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                       uint8_t *ports_overlapped, uint16_t port_max)
{
    initializeIptablesIfNeeded();

    // Find an available port for the main UDP socket
    int main_port = -1;
    for (int p = (int) port_max; p >= (int) port_min; --p)
    {
        if (ports_overlapped[(uint16_t) p] == 1)
        {
            continue;
        }

        filter->listen_io = createUdpServerWithSocketOptions(loop, filter, host, (uint16_t) p);
        if (filter->listen_io != NULL)
        {
            ports_overlapped[(uint16_t) p] = 1;
            main_port                      = p;
            break;
        }
    }

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null UDP socket handle");
        terminateProgram(1);
    }

    filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;

    // Set up the UDP socket with multiport packet handler
    udpsock_t *socket = memoryAllocate(sizeof(udpsock_t));
    *socket           = (udpsock_t) {.io = filter->listen_io, .table = idleTableCreate(loop)};
    weventSetUserData(filter->listen_io, socket);
    wioSetCallBackRead(filter->listen_io, onUdpPacketReceivedMultiPort);
    wioRead(filter->listen_io);

    // Set up iptables redirection for the port range
    if (! redirectPortRangeUdp(port_min, port_max, (uint16_t) main_port))
    {
        LOGF("SocketManager: failed to add iptables rules for udp range %u-%u", port_min, port_max);
        terminateProgram(1);
    }
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "UDP");
}

/**
 * @brief Listen UDP on each port in range via socket-per-port backend.
 */
static void listenUdpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      uint8_t *ports_overlapped, uint16_t port_max)
{
    const int length = (int) (port_max - port_min + 1);
    filter->listen_ios = (wio_t **) memoryAllocate(sizeof(wio_t *) * ((size_t) length + 1));
    memorySet(filter->listen_ios, 0, sizeof(wio_t *) * ((size_t) length + 1));
    int i = 0;

    for (uint16_t p = port_min; p <= port_max; p++)
    {
        if (ports_overlapped[p] == 1)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        ports_overlapped[p] = 1;

        wio_t *udp_io = createUdpServerWithSocketOptions(loop, filter, host, p);
        if (udp_io == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }

        filter->listen_ios[i] = udp_io;
        filter->v6_dualstack = wioGetLocaladdr(udp_io)->sa_family == AF_INET6;

        // Set up the UDP socket
        udpsock_t *socket = memoryAllocate(sizeof(udpsock_t));
        *socket           = (udpsock_t) {.io = udp_io, .table = idleTableCreate(loop)};
        weventSetUserData(udp_io, socket);
        wioSetCallBackRead(udp_io, onUdpPacketReceived);
        wioRead(udp_io);

        i++;
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "UDP");
    }
}

/**
 * @brief Build UDP listeners for all registered UDP filters.
 */
static void listenUdp(wloop_t *loop, uint8_t *ports_overlapped)
{
    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, socketmanager_gstate->filters[ri])
        {
            socket_filter_t *filter = *(k.ref);
            if (filter->option.multiport_backend == kMultiportBackendDefault)
            {
                filter->option.multiport_backend = getDefaultMultiPortBackend();
            }

            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;
            if (port_min > port_max)
            {
                LOGF("SocketManager: port min must be lower than port max");
                terminateProgram(1);
            }
            else if (port_min == port_max)
            {
                option.multiport_backend = kMultiportBackendNone;
            }
            if (option.protocol == IPPROTO_UDP)
            {
                if (option.multiport_backend == kMultiportBackendIptables)
                {
                    listenUdpMultiPortIptables(loop, filter, option.host, port_min, ports_overlapped, port_max);
                }
                else if (option.multiport_backend == kMultiportBackendSockets)
                {
                    listenUdpMultiPortSockets(loop, filter, option.host, port_min, ports_overlapped, port_max);
                }
                else
                {
                    listenUdpSinglePort(loop, filter, option.host, port_min, ports_overlapped);
                }
            }
        }
    }
}

/**
 * @brief Worker-loop callback that writes queued UDP payload.
 */
static void writeUdpThisLoop(wevent_t *ev)
{
    udp_payload_t *upl = weventGetUserdata(ev);

    wioSetPeerAddr(upl->sock->io, (struct sockaddr *) &upl->peer_addr, sizeof(sockaddr_u));
    int     nwrite = wioWrite(upl->sock->io, upl->buf);
    discard nwrite;
    udppayloadDestroy(upl);
}

void postUdpWrite(udpsock_t *socket_io, wid_t wid_from, sbuf_t *buf, sockaddr_u peer_addr)
{
    if (wid_from == socketmanager_gstate->wid)
    {
        wioSetPeerAddr(socket_io->io, (struct sockaddr *) &peer_addr, sizeof(sockaddr_u));
        int     nwrite = wioWrite(socket_io->io, buf);
        discard nwrite;
        return;
    }

    udp_payload_t *item = newUdpPayload(wid_from);

    *item = (udp_payload_t) {.sock = socket_io, .buf = buf, .wid = wid_from, .peer_addr = peer_addr};

    wevent_t ev = (wevent_t) {.loop = weventGetLoop(socket_io->io), .userdata = item, .cb = writeUdpThisLoop};

    if (UNLIKELY(! wloopPostEvent(weventGetLoop(socket_io->io), &ev)))
    {
        sbufDestroy(buf);
        udppayloadDestroy(item);
    }
}

struct socket_manager_s *socketmanagerGet(void)
{
    return socketmanager_gstate;
}

void socketmanagerSet(struct socket_manager_s *new_state)
{
    assert(socketmanager_gstate == NULL);
    socketmanager_gstate = new_state;
}

void socketmanagerStart(void)
{
    assert(socketmanager_gstate != NULL);

    assert(socketmanager_gstate && socketmanager_gstate->worker->loop && ! socketmanager_gstate->started);

    mutexLock(&(socketmanager_gstate->mutex));

    {
        uint8_t ports_overlapped[65536] = {0};
        listenTcp(socketmanager_gstate->worker->loop, ports_overlapped);
    }
    {
        uint8_t ports_overlapped[65536] = {0};
        listenUdp(socketmanager_gstate->worker->loop, ports_overlapped);
    }
    socketmanager_gstate->started = true;
    mutexUnlock(&(socketmanager_gstate->mutex));
}

/**
 * @brief Allocate and initialize worker-specific TCP/UDP object pools.
 */
static void initializeSocketManagerPools(void)
{
    socketmanager_gstate->udp_pools = memoryAllocate(sizeof(*socketmanager_gstate->udp_pools) * getTotalWorkersCount());
    memorySet(socketmanager_gstate->udp_pools, 0, sizeof(*socketmanager_gstate->udp_pools) * getTotalWorkersCount());

    socketmanager_gstate->tcp_pools = memoryAllocate(sizeof(*socketmanager_gstate->tcp_pools) * getTotalWorkersCount());
    memorySet(socketmanager_gstate->tcp_pools, 0, sizeof(*socketmanager_gstate->tcp_pools) * getTotalWorkersCount());

    socketmanager_gstate->mp_udp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    socketmanager_gstate->mp_tcp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));

    for (unsigned int i = 0; i < getTotalWorkersCount(); ++i)
    {
        socketmanager_gstate->udp_pools[i] = threadsafegenericpoolCreateWithCapacity(
            socketmanager_gstate->mp_udp, (8) + RAM_PROFILE, allocUdpPayloadPoolHandle, destroyUdpPayloadPoolHandle);

        socketmanager_gstate->tcp_pools[i] = threadsafegenericpoolCreateWithCapacity(
            socketmanager_gstate->mp_tcp, (8) + RAM_PROFILE, allocTcpResultObjectPoolHandle, destroyTcpResultObjectPoolHandle);
    }
}

/**
 * @brief Detect runtime availability of external socket-routing tools.
 */
static void detectSystemCapabilities(void)
{
#ifdef OS_UNIX
    socketmanager_gstate->iptables_installed = checkCommandAvailable("iptables");
    socketmanager_gstate->lsof_installed     = checkCommandAvailable("lsof");
#if SUPPORT_V6
    socketmanager_gstate->ip6tables_installed = checkCommandAvailable("ip6tables");
#endif
#endif
}

socket_manager_state_t *socketmanagerCreate(void)
{
    assert(socketmanager_gstate == NULL);
    socketmanager_gstate = memoryAllocate(sizeof(socket_manager_state_t));
    memorySet(socketmanager_gstate, 0, sizeof(socket_manager_state_t));

    assert(getWID() == 0);
    socketmanager_gstate->worker = getWorker(0);
    socketmanager_gstate->wid    = 0;

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        socketmanager_gstate->filters[i] = filters_t_init();
    }
    socketmanager_gstate->balance_groups = balancegroup_registry_t_with_capacity(8);

    mutexInit(&socketmanager_gstate->mutex);
    initializeSocketManagerPools();
    detectSystemCapabilities();

    return socketmanager_gstate;
}

/**
 * @brief Close one listener and release protocol-specific userdata.
 */
static void cleanupOneListenerIo(wio_t *io, uint8_t protocol)
{
    if (io == NULL)
    {
        return;
    }

    if (protocol == IPPROTO_UDP)
    {
        udpsock_t *socket = weventGetUserdata(io);
        if (socket != NULL)
        {
            if (socket->table != NULL)
            {
                idletableDestroy(socket->table);
                socket->table = NULL;
            }
            memoryFree(socket);
            weventSetUserData(io, NULL);
        }
    }

    wioClose(io);
}

/**
 * @brief Destroy all registered filters and associated listener sockets.
 */
static void cleanupFilters(void)
{
    for (size_t i = 0; i < kFilterLevels; i++)
    {
        c_foreach(filter, filters_t, socketmanager_gstate->filters[i])
        {
            socket_filter_t *f = *filter.ref;

            if (f->listen_ios != NULL)
            {
                int ios_i = 0;
                for (;;)
                {
                    wio_t *io = f->listen_ios[ios_i++];
                    if (io == NULL)
                    {
                        break;
                    }
                    cleanupOneListenerIo(io, f->option.protocol);
                }
                memoryFree((void *) f->listen_ios);
            }
            else
            {
                cleanupOneListenerIo(f->listen_io, f->option.protocol);
            }

            socketfilteroptionDeInit(&(f->option));
            memoryFree(f);
        }
        filters_t_drop(&(socketmanager_gstate->filters[i]));
    }
}

/**
 * @brief Destroy all shared balance-group idle tables.
 */
static void destroyBalanceGroups(void)
{
    c_foreach(bg, balancegroup_registry_t, socketmanager_gstate->balance_groups)
    {
        idletableDestroy(bg.ref->second);
    }
    balancegroup_registry_t_drop(&socketmanager_gstate->balance_groups);
}

/**
 * @brief Destroy socket manager pools and synchronization primitives.
 */
static void destroyPools(void)
{
    for (unsigned int i = 0; i < getTotalWorkersCount(); ++i)
    {
        threadsafegenericpoolDestroy(socketmanager_gstate->udp_pools[i]);
        threadsafegenericpoolDestroy(socketmanager_gstate->tcp_pools[i]);
    }

    memoryFree(socketmanager_gstate->udp_pools);
    memoryFree(socketmanager_gstate->tcp_pools);
    masterpoolDestroy(socketmanager_gstate->mp_tcp);
    masterpoolDestroy(socketmanager_gstate->mp_udp);
}

void socketmanagerDestroy(void)
{
    assert(socketmanager_gstate != NULL);

    if (socketmanager_gstate->iptables_used)
    {
        resetIptables(true);
    }

    cleanupFilters();
    destroyBalanceGroups();
    destroyPools();
    memoryFree(socketmanager_gstate);
    socketmanager_gstate = NULL;
}
