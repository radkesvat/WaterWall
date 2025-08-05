#include "socket_manager.h"

#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "stc/common.h"
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

    struct
    {
        generic_pool_t *pool; /* holds udp_payload_t */
        wmutex_t        mutex;

    } *udp_pools;

    struct
    {
        generic_pool_t *pool; /* holds socket_accept_result_t */
        wmutex_t        mutex;

    } *tcp_pools;

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

static socket_manager_state_t *state = NULL;

static void distributeTcpSocket(wio_t *io, uint16_t local_port);
static void distributeUdpPayload(udp_payload_t pl);

static pool_item_t *allocTcpResultObjectPoolHandle(generic_pool_t *pool)
{
    discard pool;
    return memoryAllocate(sizeof(socket_accept_result_t));
}

static void destroyTcpResultObjectPoolHandle(generic_pool_t *pool, pool_item_t *item)
{
    discard pool;
    memoryFree(item);
}

static pool_item_t *allocUdpPayloadPoolHandle(generic_pool_t *pool)
{
    discard pool;
    return memoryAllocate(sizeof(udp_payload_t));
}

static void destroyUdpPayloadPoolHandle(generic_pool_t *pool, pool_item_t *item)
{
    discard pool;
    memoryFree(item);
}

void socketacceptresultDestroy(socket_accept_result_t *sar)
{
    const wid_t wid = sar->wid;

    mutexLock(&(state->tcp_pools[wid].mutex));
    genericpoolReuseItem(state->tcp_pools[wid].pool, sar);
    mutexUnlock(&(state->tcp_pools[wid].mutex));
}

static udp_payload_t *newUdpPayload(wid_t wid)
{
    mutexLock(&(state->udp_pools[wid].mutex));
    udp_payload_t *item = genericpoolGetItem(state->udp_pools[wid].pool);
    mutexUnlock(&(state->udp_pools[wid].mutex));
    return item;
}

void udppayloadDestroy(udp_payload_t *upl)
{
    const wid_t wid = upl->wid;

    mutexLock(&(state->udp_pools[wid].mutex));
    genericpoolReuseItem(state->udp_pools[wid].pool, upl);
    mutexUnlock(&(state->udp_pools[wid].mutex));
}

static bool executeIptablesRule(const char *protocol, unsigned int port_min, unsigned int port_max,
                                unsigned int to_port)
{
    char command[256];
    bool result = true;

    if (port_min == port_max)
    {
        sprintf(command, "iptables -t nat -A PREROUTING -p %s --dport %u -j REDIRECT --to-port %u", protocol, port_min,
                to_port);
    }
    else
    {
        sprintf(command, "iptables -t nat -A PREROUTING -p %s --dport %u:%u -j REDIRECT --to-port %u", protocol,
                port_min, port_max, to_port);
    }
    result = execCmd(command).exit_code == 0;

#if SUPPORT_V6
    if (port_min == port_max)
    {
        sprintf(command, "ip6tables -t nat -A PREROUTING -p %s --dport %u -j REDIRECT --to-port %u", protocol, port_min,
                to_port);
    }
    else
    {
        sprintf(command, "ip6tables -t nat -A PREROUTING -p %s --dport %u:%u -j REDIRECT --to-port %u", protocol,
                port_min, port_max, to_port);
    }
    result = result && execCmd(command).exit_code == 0;
#endif
    return result;
}

static bool redirectPortRangeTcp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    return executeIptablesRule("TCP", pmin, pmax, to);
}

static bool redirectPortRangeUdp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    return executeIptablesRule("UDP", pmin, pmax, to);
}

static bool redirectPortTcp(unsigned int port, unsigned int to)
{
    return executeIptablesRule("TCP", port, port, to);
}

static bool redirectPortUdp(unsigned int port, unsigned int to)
{
    return executeIptablesRule("UDP", port, port, to);
}

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
    result = result && execCmd("ip6tables -t nat -F").exit_code == 0;
    result = result && execCmd("ip6tables -t nat -X").exit_code == 0;
#endif

    return result;
}

static inline bool needsV4SocketStrategy(const ip6_addr_t addr)
{
    uint16_t segments[8];
    memoryCopy(segments, addr.addr, sizeof(segments));
    return (segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 &&
            segments[5] == 0xFFFF);
}

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

static idle_table_t *getOrCreateBalanceTable(const char *balance_group_name)
{
    hash_t         name_hash = calcHashBytes(balance_group_name, stringLength(balance_group_name));
    idle_table_t *b_table   = NULL;

    mutexLock(&(state->mutex));

    balancegroup_registry_t_iter find_result = balancegroup_registry_t_find(&(state->balance_groups), name_hash);

    if (find_result.ref == balancegroup_registry_t_end(&(state->balance_groups)).ref)
    {
        b_table = idleTableCreate(state->worker->loop);
        balancegroup_registry_t_insert(&(state->balance_groups), name_hash, b_table);
    }
    else
    {
        b_table = (find_result.ref->second);
    }

    mutexUnlock(&(state->mutex));

    return b_table;
}

void socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{
    if (state->started)
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

    mutexLock(&(state->mutex));
    filters_t_push(&(state->filters[priority]), filter);
    mutexUnlock(&(state->mutex));
}

static void distributeSocket(void *io, socket_filter_t *filter, uint16_t local_port)
{
    wioDetach(io);

    wid_t wid = getNextDistributionWID();

    mutexLock(&(state->tcp_pools[wid].mutex));
    socket_accept_result_t *result = genericpoolGetItem(state->tcp_pools[wid].pool);
    mutexUnlock(&(state->tcp_pools[wid].mutex));

    *result = (socket_accept_result_t) {
        .io             = io,
        .tunnel         = filter->tunnel,
        .real_localport = local_port,
        .wid            = wid,
    };

    wloop_t *worker_loop = getWorkerLoop(wid);
    wevent_t ev          = (wevent_t) {.loop = worker_loop, .cb = filter->cb};

    ev.userdata = result;

    if (wid == state->wid)
    {
        filter->cb(&ev);
    }
    else
    {
        wloopPostEvent(worker_loop, &ev);
    }
}

static void noTcpSocketConsumerFound(wio_t *io)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGE("SocketManager: could not find consumer for Tcp socket FD:%x [%s] <= [%s]", wioGetFD(io),
         SOCKADDR_STR(wioGetLocaladdrU(io), localaddrstr), SOCKADDR_STR(wioGetPeerAddrU(io), peeraddrstr));
    wioClose(io);
}

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

    idle_item_t *idle_item = idletableGetIdleItemByHash(state->wid, option.shared_balance_table, *src_hash);

    if (idle_item)
    {
        socket_filter_t *target_filter = idle_item->userdata;
        idletableKeepIdleItemForAtleast(option.shared_balance_table, idle_item,
                                        option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                           : option.balance_group_interval);
        if (option.no_delay)
        {
            tcpNoDelay(wioGetFD(io), 1);
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

static void finalizeTcpDistribution(socket_filter_t **balance_selection_filters,
                                    uint8_t balance_selection_filters_length, wio_t *io, uint16_t local_port,
                                    hash_t src_hash)
{
    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        idletableCreateItem(filter->option.shared_balance_table, src_hash, filter, NULL, state->wid,
                            filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                       : filter->option.balance_group_interval);
        if (filter->option.no_delay)
        {
            tcpNoDelay(wioGetFD(io), 1);
        }
        distributeSocket(io, filter, local_port);
    }
    else
    {
        noTcpSocketConsumerFound(io);
    }
}

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
    return true;
}

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
        c_foreach(k, filters_t, state->filters[ri])
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
                if (option.no_delay)
                {
                    tcpNoDelay(wioGetFD(io), 1);
                }
                distributeSocket(io, filter, local_port);
                return;
            }
        }
    }

    finalizeTcpDistribution(balance_selection_filters, balance_selection_filters_length, io, local_port, src_hash);
}

static void onAcceptTcpSinglePort(wio_t *io)
{
    distributeTcpSocket(io, sockaddrPort(wioGetLocaladdrU(io)));
}

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

static multiport_backend_t getDefaultMultiPortBackend(void)
{
    if (state->iptables_installed)
    {
        return kMultiportBackendIptables;
    }
    return kMultiportBackendSockets;
}

static bool getInterfaceHostString(const char *interface, char *host_if)
{
    ip4_addr_t if_ip;
    if (! getInterfaceIp(interface, &if_ip, stringLength(interface)))
    {
        LOGF("SocketManager: Could not get interface \"%s\" ip", interface);
        terminateProgram(1);
        return false;
    }
    ip4AddrAddressToNetwork(host_if, &if_ip);
    return true;
}

static wio_t *createTcpServerWithInterface(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                           void (*callback)(wio_t *))
{
    if (filter->option.interface != NULL)
    {
        char host_if[60] = {0};
        getInterfaceHostString(filter->option.interface, host_if);
        return wloopCreateTcpServer(loop, host_if, port, callback);
    }
    return wloopCreateTcpServer(loop, host, port, callback);
}

static uint16_t selectMainPortForIptables(socket_filter_t *filter, wloop_t *loop, char *host, uint16_t port_min,
                                          uint16_t port_max, uint8_t *ports_overlapped)
{
    uint16_t main_port = port_max;

    do
    {
        if (ports_overlapped[main_port] != 1)
        {
            filter->listen_io = createTcpServerWithInterface(loop, filter, host, main_port, onAcceptTcpMultiPort);
            ports_overlapped[main_port] = 1;

            if (filter->listen_io != NULL)
            {
                filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;
                break;
            }
            main_port--;
        }
    } while (main_port >= port_min);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        terminateProgram(1);
    }

    return main_port;
}

static void initializeIptablesIfNeeded(void)
{
    if (! state->iptables_installed)
    {
        LOGF("SocketManager: multi port backend \"iptables\" colud not start, error: not installed");
        terminateProgram(1);
    }

    state->iptables_used = true;
    if (! state->iptable_cleaned)
    {
        if (! resetIptables(false))
        {
            LOGF("SocketManager: could not clear iptables rules");
            terminateProgram(1);
        }
        state->iptable_cleaned = true;
    }
}

static void listenTcpMultiPortIptables(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                       uint8_t *ports_overlapped, uint16_t port_max)
{
    initializeIptablesIfNeeded();

    uint16_t main_port = selectMainPortForIptables(filter, loop, host, port_min, port_max, ports_overlapped);

    redirectPortRangeTcp(port_min, port_max, main_port);
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "TCP");
}

static void listenTcpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      uint8_t *ports_overlapped, uint16_t port_max)
{
    const int length           = (port_max - port_min);
    filter->listen_ios         = (wio_t **) memoryAllocate(sizeof(wio_t *) * ((size_t) length + 1));
    filter->listen_ios[length] = 0x0;
    int i                      = 0;

    for (uint16_t p = port_min; p < port_max; p++)
    {
        if (ports_overlapped[p] == 1)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        ports_overlapped[p] = 1;

        filter->listen_ios[i] = createTcpServerWithInterface(loop, filter, host, p, onAcceptTcpSinglePort);

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

static void listenTcpSinglePort(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                uint8_t *ports_overlapped)
{
    if (ports_overlapped[port] == 1)
    {
        return;
    }
    ports_overlapped[port] = 1;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "TCP");

    filter->listen_io = createTcpServerWithInterface(loop, filter, host, port, onAcceptTcpSinglePort);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        terminateProgram(1);
    }
    filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;
}

static void listenTcp(wloop_t *loop, uint8_t *ports_overlapped)
{
    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
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

static void noUdpSocketConsumerFound(const udp_payload_t upl)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};
    LOGE("SocketManager: could not find consumer for Udp socket  [%s] <= [%s]",
         SOCKADDR_STR(wioGetLocaladdrU(upl.sock->io), localaddrstr),
         SOCKADDR_STR(wioGetPeerAddrU(upl.sock->io), peeraddrstr));
}

static void postUdpPayload(udp_payload_t post_pl, socket_filter_t *filter)
{
    mutexLock(&(state->udp_pools[post_pl.wid].mutex));
    udp_payload_t *pl = genericpoolGetItem(state->udp_pools[post_pl.wid].pool);
    mutexUnlock(&(state->udp_pools[post_pl.wid].mutex));
    *pl = post_pl;

    pl->tunnel           = filter->tunnel;
    wloop_t *worker_loop = getWorkerLoop(pl->wid);
    wevent_t ev          = (wevent_t) {.loop = worker_loop, .cb = filter->cb};
    ev.userdata          = (void *) pl;

    if (pl->wid == state->wid)
    {
        filter->cb(&ev);
        return;
    }
    wloopPostEvent(worker_loop, &ev);
}

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
    return true;
}

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
        sockaddrToIpAddr(wioGetPeerAddrU(pl.sock->io), &paddr);
        *src_hash   = ipaddrCalcHashNoPort(paddr);
        *src_hashed = true;
    }

    idle_item_t *idle_item = idletableGetIdleItemByHash(state->wid, option.shared_balance_table, *src_hash);

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

static void finalizeUdpDistribution(socket_filter_t **balance_selection_filters,
                                    uint8_t balance_selection_filters_length, const udp_payload_t pl, hash_t src_hash)
{
    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        idletableCreateItem(filter->option.shared_balance_table, src_hash, filter, NULL, state->wid,
                            filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                       : filter->option.balance_group_interval);
        postUdpPayload(pl, filter);
    }
    else
    {
        noUdpSocketConsumerFound(pl);
    }
}

static void distributeUdpPayload(const udp_payload_t pl)
{
    ip_addr_t paddr;
    sockaddrToIpAddr(wioGetPeerAddrU(pl.sock->io), &paddr);

    uint16_t local_port = pl.real_localport;

    static socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t                 balance_selection_filters_length = 0;
    idle_table_t          *selected_balance_table           = NULL;
    hash_t                  src_hash                         = 0x0;
    bool                    src_hashed                       = false;

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
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

static void onUdpPacketReceived(wio_t *io, sbuf_t *buf)
{
    udpsock_t *socket      = weventGetUserdata(io);
    uint16_t   local_port  = sockaddrPort(wioGetLocaladdrU(io));
    uint16_t   remote_port = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid  = (wid_t) remote_port % (getWorkersCount() - WORKER_ADDITIONS);

    if (GSTATE.application_stopping_flag)
    {
        sbufDestroy(buf);
        return;
    }

    udp_payload_t item = (udp_payload_t) {
        .sock = socket, .buf = buf, .wid = target_wid, .peer_addr = *wioGetPeerAddrU(io), .real_localport = local_port};

    distributeUdpPayload(item);
}

// sad: this dose not work (getsockopt fails)
static void onUdpPacketReceivedMultiPort(wio_t *io, sbuf_t *buf)
{

#ifdef OS_UNIX
    udpsock_t *socket      = weventGetUserdata(io);
    uint16_t   remote_port = sockaddrPort(wioGetPeerAddrU(io));
    wid_t      target_wid  = (wid_t) remote_port % (getWorkersCount() - WORKER_ADDITIONS);
    uint16_t   real_local_port = sockaddrPort(wioGetLocaladdrU(io)); // default fallback

    if (GSTATE.application_stopping_flag)
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

static void listenUdpSinglePort(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                uint8_t *ports_overlapped)
{
    if (ports_overlapped[port] == 1)
    {
        return;
    }
    ports_overlapped[port] = 1;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "UDP");
    filter->listen_io = wloopCreateUdpServer(loop, host, port);

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

static void listenUdpMultiPortIptables(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                       uint8_t *ports_overlapped, uint16_t port_max)
{
    initializeIptablesIfNeeded();

    // Find an available port for the main UDP socket
    uint16_t main_port = port_max;
    
    do
    {
        if (ports_overlapped[main_port] != 1)
        {
            filter->listen_io = wloopCreateUdpServer(loop, host, main_port);
            ports_overlapped[main_port] = 1;

            if (filter->listen_io != NULL)
            {
                break;
            }
            main_port--;
        }
        else
        {
            main_port--;
        }
    } while (main_port >= port_min);

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
    redirectPortRangeUdp(port_min, port_max, main_port);
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "UDP");
}

static void listenUdpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      uint8_t *ports_overlapped, uint16_t port_max)
{
    const int length           = (port_max - port_min);
    filter->listen_ios         = (wio_t **) memoryAllocate(sizeof(wio_t *) * ((size_t) length + 1));
    filter->listen_ios[length] = 0x0;
    int i                      = 0;

    for (uint16_t p = port_min; p < port_max; p++)
    {
        if (ports_overlapped[p] == 1)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p);
            continue;
        }
        ports_overlapped[p] = 1;

        wio_t *udp_io = wloopCreateUdpServer(loop, host, p);
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

static void listenUdp(wloop_t *loop, uint8_t *ports_overlapped)
{
    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
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
    if (wid_from == state->wid)
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
    return state;
}

void socketmanagerSet(struct socket_manager_s *new_state)
{
    assert(state == NULL);
    state = new_state;
}

void socketmanagerStart(void)
{
    assert(state != NULL);

    assert(state && state->worker->loop && ! state->started);

    mutexLock(&(state->mutex));

    {
        uint8_t ports_overlapped[65536] = {0};
        listenTcp(state->worker->loop, ports_overlapped);
    }
    {
        uint8_t ports_overlapped[65536] = {0};
        listenUdp(state->worker->loop, ports_overlapped);
    }
    state->started = true;
    mutexUnlock(&(state->mutex));
}

static void initializeSocketManagerPools(void)
{
    state->udp_pools = memoryAllocate(sizeof(*state->udp_pools) * getWorkersCount());
    memorySet(state->udp_pools, 0, sizeof(*state->udp_pools) * getWorkersCount());

    state->tcp_pools = memoryAllocate(sizeof(*state->tcp_pools) * getWorkersCount());
    memorySet(state->tcp_pools, 0, sizeof(*state->tcp_pools) * getWorkersCount());

    state->mp_udp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    state->mp_tcp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));

    for (unsigned int i = 0; i < getWorkersCount(); ++i)
    {
        state->udp_pools[i].pool = genericpoolCreateWithCapacity(
            state->mp_udp, (8) + RAM_PROFILE, allocUdpPayloadPoolHandle, destroyUdpPayloadPoolHandle);
        mutexInit(&(state->udp_pools[i].mutex));

        state->tcp_pools[i].pool = genericpoolCreateWithCapacity(
            state->mp_tcp, (8) + RAM_PROFILE, allocTcpResultObjectPoolHandle, destroyTcpResultObjectPoolHandle);
        mutexInit(&(state->tcp_pools[i].mutex));

#ifdef DEBUG
        state->udp_pools[i].pool->no_thread_check = true;
        state->tcp_pools[i].pool->no_thread_check = true;
#endif
    }
}

static void detectSystemCapabilities(void)
{
#ifdef OS_UNIX
    state->iptables_installed = checkCommandAvailable("iptables");
    state->lsof_installed     = checkCommandAvailable("lsof");
#if SUPPORT_V6
    state->ip6tables_installed = checkCommandAvailable("ip6tables");
#endif
#endif
}

socket_manager_state_t *socketmanagerCreate(void)
{
    assert(state == NULL);
    state = memoryAllocate(sizeof(socket_manager_state_t));
    memorySet(state, 0, sizeof(socket_manager_state_t));

    assert(getWID() == 0);
    state->worker = getWorker(0);
    state->wid    = 0;

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        state->filters[i] = filters_t_init();
    }

    mutexInit(&state->mutex);
    initializeSocketManagerPools();
    detectSystemCapabilities();

    return state;
}

static void cleanupFilters(void)
{
    for (size_t i = 0; i < kFilterLevels; i++)
    {
        // c_foreach(filter, filters_t, state->filters[i])
        // {
        //     if ((*filter.ref)->listen_ios != NULL)
        //     {
        //         int    ios_i = 0;
        //         wio_t *io    = (*filter.ref)->listen_ios[ios_i++];
        //         while (io != NULL)
        //         {
        //             wioClose(io);
        //             io = (*filter.ref)->listen_ios[ios_i++];
        //         }
        //         memoryFree((void *) (*filter.ref)->listen_ios);
        //     }
        //     else
        //     {
        //         wioClose((*filter.ref)->listen_io);
        //     }
        //     socketfilteroptionDeInit(&((*filter.ref)->option));
        //     memoryFree(*filter.ref);
        // }
        filters_t_drop(&(state->filters[i]));
    }
}

static void destroyPools(void)
{
    for (unsigned int i = 0; i < getWorkersCount(); ++i)
    {
        mutexDestroy(&(state->udp_pools[i].mutex));
        genericpoolDestroy(state->udp_pools[i].pool);
        mutexDestroy(&(state->tcp_pools[i].mutex));
        genericpoolDestroy(state->tcp_pools[i].pool);
    }

    memoryFree(state->udp_pools);
    memoryFree(state->tcp_pools);
    masterpoolDestroy(state->mp_tcp);
    masterpoolDestroy(state->mp_udp);
}

void socketmanagerDestroy(void)
{
    assert(state != NULL);

    if (state->iptables_used)
    {
        resetIptables(true);
    }

    cleanupFilters();
    destroyPools();
    memoryFree(state);
    state = NULL;
}
