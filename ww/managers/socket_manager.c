#include "socket_manager.h"

#include "generic_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "signal_manager.h"
#include "stc/common.h"
#include "tunnel.h"
#include "widle_table.h"
#include "wloop.h"
#include "wmutex.h"
#include "wproc.h"

#define i_type balancegroup_registry_t // NOLINT
#define i_key  hash_t                  // NOLINT
#define i_val  widle_table_t *         // NOLINT

#include "stc/hmap.h"

typedef struct socket_filter_s
{
    union {
        wio_t  *listen_io;
        wio_t **listen_ios;
    };
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

    wmutex_t                mutex;
    balancegroup_registry_t balance_groups;
    worker_t               *worker;
    wid_t                   wid;

    wid_t last_round_wid;
    bool  iptables_installed;
    bool  ip6tables_installed;
    bool  lsof_installed;
    bool  iptable_cleaned;
    bool  iptables_used;
    bool  started;

} socket_manager_state_t;

static socket_manager_state_t *state = NULL;

static pool_item_t *allocTcpResultObjectPoolHandle(generic_pool_t *pool)
{
    (void) pool;
    return memoryAllocate(sizeof(socket_accept_result_t));
}

static void destroyTcpResultObjectPoolHandle(generic_pool_t *pool, pool_item_t *item)
{
    (void) pool;
    memoryFree(item);
}

static pool_item_t *allocUdpPayloadPoolHandle(generic_pool_t *pool)
{
    (void) pool;
    return memoryAllocate(sizeof(udp_payload_t));
}

static void destroyUdpPayloadPoolHandle(generic_pool_t *pool, pool_item_t *item)
{
    (void) pool;
    memoryFree(item);
}

void socketacceptresultDestroy(socket_accept_result_t *sar)
{
    const wid_t wid = sar->wid;

    mutexLock(&(state->tcp_pools[wid].mutex));
    genericpoolReuseItem(state->tcp_pools[wid].pool, sar);
    mutexUnlock(&(state->tcp_pools[wid].mutex));
}

static udp_payload_t *newUpdPayload(wid_t wid)
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

static bool redirectPortRangeTcp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    char b[256];
    bool result = true;
    sprintf(b, "iptables -t nat -A PREROUTING -p TCP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    result = result && execCmd(b).exit_code == 0;
#if SUPPORT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p TCP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    result = result && execCmd(b).exit_code == 0;
#endif
    return result;
}

static bool redirectPortRangeUdp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    char b[256];
    bool result = true;
    sprintf(b, "iptables -t nat -A PREROUTING -p UDP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    result = result && execCmd(b).exit_code == 0;
#if SUPPORT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p UDP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    result = result && execCmd(b).exit_code == 0;
#endif
    return result;
}

static bool redirectPortTcp(unsigned int port, unsigned int to)
{
    char b[256];
    bool result = true;
    sprintf(b, "iptables -t nat -A PREROUTING -p TCP --dport %u -j REDIRECT --to-port %u", port, to);
    result = result && execCmd(b).exit_code == 0;
#if SUPPORT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p TCP --dport %u -j REDIRECT --to-port %u", port, to);
    result = result && execCmd(b).exit_code == 0;
#endif
    return result;
}

static bool redirectPortUdp(unsigned int port, unsigned int to)
{
    char b[256];
    bool result = true;
    sprintf(b, "iptables -t nat -A PREROUTING -p UDP --dport %u -j REDIRECT --to-port %u", port, to);
    result = result && execCmd(b).exit_code == 0;
#if SUPPORT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p UDP --dport %u -j REDIRECT --to-port %u", port, to);
    result = result && execCmd(b).exit_code == 0;
#endif
    return result;
}

static bool resetIptables(bool safe_mode)
{

    if (safe_mode)
    {
        char    msg[] = "SocketManager: clearing iptables nat rules\n";
        ssize_t _     = write(STDOUT_FILENO, msg, sizeof(msg));
        (void) _;
    }
    else
    {
        char msg[] = "SocketManager: clearing iptables nat rules";
        LOGD(msg);
    }
    bool result = true;

    // todo (async unsafe) this works but should be replaced with a asyncsafe execcmd function
    // probably do it with fork?
    result = result && execCmd("iptables -t nat -F").exit_code == 0;
    result = result && execCmd("iptables -t nat -X").exit_code == 0;
#if SUPPORT_V6
    result = result && execCmd("ip6tables -t nat -F").exit_code == 0;
    result = result && execCmd("ip6tables -t nat -X").exit_code == 0;
#endif

    return result;
}

static void exitHook(void *userdata, int _)
{
    (void) (userdata);
    (void) _;
    if (state->iptables_used)
    {
        resetIptables(true);
    }
}

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a)                                                                                        \
    ((((a)->s6_words[0]) == 0) && (((a)->s6_words[1]) == 0) && (((a)->s6_words[2]) == 0) &&                            \
     (((a)->s6_words[3]) == 0) && (((a)->s6_words[4]) == 0) && (((a)->s6_words[5]) == 0xFFFF))
#endif

static inline bool needsV4SocketStrategy(sockaddr_u *peer_addr)
{
    bool use_v4_strategy;
    if (peer_addr->sa.sa_family == AF_INET)
    {
        use_v4_strategy = true;
    }
    else
    {
        if (IN6_IS_ADDR_V4MAPPED(&(peer_addr->sin6.sin6_addr)))
        {
            use_v4_strategy = true;
        }
        else
        {
            use_v4_strategy = false;
        }
    }
    return use_v4_strategy;
}

static void parseWhiteListOption(socket_filter_option_t *option)
{
    assert(option->white_list_raddr != NULL);

    int   len = 0;
    char *cur = NULL;

    cur = option->white_list_raddr[len];
    while (cur != NULL)
    {
        len++;
        cur = option->white_list_raddr[len];
    }

    option->white_list_parsed_length = len;
    option->white_list_parsed        = memoryAllocate(sizeof(option->white_list_parsed[0]) * len);
    for (int i = 0; i < len; i++)
    {
        cur              = option->white_list_raddr[i];
        int parse_result = parseIPWithSubnetMask(&(option->white_list_parsed[i].ip_bytes_buf), cur,
                                                 &(option->white_list_parsed[i].mask_bytes_buf));

        if (parse_result == -1)
        {
            LOGF("SocketManager: stopping due to whitelist address [%d] \"%s\" parse failure", i, cur);
            exit(1);
        }
    }
}

void socketacceptorRegister(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{
    if (state->started)
    {
        LOGF("SocketManager: cannot register after accept thread starts");
        exit(1);
    }
    socket_filter_t *filter   = memoryAllocate(sizeof(socket_filter_t));
    unsigned int     pirority = 0;
    if (option.multiport_backend == kMultiportBackendNone)
    {
        pirority++;
    }
    if (option.white_list_raddr != NULL)
    {
        pirority++;
        parseWhiteListOption(&option);
    }

    if (option.black_list_raddr != NULL)
    {
        pirority++;
    }

    if (option.balance_group_name)
    {
        hash_t         name_hash = calcHashBytes(option.balance_group_name, strlen(option.balance_group_name));
        widle_table_t *b_table   = NULL;
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

        option.shared_balance_table = b_table;
    }

    *filter = (socket_filter_t){.tunnel = tunnel, .option = option, .cb = cb, .listen_io = NULL};

    mutexLock(&(state->mutex));
    filters_t_push(&(state->filters[pirority]), filter);
    mutexUnlock(&(state->mutex));
}

static inline uint16_t getCurrentDistributeTid(void)
{
    return state->last_round_wid;
}

static inline void incrementDistributeTid(void)
{
    state->last_round_wid++;
    if (state->last_round_wid >= getWorkersCount())
    {
        state->last_round_wid = 0;
    }
}

static void distributeSocket(void *io, socket_filter_t *filter, uint16_t local_port)
{

    wid_t wid = (uint8_t) getCurrentDistributeTid();

    mutexLock(&(state->tcp_pools[wid].mutex));
    socket_accept_result_t *result = genericpoolGetItem(state->tcp_pools[wid].pool);
    mutexUnlock(&(state->tcp_pools[wid].mutex));

    result->real_localport = local_port;

    wloop_t *worker_loop = getWorkerLoop(wid);
    wevent_t ev          = (wevent_t){.loop = worker_loop, .cb = filter->cb};
    result->wid          = wid;
    result->io           = io;
    result->tunnel       = filter->tunnel;
    ev.userdata          = result;
    incrementDistributeTid();

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

static bool checkIpIsWhiteList(sockaddr_u *addr, const socket_filter_option_t option)
{
    const bool     is_v4 = addr->sa.sa_family == AF_INET;
    struct in_addr ipv4_addr;

    if (is_v4)
    {
        ipv4_addr = addr->sin.sin_addr;
    v4checks:
        for (unsigned int i = 0; i < option.white_list_parsed_length; i++)
        {

            if (checkIPRange4(ipv4_addr, *(struct in_addr *) &(option.white_list_parsed[i].ip_bytes_buf),
                              *(struct in_addr *) &(option.white_list_parsed[i].mask_bytes_buf)))
            {
                return true;
            }
        }
    }
    else
    {
        if (needsV4SocketStrategy(addr))
        {
            memoryCopy(&ipv4_addr, &(addr->sin6.sin6_addr.s6_addr[12]), sizeof(ipv4_addr));
            goto v4checks;
        }

        for (unsigned int i = 0; i < option.white_list_parsed_length; i++)
        {

            if (checkIPRange6(addr->sin6.sin6_addr, option.white_list_parsed[i].ip_bytes_buf,
                              option.white_list_parsed[i].mask_bytes_buf))
            {
                return true;
            }
        }
    }

    return false;
}

static void distributeTcpSocket(wio_t *io, uint16_t local_port)
{
    sockaddr_u *paddr = (sockaddr_u *) wioGetPeerAddrU(io);

    static socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t                 balance_selection_filters_length = 0;
    widle_table_t          *selected_balance_table           = NULL;
    hash_t                  src_hash                         = 0x0;
    bool                    src_hashed                       = false;
    const uint8_t           this_wid                         = state->wid;

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
        {
            socket_filter_t       *filter   = *(k.ref);
            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;

            if (selected_balance_table != NULL && option.shared_balance_table != selected_balance_table)
            {
                continue;
            }

            if (option.protocol != kSapTcp || port_min > local_port || port_max < local_port)
            {
                continue;
            }

            if (option.white_list_raddr != NULL)
            {
                if (! checkIpIsWhiteList(paddr, option))
                {
                    continue;
                }
            }

            if (option.shared_balance_table)
            {
                if (! src_hashed)
                {
                    src_hash = sockaddrCalcHashNoPort((sockaddr_u *) wioGetPeerAddrU(io));
                }
                idle_item_t *idle_item = idleTableGetIdleItemByHash(this_wid, option.shared_balance_table, src_hash);

                if (idle_item)
                {
                    socket_filter_t *target_filter = idle_item->userdata;
                    idleTableKeepIdleItemForAtleast(option.shared_balance_table, idle_item,
                                                    option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                                       : option.balance_group_interval);
                    if (option.no_delay)
                    {
                        tcpNoDelay(wioGetFD(io), 1);
                    }
                    wioDetach(io);
                    distributeSocket(io, target_filter, local_port);
                    return;
                }

                if (UNLIKELY(balance_selection_filters_length >= kMaxBalanceSelections))
                {
                    // probably never but the limit can be simply increased
                    LOGW("SocketManager: balance between more than %d tunnels is not supported", kMaxBalanceSelections);
                    continue;
                }
                balance_selection_filters[balance_selection_filters_length++] = filter;
                selected_balance_table                                        = option.shared_balance_table;
                continue;
            }

            if (option.no_delay)
            {
                tcpNoDelay(wioGetFD(io), 1);
            }
            wioDetach(io);
            distributeSocket(io, filter, local_port);
            return;
        }
    }

    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        idleItemNew(filter->option.shared_balance_table, src_hash, filter, NULL, this_wid,
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

static void onAcceptTcpSinglePort(wio_t *io)
{
    distributeTcpSocket(io, sockaddrPort((sockaddr_u *) wioGetLocaladdrU(io)));
}

static void onAcceptTcpMultiPort(wio_t *io)
{
#ifdef OS_UNIX

    bool          use_v4_strategy = needsV4SocketStrategy((sockaddr_u *) wioGetPeerAddrU(io));
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

    distributeTcpSocket(io, (pbuf[2] << 8) | pbuf[3]);
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

static void listenTcpMultiPortIptables(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                       uint8_t *ports_overlapped, uint16_t port_max)
{
    if (! state->iptables_installed)
    {
        LOGF("SocketManager: multi port backend \"iptables\" colud not start, error: not installed");
        exit(1);
    }
    state->iptables_used = true;
    if (! state->iptable_cleaned)
    {
        if (! resetIptables(false))
        {
            LOGF("SocketManager: could not clear iptables rules");
            exit(1);
        }
        state->iptable_cleaned = true;
    }
    uint16_t main_port = port_max;
    // select main port
    {
        do
        {
            if (ports_overlapped[main_port] != 1)
            {
                filter->listen_io           = wloopCreateTcpServer(loop, host, main_port, onAcceptTcpMultiPort);
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
            exit(1);
        }
    }
    redirectPortRangeTcp(port_min, port_max, main_port);
    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", host, port_min, port_max, main_port, "TCP");
}

static void listenTcpMultiPortSockets(wloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      uint8_t *ports_overlapped, uint16_t port_max)
{
    const int length           = (port_max - port_min);
    filter->listen_ios         = (wio_t **) memoryAllocate(sizeof(wio_t *) * (length + 1));
    filter->listen_ios[length] = 0x0;
    int i                      = 0;
    for (uint16_t p = port_min; p < port_max; p++)
    {
        if (ports_overlapped[p] == 1)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p, "TCP");
            continue;
        }
        ports_overlapped[p] = 1;

        filter->listen_ios[i] = wloopCreateTcpServer(loop, host, p, onAcceptTcpSinglePort);

        if (filter->listen_ios[i] == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p, "TCP");
            continue;
        }
        filter->v6_dualstack = wioGetLocaladdr(filter->listen_io)->sa_family == AF_INET6;

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
    filter->listen_io = wloopCreateTcpServer(loop, host, port, onAcceptTcpSinglePort);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        exit(1);
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
            }

            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;
            if (port_min > port_max)
            {
                LOGF("SocketManager: port min must be lower than port max");
                exit(1);
            }
            else if (port_min == port_max)
            {
                option.multiport_backend = kMultiportBackendNone;
            }
            if (option.protocol == kSapTcp)
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

static void postPayload(udp_payload_t post_pl, socket_filter_t *filter)
{

    mutexLock(&(state->udp_pools[post_pl.wid].mutex));
    udp_payload_t *pl = genericpoolGetItem(state->udp_pools[post_pl.wid].pool);
    mutexUnlock(&(state->udp_pools[post_pl.wid].mutex));
    *pl = post_pl;

    pl->tunnel           = filter->tunnel;
    wloop_t *worker_loop = getWorkerLoop(pl->wid);
    wevent_t ev          = (wevent_t){.loop = worker_loop, .cb = filter->cb};
    ev.userdata          = (void *) pl;

    if(pl->wid == state->wid)
    {
        filter->cb(&ev);
        return;
    }
    wloopPostEvent(worker_loop, &ev);
}

static void distributeUdpPayload(const udp_payload_t pl)
{
    // mutexLock(&(state->mutex)); new socket manager will not lock here
    sockaddr_u *paddr      = (sockaddr_u *) wioGetPeerAddrU(pl.sock->io);
    uint16_t    local_port = pl.real_localport;

    static socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t                 balance_selection_filters_length = 0;
    widle_table_t          *selected_balance_table           = NULL;
    hash_t                  src_hash                         = 0x0;
    bool                    src_hashed                       = false;
    const uint8_t           this_wid                         = state->wid;

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
        {

            socket_filter_t       *filter   = *(k.ref);
            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;

            if (selected_balance_table != NULL && option.shared_balance_table != selected_balance_table)
            {
                continue;
            }

            if (option.protocol != kSapUdp || port_min > local_port || port_max < local_port)
            {
                continue;
            }
            if (option.white_list_raddr != NULL)
            {
                if (! checkIpIsWhiteList(paddr, option))
                {
                    continue;
                }
            }
            if (option.shared_balance_table)
            {
                if (! src_hashed)
                {
                    src_hash = sockaddrCalcHashNoPort((sockaddr_u *) wioGetPeerAddrU(pl.sock->io));
                }
                idle_item_t *idle_item = idleTableGetIdleItemByHash(this_wid, option.shared_balance_table, src_hash);

                if (idle_item)
                {
                    socket_filter_t *target_filter = idle_item->userdata;
                    idleTableKeepIdleItemForAtleast(option.shared_balance_table, idle_item,
                                                    option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                                                       : option.balance_group_interval);
                    postPayload(pl, target_filter);
                    return;
                }

                if (UNLIKELY(balance_selection_filters_length >= kMaxBalanceSelections))
                {
                    // probably never but the limit can be simply increased
                    LOGW("SocketManager: balance between more than %d tunnels is not supported", kMaxBalanceSelections);
                    continue;
                }
                balance_selection_filters[balance_selection_filters_length++] = filter;
                selected_balance_table                                        = option.shared_balance_table;
                continue;
            }

            postPayload(pl, filter);
            return;
        }
    }
    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        idleItemNew(filter->option.shared_balance_table, src_hash, filter, NULL, this_wid,
                    filter->option.balance_group_interval == 0 ? kDefaultBalanceInterval
                                                               : filter->option.balance_group_interval);
        postPayload(pl, filter);
    }
    else
    {
        noUdpSocketConsumerFound(pl);
    }
}

static void onRecvFrom(wio_t *io, sbuf_t *buf)
{
    udpsock_t *socket     = weventGetUserdata(io);
    uint16_t   local_port = sockaddrPort((sockaddr_u *) wioGetLocaladdrU(io));
    uint8_t    target_wid = local_port % getWorkersCount();

    udp_payload_t item = (udp_payload_t){.sock           = socket,
                                         .buf            = buf,
                                         .wid            = target_wid,
                                         .peer_addr      = *(sockaddr_u *) wioGetPeerAddrU(io),
                                         .real_localport = local_port};

    distributeUdpPayload(item);
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
        exit(1);
    }
    udpsock_t *socket = memoryAllocate(sizeof(udpsock_t));
    *socket           = (udpsock_t){.io = filter->listen_io, .table = idleTableCreate(loop)};
    weventSetUserData(filter->listen_io, socket);
    wioSetCallBackRead(filter->listen_io, onRecvFrom);
    wioRead(filter->listen_io);
}

// todo (udp manager)
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
                exit(1);
            }
            else if (port_min == port_max)
            {
                option.multiport_backend = kMultiportBackendNone;
            }
            if (option.protocol == kSapUdp)
            {
                if (option.multiport_backend == kMultiportBackendIptables)
                {
                    ;
                    // listenUdpMultiPortIptables(loop, filter, option.host, port_min, ports_overlapped, port_max);
                }
                else if (option.multiport_backend == kMultiportBackendSockets)
                {
                    // listenUdpMultiPortSockets(loop, filter, option.host, port_min, ports_overlapped, port_max);
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
    udp_payload_t *upl    = weventGetUserdata(ev);
    size_t         nwrite = wioWrite(upl->sock->io, upl->buf);
    (void) nwrite;
    udppayloadDestroy(upl);
}

void postUdpWrite(udpsock_t *socket_io, wid_t wid_from, sbuf_t *buf)
{
    if (wid_from == state->wid)
    {
        size_t nwrite = wioWrite(socket_io->io, buf);
        (void) nwrite;

        return;
    }

    udp_payload_t *item = newUpdPayload(wid_from);

    *item = (udp_payload_t){.sock = socket_io, .buf = buf, .wid = wid_from};

    wevent_t ev = (wevent_t){.loop = weventGetLoop(socket_io->io), .userdata = item, .cb = writeUdpThisLoop};

    wloopPostEvent(weventGetLoop(socket_io->io), &ev);
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

    frandInit();

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

socket_manager_state_t *socketmanagerCreate(void)
{
    assert(state == NULL);
    state = memoryAllocate(sizeof(socket_manager_state_t));
    memorySet(state, 0, sizeof(socket_manager_state_t));

    // worker_t *worker = memoryAllocate(sizeof(worker_t));

    // *worker = (worker_t){.wid = 255};

    // worker->buffer_pool = bufferpoolCreate(GSTATE.masterpool_buffer_pools_large,
    // GSTATE.masterpool_buffer_pools_small,
    //                                        GSTATE.ram_profile, SMALL_BUFFER_SIZE, LARGE_BUFFER_SIZE);

    // worker->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, worker->buffer_pool, worker->wid);

    // state->worker = worker;

    assert(getWID() == 0);
    state->worker = getWorker(0);
    state->wid    = 0;

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        state->filters[i] = filters_t_init();
    }

    mutexInit(&state->mutex);

    state->udp_pools = memoryAllocate(sizeof(*state->udp_pools) * getWorkersCount());
    memorySet(state->udp_pools, 0, sizeof(*state->udp_pools) * getWorkersCount());

    state->tcp_pools = memoryAllocate(sizeof(*state->tcp_pools) * getWorkersCount());
    memorySet(state->tcp_pools, 0, sizeof(*state->tcp_pools) * getWorkersCount());
    master_pool_t *mp_udp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    master_pool_t *mp_tcp = masterpoolCreateWithCapacity(2 * ((8) + RAM_PROFILE));
    for (unsigned int i = 0; i < getWorkersCount(); ++i)
    {

        state->udp_pools[i].pool = genericpoolCreateWithCapacity(mp_udp, (8) + RAM_PROFILE, allocUdpPayloadPoolHandle,
                                                                 destroyUdpPayloadPoolHandle);
        mutexInit(&(state->udp_pools[i].mutex));

        state->tcp_pools[i].pool = genericpoolCreateWithCapacity(
            mp_tcp, (8) + RAM_PROFILE, allocTcpResultObjectPoolHandle, destroyTcpResultObjectPoolHandle);
        mutexInit(&(state->tcp_pools[i].mutex));
    }

#ifdef OS_UNIX

    state->iptables_installed = checkCommandAvailable("iptables");
    state->lsof_installed     = checkCommandAvailable("lsof");
#if SUPPORT_V6
    state->ip6tables_installed = checkCommandAvailable("ip6tables");
#endif

#endif

    registerAtExitCallBack(exitHook, NULL);

    return state;
}

void socketmanagerDestroy(void)
{
    assert(state != NULL);

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        filters_t_drop(&(state->filters[i]));
    }
    memoryFree(state->filters);

    for (unsigned int i = 0; i < getWorkersCount(); ++i)
    {
        mutexDestroy(&(state->udp_pools[i].mutex));
        genericpoolDestroy(state->udp_pools[i].pool);
        mutexDestroy(&(state->tcp_pools[i].mutex));
        genericpoolDestroy(state->tcp_pools[i].pool);
    }

    memoryFree(state->udp_pools);
    memoryFree(state->tcp_pools);

    memoryFree(state);
    state = NULL;
}
