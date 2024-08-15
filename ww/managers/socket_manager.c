#include "socket_manager.h"
#include "basic_types.h"
#include "frand.h"
#include "generic_pool.h"
#include "hloop.h"
#include "hmutex.h"
#include "idle_table.h"
#include "loggers/network_logger.h"
#include "signal_manager.h"
#include "stc/common.h"
#include "tunnel.h"
#include "utils/hashutils.h"
#include "utils/procutils.h"
#include "utils/sockutils.h"

#define i_type balancegroup_registry_t // NOLINT
#define i_key  hash_t                  // NOLINT
#define i_val  idle_table_t *          // NOLINT

#include "stc/hmap.h"

typedef struct socket_filter_s
{
    union {
        hio_t  *listen_io;
        hio_t **listen_ios;
    };
    socket_filter_option_t option;
    tunnel_t              *tunnel;
    onAccept               cb;
    bool                   v6_dualstack;

} socket_filter_t;

#define i_key     socket_filter_t * // NOLINT
#define i_type    filters_t         // NOLINT
#define i_use_cmp                   // NOLINT
#include "stc/vec.h"

#define SUPPORT_V6 true

enum
{
    kSoOriginalDest          = 80,
    kFilterLevels            = 4,
    kMaxBalanceSelections    = 64,
    kDefalultBalanceInterval = 60 * 1000
};

typedef struct socket_manager_s
{
    filters_t filters[kFilterLevels];

    struct
    {
        generic_pool_t *pool; /* holds udp_payload_t */
        hhybridmutex_t  mutex;

    } *udp_pools;

    struct
    {
        generic_pool_t *pool; /* holds socket_accept_result_t */
        hhybridmutex_t  mutex;

    } *tcp_pools;

    hhybridmutex_t          mutex;
    balancegroup_registry_t balance_groups;
    hthread_t               accept_thread;
    worker_t               *worker;

    uint16_t last_round_tid;
    bool     iptables_installed;
    bool     ip6tables_installed;
    bool     lsof_installed;
    bool     iptable_cleaned;
    bool     iptables_used;
    bool     started;

} socket_manager_state_t;

static socket_manager_state_t *state = NULL;

static pool_item_t *allocTcpResultObjectPoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return globalMalloc(sizeof(socket_accept_result_t));
}

static void destroyTcpResultObjectPoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    globalFree(item);
}

static pool_item_t *allocUdpPayloadPoolHandle(struct generic_pool_s *pool)
{
    (void) pool;
    return globalMalloc(sizeof(udp_payload_t));
}

static void destroyUdpPayloadPoolHandle(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    globalFree(item);
}

void destroySocketAcceptResult(socket_accept_result_t *sar)
{
    const tid_t tid = sar->tid;

    hhybridmutex_lock(&(state->tcp_pools[tid].mutex));
    reusePoolItem(state->tcp_pools[tid].pool, sar);
    hhybridmutex_unlock(&(state->tcp_pools[tid].mutex));
}

static udp_payload_t *newUpdPayload(tid_t tid)
{
    hhybridmutex_lock(&(state->udp_pools[tid].mutex));
    udp_payload_t *item = popPoolItem(state->udp_pools[tid].pool);
    hhybridmutex_unlock(&(state->udp_pools[tid].mutex));
    return item;
}

void destroyUdpPayload(udp_payload_t *upl)
{
    const tid_t tid = upl->tid;

    hhybridmutex_lock(&(state->udp_pools[tid].mutex));
    reusePoolItem(state->udp_pools[tid].pool, upl);
    hhybridmutex_unlock(&(state->udp_pools[tid].mutex));
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

    while ((cur = option->white_list_raddr[len]))
    {
        len++;
    }

    option->white_list_parsed_length = len;
    option->white_list_parsed        = globalMalloc(sizeof(option->white_list_parsed[0]) * len);
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

void registerSocketAcceptor(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{
    if (state->started)
    {
        LOGF("SocketManager: cannot register after accept thread starts");
        exit(1);
    }
    socket_filter_t *filter   = globalMalloc(sizeof(socket_filter_t));
    unsigned int     pirority = 0;
    if (option.multiport_backend == kMultiportBackendNothing)
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
        hash_t        name_hash = CALC_HASH_BYTES(option.balance_group_name, strlen(option.balance_group_name));
        idle_table_t *b_table   = NULL;
        hhybridmutex_lock(&(state->mutex));

        balancegroup_registry_t_iter find_result = balancegroup_registry_t_find(&(state->balance_groups), name_hash);

        if (find_result.ref == balancegroup_registry_t_end(&(state->balance_groups)).ref)
        {
            b_table = newIdleTable(state->worker->loop);
            balancegroup_registry_t_insert(&(state->balance_groups), name_hash, b_table);
        }
        else
        {
            b_table = (find_result.ref->second);
        }

        hhybridmutex_unlock(&(state->mutex));

        option.shared_balance_table = b_table;
    }

    *filter = (socket_filter_t) {.tunnel = tunnel, .option = option, .cb = cb, .listen_io = NULL};

    hhybridmutex_lock(&(state->mutex));
    filters_t_push(&(state->filters[pirority]), filter);
    hhybridmutex_unlock(&(state->mutex));
}

static inline uint16_t getCurrentDistributeTid(void)
{
    return state->last_round_tid;
}

static inline void incrementDistributeTid(void)
{
    state->last_round_tid++;
    if (state->last_round_tid >= getWorkersCount())
    {
        state->last_round_tid = 0;
    }
}

static void distributeSocket(void *io, socket_filter_t *filter, uint16_t local_port)
{

    tid_t tid = (uint8_t) getCurrentDistributeTid();

    hhybridmutex_lock(&(state->tcp_pools[tid].mutex));
    socket_accept_result_t *result = popPoolItem(state->tcp_pools[tid].pool);
    hhybridmutex_unlock(&(state->tcp_pools[tid].mutex));

    result->real_localport = local_port;

    hloop_t *worker_loop = getWorkerLoop(tid);
    hevent_t ev          = (hevent_t) {.loop = worker_loop, .cb = filter->cb};
    result->tid          = tid;
    result->io           = io;
    result->tunnel       = filter->tunnel;
    ev.userdata          = result;
    incrementDistributeTid();

    hloop_post_event(worker_loop, &ev);
}

static void noTcpSocketConsumerFound(hio_t *io)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGE("SocketManager: could not find consumer for Tcp socket FD:%x [%s] <= [%s]", hio_fd(io),
         SOCKADDR_STR(hio_localaddr_u(io), localaddrstr), SOCKADDR_STR(hio_peeraddr_u(io), peeraddrstr));
    hio_close(io);
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
            memcpy(&ipv4_addr, &(addr->sin6.sin6_addr.s6_addr[12]), sizeof(ipv4_addr));
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

static void distributeTcpSocket(hio_t *io, uint16_t local_port)
{
    sockaddr_u *paddr = (sockaddr_u *) hio_peeraddr_u(io);

    static socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t                 balance_selection_filters_length = 0;
    idle_table_t           *selected_balance_table           = NULL;
    hash_t                  src_hash;
    bool                    src_hashed = false;
    const uint8_t           this_tid   = state->worker->tid;

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
                    src_hash = sockAddrCalcHashNoPort((sockaddr_u *) hio_peeraddr_u(io));
                }
                idle_item_t *idle_item = getIdleItemByHash(this_tid, option.shared_balance_table, src_hash);

                if (idle_item)
                {
                    socket_filter_t *target_filter = idle_item->userdata;
                    keepIdleItemForAtleast(option.shared_balance_table, idle_item,
                                           option.balance_group_interval == 0 ? kDefalultBalanceInterval
                                                                              : option.balance_group_interval);
                    if (option.no_delay)
                    {
                        tcp_nodelay(hio_fd(io), 1);
                    }
                    hio_detach(io);
                    distributeSocket(io, target_filter, local_port);
                    return;
                }

                if (WW_UNLIKELY(balance_selection_filters_length >= kMaxBalanceSelections))
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
                tcp_nodelay(hio_fd(io), 1);
            }
            hio_detach(io);
            distributeSocket(io, filter, local_port);
            return;
        }
    }

    if (balance_selection_filters_length > 0)
    {
        socket_filter_t *filter = balance_selection_filters[fastRand() % balance_selection_filters_length];
        newIdleItem(filter->option.shared_balance_table, src_hash, filter, NULL, this_tid,
                    filter->option.balance_group_interval == 0 ? kDefalultBalanceInterval
                                                               : filter->option.balance_group_interval);

        if (filter->option.no_delay)
        {
            tcp_nodelay(hio_fd(io), 1);
        }
        distributeSocket(io, filter, local_port);
    }
    else
    {
        noTcpSocketConsumerFound(io);
    }
}

static void onAcceptTcpSinglePort(hio_t *io)
{
    distributeTcpSocket(io, sockaddr_port((sockaddr_u *) hio_localaddr_u(io)));
}

static void onAcceptTcpMultiPort(hio_t *io)
{
#ifdef OS_UNIX

    bool          use_v4_strategy = needsV4SocketStrategy((sockaddr_u *) hio_peeraddr_u(io));
    unsigned char pbuf[28]        = {0};
    socklen_t     size            = use_v4_strategy ? 16 : 24;

    int level = use_v4_strategy ? IPPROTO_IP : IPPROTO_IPV6;
    if (getsockopt(hio_fd(io), level, kSoOriginalDest, &(pbuf[0]), &size) < 0)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGE("SocketManger: multiport failure getting origin port FD:%x [%s] <= [%s]", hio_fd(io),
             SOCKADDR_STR(hio_localaddr_u(io), localaddrstr), SOCKADDR_STR(hio_peeraddr_u(io), peeraddrstr));
        hio_close(io);
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

static void listenTcpMultiPortIptables(hloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
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
                filter->listen_io           = hloop_create_tcp_server(loop, host, main_port, onAcceptTcpMultiPort);
                ports_overlapped[main_port] = 1;
                if (filter->listen_io != NULL)
                {
                    filter->v6_dualstack = hio_localaddr(filter->listen_io)->sa_family == AF_INET6;
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

static void listenTcpMultiPortSockets(hloop_t *loop, socket_filter_t *filter, char *host, uint16_t port_min,
                                      uint8_t *ports_overlapped, uint16_t port_max)
{
    const int length           = (port_max - port_min);
    filter->listen_ios         = (hio_t **) globalMalloc(sizeof(hio_t *) * (length + 1));
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

        filter->listen_ios[i] = hloop_create_tcp_server(loop, host, p, onAcceptTcpSinglePort);

        if (filter->listen_ios[i] == NULL)
        {
            LOGW("SocketManager: could not listen on %s:[%u] , skipped...", host, p, "TCP");
            continue;
        }
        filter->v6_dualstack = hio_localaddr(filter->listen_io)->sa_family == AF_INET6;

        i++;
        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "TCP");
    }
}

static void listenTcpSinglePort(hloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                uint8_t *ports_overlapped)
{
    if (ports_overlapped[port] == 1)
    {
        return;
    }
    ports_overlapped[port] = 1;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "TCP");
    filter->listen_io = hloop_create_tcp_server(loop, host, port, onAcceptTcpSinglePort);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        exit(1);
    }
    filter->v6_dualstack = hio_localaddr(filter->listen_io)->sa_family == AF_INET6;
}

static void listenTcp(hloop_t *loop, uint8_t *ports_overlapped)
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
                option.multiport_backend = kMultiportBackendNothing;
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
         SOCKADDR_STR(hio_localaddr_u(upl.sock->io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr_u(upl.sock->io), peeraddrstr));
}

static void postPayload(udp_payload_t post_pl, socket_filter_t *filter)
{

    hhybridmutex_lock(&(state->udp_pools[post_pl.tid].mutex));
    udp_payload_t *pl = popPoolItem(state->udp_pools[post_pl.tid].pool);
    hhybridmutex_unlock(&(state->udp_pools[post_pl.tid].mutex));
    *pl = post_pl;

    pl->tunnel           = filter->tunnel;
    hloop_t *worker_loop = getWorkerLoop(pl->tid);
    hevent_t ev          = (hevent_t) {.loop = worker_loop, .cb = filter->cb};
    ev.userdata          = (void *) pl;

    hloop_post_event(worker_loop, &ev);
}

static void distributeUdpPayload(const udp_payload_t pl)
{
    // hhybridmutex_lock(&(state->mutex)); new socket manager will not lock here
    sockaddr_u *paddr      = (sockaddr_u *) hio_peeraddr_u(pl.sock->io);
    uint16_t    local_port = pl.real_localport;

    static socket_filter_t *balance_selection_filters[kMaxBalanceSelections];
    uint8_t                 balance_selection_filters_length = 0;
    idle_table_t           *selected_balance_table           = NULL;
    hash_t                  src_hash;
    bool                    src_hashed = false;
    const uint8_t           this_tid   = state->worker->tid;

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
                    src_hash = sockAddrCalcHashNoPort((sockaddr_u *) hio_peeraddr_u(pl.sock->io));
                }
                idle_item_t *idle_item = getIdleItemByHash(this_tid, option.shared_balance_table, src_hash);

                if (idle_item)
                {
                    socket_filter_t *target_filter = idle_item->userdata;
                    keepIdleItemForAtleast(option.shared_balance_table, idle_item,
                                           option.balance_group_interval == 0 ? kDefalultBalanceInterval
                                                                              : option.balance_group_interval);
                    postPayload(pl, target_filter);
                    return;
                }

                if (WW_UNLIKELY(balance_selection_filters_length >= kMaxBalanceSelections))
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
        newIdleItem(filter->option.shared_balance_table, src_hash, filter, NULL, this_tid,
                    filter->option.balance_group_interval == 0 ? kDefalultBalanceInterval
                                                               : filter->option.balance_group_interval);
        postPayload(pl, filter);
    }
    else
    {
        noUdpSocketConsumerFound(pl);
    }
}

static void onRecvFrom(hio_t *io, shift_buffer_t *buf)
{
    udpsock_t *socket     = hevent_userdata(io);
    uint16_t   local_port = sockaddr_port((sockaddr_u *) hio_localaddr_u(io));
    uint8_t    target_tid = local_port % getWorkersCount();

    udp_payload_t item = (udp_payload_t) {.sock           = socket,
                                          .buf            = buf,
                                          .tid            = target_tid,
                                          .peer_addr      = *(sockaddr_u *) hio_peeraddr_u(io),
                                          .real_localport = local_port};

    distributeUdpPayload(item);
}

static void listenUdpSinglePort(hloop_t *loop, socket_filter_t *filter, char *host, uint16_t port,
                                uint8_t *ports_overlapped)
{
    if (ports_overlapped[port] == 1)
    {
        return;
    }
    ports_overlapped[port] = 1;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "UDP");
    filter->listen_io = hloop_create_udp_server(loop, host, port);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        exit(1);
    }
    udpsock_t *socket = globalMalloc(sizeof(udpsock_t));
    *socket           = (udpsock_t) {.io = filter->listen_io, .table = newIdleTable(loop)};
    hevent_set_userdata(filter->listen_io, socket);
    hio_setcb_read(filter->listen_io, onRecvFrom);
    hio_read(filter->listen_io);
}

// todo (udp manager)
static void listenUdp(hloop_t *loop, uint8_t *ports_overlapped)
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
                option.multiport_backend = kMultiportBackendNothing;
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

static void writeUdpThisLoop(hevent_t *ev)
{
    udp_payload_t *upl    = hevent_userdata(ev);
    size_t         nwrite = hio_write(upl->sock->io, upl->buf);
    (void) nwrite;
    destroyUdpPayload(upl);
}

void postUdpWrite(udpsock_t *socket_io, uint8_t tid_from, shift_buffer_t *buf)
{

    udp_payload_t *item = newUpdPayload(tid_from);

    *item = (udp_payload_t) {.sock = socket_io, .buf = buf, .tid = tid_from};

    hevent_t ev = (hevent_t) {.loop = hevent_loop(socket_io->io), .userdata = item, .cb = writeUdpThisLoop};

    hloop_post_event(hevent_loop(socket_io->io), &ev);
}

static HTHREAD_ROUTINE(accept_thread) // NOLINT
{
    (void) userdata;

    assert(state && state->worker->loop && ! state->started);

    hhybridmutex_lock(&(state->mutex));

    {
        uint8_t ports_overlapped[65536] = {0};
        listenTcp(state->worker->loop, ports_overlapped);
    }
    {
        uint8_t ports_overlapped[65536] = {0};
        listenUdp(state->worker->loop, ports_overlapped);
    }
    state->started = true;
    hhybridmutex_unlock(&(state->mutex));

    hloop_run(state->worker->loop);
    LOGW("AcceptThread eventloop finished!");
    return 0;
}

struct socket_manager_s *getSocketManager(void)
{
    return state;
}

void setSocketManager(struct socket_manager_s *new_state)
{
    assert(state == NULL);
    state = new_state;
}

void startSocketManager(void)
{
    assert(state != NULL);
    // accept_thread(accept_thread_loop);

    state->accept_thread = hthread_create(accept_thread, NULL);
}

socket_manager_state_t *createSocketManager(void)
{
    assert(state == NULL);
    state = globalMalloc(sizeof(socket_manager_state_t));
    memset(state, 0, sizeof(socket_manager_state_t));

    worker_t *worker = globalMalloc(sizeof(worker_t));

    *worker = (worker_t) {.tid = 255};

    worker->shift_buffer_pool = newGenericPoolWithCap(GSTATE.masterpool_shift_buffer_pools, (64) + GSTATE.ram_profile,
                                                      allocShiftBufferPoolHandle, destroyShiftBufferPoolHandle);

    worker->buffer_pool = createBufferPool(GSTATE.masterpool_buffer_pools_large, GSTATE.masterpool_buffer_pools_small,
                                           worker->shift_buffer_pool,GSTATE.ram_profile);

    worker->loop = hloop_new(HLOOP_FLAG_AUTO_FREE, worker->buffer_pool, worker->tid);

    state->worker = worker;

    for (size_t i = 0; i < kFilterLevels; i++)
    {
        state->filters[i] = filters_t_init();
    }

    hhybridmutex_init(&state->mutex);

    state->udp_pools = globalMalloc(sizeof(*state->udp_pools) * getWorkersCount());
    memset(state->udp_pools, 0, sizeof(*state->udp_pools) * getWorkersCount());

    state->tcp_pools = globalMalloc(sizeof(*state->tcp_pools) * getWorkersCount());
    memset(state->tcp_pools, 0, sizeof(*state->tcp_pools) * getWorkersCount());
    master_pool_t *mp_udp = newMasterPoolWithCap(2 * ((8) + RAM_PROFILE));
    master_pool_t *mp_tcp = newMasterPoolWithCap(2 * ((8) + RAM_PROFILE));
    for (unsigned int i = 0; i < getWorkersCount(); ++i)
    {

        state->udp_pools[i].pool =
            newGenericPoolWithCap(mp_udp, (8) + RAM_PROFILE, allocUdpPayloadPoolHandle, destroyUdpPayloadPoolHandle);
        hhybridmutex_init(&(state->udp_pools[i].mutex));

        state->tcp_pools[i].pool = newGenericPoolWithCap(mp_tcp, (8) + RAM_PROFILE, allocTcpResultObjectPoolHandle,
                                                         destroyTcpResultObjectPoolHandle);
        hhybridmutex_init(&(state->tcp_pools[i].mutex));
    }

#ifdef OS_UNIX

    state->iptables_installed = checkCommandAvailable("iptables");
    state->lsof_installed     = checkCommandAvailable("lsof");
#if SUPPORT_V6
    state->ip6tables_installed = checkCommandAvailable("ip6tables");
#endif

#endif

    registerAtExitCallback(exitHook, NULL);

    return state;
}
