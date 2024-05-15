#include "socket_manager.h"
#include "basic_types.h"
#include "buffer_pool.h"
#include "hloop.h"
#include "hmutex.h"
#include "idle_table.h"
#include "loggers/network_logger.h"
#include "stc/common.h"
#include "tunnel.h"
#include "utils/procutils.h"
#include "ww.h"

typedef struct socket_filter_s
{
    union {
        hio_t  *listen_io;
        hio_t **listen_ios;
    };
    socket_filter_option_t option;
    tunnel_t              *tunnel;
    onAccept               cb;
} socket_filter_t;

#define i_key     socket_filter_t * // NOLINT
#define i_type    filters_t         // NOLINT
#define i_use_cmp                   // NOLINT
#include "stc/vec.h"

#define SUPOPRT_V6 false
enum
{
    kSoOriginalDest = 80,
    kFilterLevels   = 4
};

typedef struct socket_manager_s
{
    hthread_t      accept_thread;
    filters_t      filters[kFilterLevels];
    hhybridmutex_t mutex;

    uint16_t last_round_tid;
    bool     iptables_installed;
    bool     ip6tables_installed;
    bool     lsof_installed;
    bool     iptable_cleaned;
    bool     iptables_used;

} socket_manager_state_t;

static socket_manager_state_t *state = NULL;

static bool redirectPortRangeTcp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p TCP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    execCmd(b);
#endif

    sprintf(b, "iptables -t nat -A PREROUTING -p TCP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    return execCmd(b).exit_code == 0;
}

static bool redirectPortRangeUdp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p UDP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    execCmd(b);
#endif
    sprintf(b, "iptables -t nat -A PREROUTING -p UDP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    return execCmd(b).exit_code == 0;
}

static bool redirectPortTcp(unsigned int port, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p TCP --dport %u -j REDIRECT --to-port %u", port, to);
    execCmd(b);
#endif
    sprintf(b, "iptables -t nat -A PREROUTING -p TCP --dport %u -j REDIRECT --to-port %u", port, to);
    return execCmd(b).exit_code == 0;
}

static bool redirectPortUdp(unsigned int port, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p UDP --dport %u -j REDIRECT --to-port %u", port, to);
    execCmd(b);
#endif
    sprintf(b, "iptables -t nat -A PREROUTING -p UDP --dport %u -j REDIRECT --to-port %u", port, to);
    return execCmd(b).exit_code == 0;
}

static bool resetIptables(void)
{
    LOGD("SocketManager: clearing iptables nat rules");
#if SUPOPRT_V6
    execCmd("ip6tables -t nat -F");
    execCmd("ip6tables -t nat -X");
#endif

    return execCmd("iptables -t nat -F").exit_code == 0 && execCmd("iptables -t nat -X").exit_code == 0;
}
static void exitHook(void)
{
    if (state->iptables_used)
    {
        resetIptables();
    }
}
static void signalHandler(int signum)
{
    signal(signum, SIG_DFL);
    if (signum == SIGTERM || signum == SIGINT)
    {
        exit(0); // exit hook gets called NOLINT
    }
}

int checkIPRange(bool ipver6, const struct in6_addr test_addr, const struct in6_addr base_addr,
                 const struct in6_addr subnet_mask)
{
    struct in6_addr result_addr;

    if (ipver6)
    {
        // IPv6 addresses
        for (int i = 0; i < 16; i++)
        {
            result_addr.s6_addr[i] = base_addr.s6_addr[i] & subnet_mask.s6_addr[i];
        }
        if (memcmp(&test_addr, &result_addr, sizeof(struct in6_addr)) == 0)
        {
            return 1;
        }
        return 0;
    }

    // IPv4 addresses
    uint32_t base_addr_32 = ntohl(*((uint32_t *) base_addr.s6_addr));
    uint32_t test_addr_32 = ntohl(*((uint32_t *) test_addr.s6_addr));
    uint32_t mask_addr32  = ntohl(*((uint32_t *) subnet_mask.s6_addr));

    uint32_t result_addr32 = base_addr_32 & mask_addr32;

    if ((test_addr_32 & mask_addr32) == result_addr32)
    {
        return 1;
    }

    return 0;
}
int parseIPWithSubnetMask(struct in6_addr *base_addr, const char *input, struct in6_addr *subnet_mask)
{
    char *slash;
    char *ip_part;
    char *subnet_part;
    char  input_copy[strlen(input) + 1];
    strcpy(input_copy, input);

    slash = strchr(input_copy, '/');
    if (slash == NULL)
    {
        fprintf(stderr, "Invalid input format.\n");
        return -1;
    }

    *slash      = '\0';
    ip_part     = input_copy;
    subnet_part = slash + 1;

    if (inet_pton(AF_INET, ip_part, base_addr) == 1)
    {
        // IPv4 address
        int prefix_length = atoi(subnet_part);
        if (prefix_length < 0 || prefix_length > 32)
        {
            fprintf(stderr, "Invalid subnet mask length.\n");
            return -1;
        }
        uint32_t mask;
        if (sizeof(unsigned long long) == 8)
        {
            mask = htonl(0xFFFFFFFF &
                         ((unsigned long long) 0x00000000FFFFFFFF << (unsigned long long) (32 - prefix_length)));
        }
        else
        {
            if (prefix_length > 0)
            {
                mask = htonl(0xFFFFFFFF & (0xFFFFFFFF << (32 - prefix_length)));
            }
            else
            {
                mask = 0;
            }
        }
        struct in_addr mask_addr = {.s_addr = mask};
        memcpy(subnet_mask, &mask_addr, 4);
        // inet_ntop(AF_INET, &mask_addr, subnet_mask, INET_ADDRSTRLEN);
    }
    else if (inet_pton(AF_INET6, ip_part, base_addr) == 1)
    {
        // IPv6 address

        int prefix_length = atoi(subnet_part);
        if (prefix_length < 0 || prefix_length > 128)
        {
            fprintf(stderr, "Invalid subnet mask length.\n");
            return -1;
        }
        int i;
        for (i = 0; i < 16; i++)
        {
            int bits                     = prefix_length >= 8 ? 8 : prefix_length;
            ((uint8_t *) subnet_mask)[i] = bits == 0 ? 0 : (0xFF << (8 - bits));
            prefix_length -= bits;
        }
        // struct in6_addr mask_addr;
        // memcpy(&(subnet_mask->s6_addr), subnet_mask, 16);
        // inet_ntop(AF_INET6, &mask_addr, subnet_mask, INET6_ADDRSTRLEN);
    }
    else
    {
        fprintf(stderr, "Invalid IP address.\n");
        return -1;
    }

    return 0;
}

void registerSocketAcceptor(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{

    socket_filter_t *filter = malloc(sizeof(socket_filter_t));
    *filter                 = (socket_filter_t){.tunnel = tunnel, .option = option, .cb = cb, .listen_io = NULL};

    unsigned int pirority = 0;
    if (option.multiport_backend == kMultiportBackendNothing)
    {
        pirority++;
    }
    if (option.white_list_raddr != NULL)
    {
        pirority++;
    }
    if (option.black_list_raddr != NULL)
    {
        pirority++;
    }

    hhybridmutex_lock(&(state->mutex));
    filters_t_push(&(state->filters[pirority]), filter);
    hhybridmutex_unlock(&(state->mutex));
}

static inline uint16_t getCurrentDistrbuteTid(void)
{
    return state->last_round_tid;
}
static inline void incrementDistrbuteTid(void)
{
    state->last_round_tid++;
    if (state->last_round_tid >= workers_count)
    {
        state->last_round_tid = 0;
    }
}
static void distributeSocket(void *io, socket_filter_t *filter, uint16_t local_port)
{
    socket_accept_result_t *result = malloc(sizeof(socket_accept_result_t));
    result->real_localport         = local_port;

    uint8_t  tid         = (uint8_t) getCurrentDistrbuteTid();
    hloop_t *worker_loop = loops[tid];
    hevent_t ev          = (hevent_t){.loop = worker_loop, .cb = filter->cb};
    result->tid          = tid;
    result->io           = io;
    result->tunnel       = filter->tunnel;
    ev.userdata          = result;
    incrementDistrbuteTid();

    hloop_post_event(worker_loop, &ev);
}
static void noTcpSocketConsumerFound(hio_t *io)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGE("SocketManager: could not find consumer for Tcp socket FD:%x [%s] <= [%s]", (int) hio_fd(io),
         SOCKADDR_STR(hio_localaddr(io), localaddrstr), SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    hio_close(io);
}

// todo (optimize) preparse + avoid copy
static bool checkIpIsWhiteList(sockaddr_u *addr, char **white_list_raddr)
{
    bool  matches = false;
    int   i       = 0;
    char *cur     = white_list_raddr[i];
    do
    {
        struct in6_addr ip_strbuf     = {0};
        struct in6_addr mask_stripbuf = {0};
        parseIPWithSubnetMask(&ip_strbuf, cur, &mask_stripbuf);
        struct in6_addr test_addr = {0};
        if (addr->sa.sa_family == AF_INET)
        {
            memcpy(&test_addr, &addr->sin.sin_addr, 4);
            matches = checkIPRange(false, test_addr, ip_strbuf, mask_stripbuf);
        }
        else
        {
            memcpy(&test_addr, &addr->sin6.sin6_addr, 16);
            matches = checkIPRange(true, test_addr, ip_strbuf, mask_stripbuf);
        }
        if (matches)
        {
            return true;
        }
        i++;
    } while ((cur = white_list_raddr[i]));

    return false;
}

static void distributeTcpSocket(hio_t *io, uint16_t local_port)
{
    hhybridmutex_lock(&(state->mutex));
    sockaddr_u *paddr = (sockaddr_u *) hio_peeraddr(io);

    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
        {
            socket_filter_t       *filter   = *(k.ref);
            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;

            if (option.proto != kSapTcp || port_min > local_port || port_max < local_port)
            {
                continue;
            }
            if (option.white_list_raddr != NULL)
            {
                if (! checkIpIsWhiteList(paddr, option.white_list_raddr))
                {
                    continue;
                }
            }

            if (option.no_delay)
            {
                tcp_nodelay(hio_fd(io), 1);
            }
            hio_detach(io);
            hhybridmutex_unlock(&(state->mutex));
            distributeSocket(io, filter, local_port);
            return;
        }
    }

    hhybridmutex_unlock(&(state->mutex));
    noTcpSocketConsumerFound(io);
}

static void onAcceptTcpSinglePort(hio_t *io)
{
    distributeTcpSocket(io, sockaddr_port((sockaddr_u *) hio_localaddr(io)));
}

static void onAcceptTcpMultiPort(hio_t *io)
{
    unsigned char pbuf[28] = {0};
    socklen_t     size     = 16; // todo ipv6 value is 28
    if (getsockopt(hio_fd(io), SOL_IP, kSoOriginalDest, &(pbuf[0]), &size) < 0)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        LOGE("SocketManger: multiport failure getting origin port FD:%x [%s] <= [%s]", (int) hio_fd(io),
             SOCKADDR_STR(hio_localaddr(io), localaddrstr), SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
        hio_close(io);
        return;
    }

    distributeTcpSocket(io, (pbuf[2] << 8) | pbuf[3]);
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
        if (! resetIptables())
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
    filter->listen_ios         = (hio_t **) malloc(sizeof(hio_t *) * (length + 1));
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
            if (option.proto == kSapTcp)
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

// void onUdpSocketExpire(struct idle_item_s *table_item)
// {
//     assert(table_item->userdata != NULL);
//     udpsock_t *udpsock = table_item->userdata;

//     // call close callback
//     if (udpsock->closecb)
//     {
//         hevent_t ev;
//         memset(&ev, 0, sizeof(ev));
//         ev.loop = loops[table_item->tid];
//         ev.cb   = udpsock->closecb;
//         hevent_set_userdata(&ev, udpsock);
//         hloop_post_event(loops[table_item->tid], &ev);
// }
// }
static void noUdpSocketConsumerFound(const udp_payload_t pl)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};
    LOGE("SocketManager: could not find consumer for Udp socket  [%s] <= [%s]",
         SOCKADDR_STR(hio_localaddr(pl.sock->io), localaddrstr), SOCKADDR_STR(hio_peeraddr(pl.sock->io), peeraddrstr));
}
static void postPayload(const udp_payload_t pl, socket_filter_t *filter)
{
    udp_payload_t *heap_pl = malloc(sizeof(udp_payload_t));
    *heap_pl               = pl;
    heap_pl->tunnel        = filter->tunnel;
    hloop_t *worker_loop   = loops[pl.tid];
    hevent_t ev            = (hevent_t){.loop = worker_loop, .cb = filter->cb};
    ev.userdata            = heap_pl;

    hloop_post_event(worker_loop, &ev);
}
static void distributeUdpPayload(const udp_payload_t pl)
{
    hhybridmutex_lock(&(state->mutex));
    sockaddr_u *paddr      = (sockaddr_u *) hio_peeraddr(pl.sock->io);
    uint16_t    local_port = pl.real_localport;
    for (int ri = (kFilterLevels - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
        {

            socket_filter_t       *filter   = *(k.ref);
            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;

            if (option.proto != kSapUdp || port_min > local_port || port_max < local_port)
            {
                continue;
            }
            if (option.white_list_raddr != NULL)
            {
                if (! checkIpIsWhiteList(paddr, option.white_list_raddr))
                {
                    continue;
                }
            }
            hhybridmutex_unlock(&(state->mutex));
            postPayload(pl, filter);
            return;
        }
    }

    hhybridmutex_unlock(&(state->mutex));
    noUdpSocketConsumerFound(pl);
}
static void onRecvFrom(hio_t *io, shift_buffer_t *buf)
{

    // printf("on_recvfrom fd=%d readbytes=%d\n", hio_fd(io), (int) bufLen(buf));
    // char localaddrstr[SOCKADDR_STRLEN] = {0};
    // char peeraddrstr[SOCKADDR_STRLEN]  = {0};
    // printf("[%s] <=> [%s]\n", SOCKADDR_STR(hio_localaddr(io), localaddrstr),
    //        SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    // hash_t       peeraddr_hash = sockAddrCalcHash((sockaddr_u *) hio_peeraddr(io));

    udpsock_t *socket     = hevent_userdata(io);
    uint16_t   local_port = sockaddr_port((sockaddr_u *) hio_localaddr(io));
    uint8_t    target_tid = local_port % workers_count;

    distributeUdpPayload((udp_payload_t){.sock           = socket,
                                         .buf            = buf,
                                         .tid            = target_tid,
                                         .peer_addr      = *(sockaddr_u *) hio_peeraddr(io),
                                         .real_localport = local_port});
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
    udpsock_t *socket = malloc(sizeof(udpsock_t));
    *socket           = (udpsock_t){.io = filter->listen_io, .table = newIdleTable(loop)};
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
            if (option.proto == kSapUdp)
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
// todo (async channel) :(
struct udp_sb
{
    hio_t          *socket_io;
    shift_buffer_t *buf;
};
void writeUdpThisLoop(hevent_t *ev)
{
    struct udp_sb *ub     = hevent_userdata(ev);
    size_t         nwrite = hio_write(ub->socket_io, ub->buf);
    (void) nwrite;

    free(ub);
}
void postUdpWrite(hio_t *socket_io, shift_buffer_t *buf)
{
    struct udp_sb *ub = malloc(sizeof(struct udp_sb));
    *ub               = (struct udp_sb){.socket_io = socket_io, buf};
    hevent_t ev       = (hevent_t){.loop = hevent_loop(socket_io), .cb = writeUdpThisLoop};
    ev.userdata       = ub;

    hloop_post_event(hevent_loop(socket_io), &ev);
}

static HTHREAD_ROUTINE(accept_thread) // NOLINT
{
    (void) userdata;
    hloop_t *loop = hloop_new(HLOOP_FLAG_AUTO_FREE, createSmallBufferPool());

    hhybridmutex_lock(&(state->mutex));
    // state->table = newIdleTable(loop, onUdpSocketExpire);

    {
        uint8_t ports_overlapped[65536] = {0};
        listenTcp(loop, ports_overlapped);
    }
    {
        uint8_t ports_overlapped[65536] = {0};
        listenUdp(loop, ports_overlapped);
    }
    hhybridmutex_unlock(&(state->mutex));

    hloop_run(loop);
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
    state = malloc(sizeof(socket_manager_state_t));
    memset(state, 0, sizeof(socket_manager_state_t));
    for (size_t i = 0; i < kFilterLevels; i++)
    {
        state->filters[i] = filters_t_init();
    }

    hhybridmutex_init(&state->mutex);

    state->iptables_installed = checkCommandAvailable("iptables");
    state->lsof_installed     = checkCommandAvailable("lsof");
#if SUPOPRT_V6
    state->ip6tables_installed = checkCommandAvailable("ip6tables");
#endif

    if (signal(SIGTERM, signalHandler) == SIG_ERR)
    {
        perror("Error setting SIGTERM signal handler");
        exit(1);
    }
    if (signal(SIGINT, signalHandler) == SIG_ERR)
    {
        perror("Error setting SIGINT signal handler");
        exit(1);
    }
    if (atexit(exitHook) != 0)
    {
        perror("Error setting ATEXIT hook");
        exit(1);
    }

    return state;
}
