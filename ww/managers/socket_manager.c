#include "socket_manager.h"
#include "hv/hthread.h"
#include "loggers/network_logger.h"
#include "utils/procutils.h"
#include "ww.h"
#include <signal.h>

#define i_key     socket_filter_t * // NOLINT
#define i_type    filters_t         // NOLINT
#define i_use_cmp                   // NOLINT
#include "stc/vec.h"

#define SUPOPRT_V6      false
#define SO_ORIGINAL_DST 80
#define FILTERS_LEVELS  4

typedef struct socket_manager_s
{
    hthread_t accept_thread;
    hmutex_t  mutex;
    filters_t filters[FILTERS_LEVELS];
    uint16_t  last_round_tindex;
    bool      iptables_installed;
    bool      ip6tables_installed;
    bool      lsof_installed;
    bool      iptable_cleaned;
    bool      iptables_used;

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

static bool resetIptables()
{
    LOGD("SocketManager: clearing iptables nat rules");
#if SUPOPRT_V6
    execCmd("ip6tables -t nat -F");
    execCmd("ip6tables -t nat -X");
#endif

    return execCmd("iptables -t nat -F").exit_code == 0 && execCmd("iptables -t nat -X").exit_code == 0;
}
static void exitHook()
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
        memcpy(&(subnet_mask->s6_addr), subnet_mask, 16);
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
    filter->tunnel          = tunnel;
    filter->option          = option;
    filter->cb              = cb;
    filter->listen_io       = NULL;
    unsigned int pirority   = 0;
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

    hmutex_lock(&(state->mutex));
    filters_t_push(&(state->filters[pirority]), filter);
    hmutex_unlock(&(state->mutex));
}

static void distributeSocket(hio_t *io, socket_filter_t *filter, uint16_t local_port, bool no_delay)
{
    socket_accept_result_t *result = malloc(sizeof(socket_accept_result_t));
    result->real_localport         = local_port;

    if (no_delay)
    {
        tcp_nodelay(hio_fd(io), 1);
    }

    hio_detach(io);
    hloop_t *worker_loop = loops[state->last_round_tindex];
    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.loop        = worker_loop;
    ev.cb          = filter->cb;
    result->tid    = state->last_round_tindex;
    result->io     = io;
    result->tunnel = filter->tunnel;
    ev.userdata    = result;
    state->last_round_tindex++;
    if (state->last_round_tindex >= workers_count)
    {
        state->last_round_tindex = 0;
    }
    hloop_post_event(worker_loop, &ev);
}
static void noSocketConsumerFound(hio_t *io)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    LOGE("SocketManager: Couldnot find consumer for socket FD:%x [%s] <= [%s]", (int) hio_fd(io),
         SOCKADDR_STR(hio_localaddr(io), localaddrstr), SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    hio_close(io);
}
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
    hmutex_lock(&(state->mutex));
    sockaddr_u *paddr = (sockaddr_u *) hio_peeraddr(io);

    for (int ri = (FILTERS_LEVELS - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
        {
            socket_filter_t *      filter   = *(k.ref);
            socket_filter_option_t option   = filter->option;
            uint16_t               port_min = option.port_min;
            uint16_t               port_max = option.port_max;

            // single port or multi port per socket
            if (port_min > local_port || port_max < local_port)
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

            distributeSocket(io, filter, local_port, option.no_delay);
            hmutex_unlock(&(state->mutex));
            return;
        }
    }

    hmutex_unlock(&(state->mutex));
    noSocketConsumerFound(io);
}

static void onAcceptTcpSinplePort(hio_t *io)
{
    distributeTcpSocket(io, sockaddr_port((sockaddr_u *) hio_localaddr(io)));
}

static void onAcceptTcpMultiPort(hio_t *io)
{
    unsigned char pbuf[28] = {0};
    socklen_t     size     = 16; // todo ipv6 value is 28
    if (getsockopt(hio_fd(io), SOL_IP, SO_ORIGINAL_DST, &(pbuf[0]), &size) < 0)
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

static multiport_backend_t getDefaultMultiPortBackend()
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
            LOGF("SocketManager: could not clear iptables rusles");
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
    for (uint16_t p = port_min; p < port_max; p++)
    {
        if (ports_overlapped[p] == 1)
        {
            LOGW("SocketManager: Couldnot listen on %s:[%u] , skipped...", host, p, "TCP");
            continue;
        }
        ports_overlapped[p] = 1;

        filter->listen_io = hloop_create_tcp_server(loop, host, p, onAcceptTcpSinplePort);

        if (filter->listen_io == NULL)
        {
            LOGW("SocketManager: Couldnot listen on %s:[%u] , skipped...", host, p, "TCP");
            continue;
        }

        LOGI("SocketManager: listening on %s:[%u] (%s)", host, p, "TCP");
    }
}
static void listenTcpSinglePort(hloop_t *loop,socket_filter_t *filter, char *host, uint16_t port, uint8_t *ports_overlapped)
{
    if (ports_overlapped[port] == 1)
    {
        return;
    }
    ports_overlapped[port] = 1;
    LOGI("SocketManager: listening on %s:[%u] (%s)", host, port, "TCP");
    filter->listen_io = hloop_create_tcp_server(loop, host, port, onAcceptTcpSinplePort);

    if (filter->listen_io == NULL)
    {
        LOGF("SocketManager: stopping due to null socket handle");
        exit(1);
    }
}
static void listenTcp(hloop_t *loop, uint8_t *ports_overlapped)
{
    for (int ri = (FILTERS_LEVELS - 1); ri >= 0; ri--)
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
                option.multiport_backend == kMultiportBackendNothing;
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

static HTHREAD_ROUTINE(accept_thread) //NOLINT
{
    hloop_t *loop = (hloop_t *) userdata;

    hmutex_lock(&(state->mutex));
    {
        uint8_t ports_overlapped[65536] = {0};
        listenTcp(loop, ports_overlapped);
    }

    hmutex_unlock(&(state->mutex));

    hloop_run(loop);
    LOGW("AcceptThread eventloop finished!");
    return 0;
}

struct socket_manager_s *getSocketManager()
{
    return state;
}

void setSocketManager(struct socket_manager_s *new_state)
{
    assert(state == NULL);
    state = new_state;
}

void startSocketManager()
{
    assert(state != NULL);
    hloop_t *accept_thread_loop = hloop_new(HLOOP_FLAG_AUTO_FREE);
    // accept_thread(accept_thread_loop);
    state->accept_thread = hthread_create(accept_thread, accept_thread_loop);
}

socket_manager_state_t *createSocketManager()
{
    assert(state == NULL);
    state = malloc(sizeof(socket_manager_state_t));
    memset(state, 0, sizeof(socket_manager_state_t));
    for (size_t i = 0; i < FILTERS_LEVELS; i++)
    {
        state->filters[i] = filters_t_init();
    }

    hmutex_init(&state->mutex);

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
