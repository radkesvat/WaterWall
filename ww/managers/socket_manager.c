#include "socket_manager.h"
#include "ww.h"
#include "utils/procutils.h"
#include "hv/hthread.h"
#include "loggers/network_logger.h"
#include <signal.h>

#define i_key socket_filter_t *
#define i_type filters_t
#define i_use_cmp // enable sorting/searhing using default <, == operators
#include "stc/vec.h"

#define SUPOPRT_V6 false
#define SO_ORIGINAL_DST 80
#define FILTERS_LEVELS 4

typedef struct socket_manager_s
{
    hthread_t accept_thread;
    hmutex_t mutex;
    filters_t filters[FILTERS_LEVELS];
    size_t last_round_tindex;
    bool iptables_installed;
    bool ip6tables_installed;
    bool lsof_installed;
    bool iptable_cleaned;
    bool iptables_used;

} socket_manager_state_t;

static socket_manager_state_t *state = NULL;

static bool redirect_port_range_tcp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p TCP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    execCmd(b);
#endif

    sprintf(b, "iptables -t nat -A PREROUTING -p TCP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    return execCmd(b).exit_code == 0;
}

static bool redirect_port_range_udp(unsigned int pmin, unsigned int pmax, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p UDP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    execCmd(b);
#endif
    sprintf(b, "iptables -t nat -A PREROUTING -p UDP --dport %u:%u -j REDIRECT --to-port %u", pmin, pmax, to);
    return execCmd(b).exit_code == 0;
}
static bool redirect_port_tcp(unsigned int port, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p TCP --dport %u -j REDIRECT --to-port %u", port, to);
    execCmd(b);
#endif
    sprintf(b, "iptables -t nat -A PREROUTING -p TCP --dport %u -j REDIRECT --to-port %u", port, to);
    return execCmd(b).exit_code == 0;
}

static bool redirect_port_udp(unsigned int port, unsigned int to)
{
    char b[300];
#if SUPOPRT_V6
    sprintf(b, "ip6tables -t nat -A PREROUTING -p UDP --dport %u -j REDIRECT --to-port %u", port, to);
    execCmd(b);
#endif
    sprintf(b, "iptables -t nat -A PREROUTING -p UDP --dport %u -j REDIRECT --to-port %u", port, to);
    return execCmd(b).exit_code == 0;
}

static bool reset_iptables()
{
    LOGD("SocketManager: clearing iptables nat rules");
#if SUPOPRT_V6
    execCmd("ip6tables -t nat -F");
    execCmd("ip6tables -t nat -X");
#endif

    return execCmd("iptables -t nat -F").exit_code == 0 && execCmd("iptables -t nat -X").exit_code == 0;
}
static void exit_hook()
{
    if (state->iptables_used)
        reset_iptables();
}
static void sig_handler(int signum)
{
    signal(signum, SIG_DFL);
    if (signum == SIGTERM || signum == SIGINT)
    {
        exit(0); // exit hook gets called
    }
}

int checkIPRange(bool ipver6, const struct in6_addr testAddr, const struct in6_addr base_addr, const struct in6_addr subnet_mask)
{
    struct in6_addr resultAddr;

    if (ipver6)
    {
        // IPv6 addresses
        for (int i = 0; i < 16; i++)
        {
            resultAddr.s6_addr[i] = base_addr.s6_addr[i] & subnet_mask.s6_addr[i];
        }
        if (memcmp(&testAddr, &resultAddr, sizeof(struct in6_addr)) == 0)
            return 1;
        else
            return 0;
    }
    else
    {
        // IPv4 addresses
        uint32_t baseAddr32 = ntohl(*((uint32_t *)base_addr.s6_addr));
        uint32_t testAddr32 = ntohl(*((uint32_t *)testAddr.s6_addr));
        uint32_t mask_addr32 = ntohl(*((uint32_t *)subnet_mask.s6_addr));

        uint32_t result_addr32 = baseAddr32 & mask_addr32;

        if ((testAddr32 & mask_addr32) == result_addr32)
            return 1;
        else
            return 0;
    }
}
int parseIPWithSubnetMask(const char *input, struct in6_addr *base_addr, struct in6_addr *subnet_mask)
{
    char *slash;
    char *ip_part, *subnet_part;
    char input_copy[strlen(input) + 1];
    strcpy(input_copy, input);

    slash = strchr(input_copy, '/');
    if (slash == NULL)
    {
        fprintf(stderr, "Invalid input format.\n");
        return -1;
    }

    *slash = '\0';
    ip_part = input_copy;
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
            mask = htonl(0xFFFFFFFF & ((unsigned long long)0x00000000FFFFFFFF << (unsigned long long)(32 - prefix_length)));
        }
        else
        {
            if (prefix_length > 0)
            {
                mask = htonl(0xFFFFFFFF & (0xFFFFFFFF << (32 - prefix_length)));
            }
            else
                mask = 0;
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
            int bits = prefix_length >= 8 ? 8 : prefix_length;
            ((uint8_t *)subnet_mask)[i] = bits == 0 ? 0 : (0xFF << (8 - bits));
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
    filter->tunnel = tunnel;
    filter->option = option;
    filter->cb = cb;
    filter->listen_io = NULL;
    unsigned int pirority = 0;
    if (option.multiport_backend == multiport_backend_nothing)
        pirority++;
    if (option.white_list_raddr != NULL)
        pirority++;
    if (option.black_list_raddr != NULL)
        pirority++;

    hmutex_lock(&(state->mutex));
    filters_t_push(&(state->filters[pirority]), filter);
    hmutex_unlock(&(state->mutex));
}

static void on_accept(hio_t *io, bool tcp, uint16_t socket_local_port)
{

    hmutex_lock(&(state->mutex));
    sockaddr_u *laddr = (sockaddr_u *)hio_localaddr(io);
    sockaddr_u *paddr = (sockaddr_u *)hio_peeraddr(io);

    for (int ri = (FILTERS_LEVELS - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
        {
            socket_filter_t *filter = *(k.ref);
            socket_filter_option_t option = filter->option;
            uint16_t port_min = option.port_min;
            uint16_t port_max = option.port_max;

            // if (option.proto == socket_protocol_tcp)

            // single port or multi port per socket
            if (port_min <= socket_local_port && port_max >= socket_local_port)
            {
                if (option.white_list_raddr != NULL)
                {
                    bool matches = false;
                    int i = 0;
                    char *cur = option.white_list_raddr[i];
                    do
                    {
                        struct in6_addr ip_strbuf = {0};
                        struct in6_addr mask_stripbuf = {0};
                        parseIPWithSubnetMask(cur, &ip_strbuf, &mask_stripbuf);
                        struct in6_addr testAddr = {0};
                        if (paddr->sa.sa_family == AF_INET)
                        {
                            memcpy(&testAddr, &paddr->sin.sin_addr, 4);
                            matches = checkIPRange(false, testAddr, ip_strbuf, mask_stripbuf);
                        }
                        else
                        {
                            memcpy(&testAddr, &paddr->sin6.sin6_addr, 16);
                            matches = checkIPRange(true, testAddr, ip_strbuf, mask_stripbuf);
                        }
                        if (matches)
                            break;

                        i++;
                    } while (cur = option.white_list_raddr[i]);
                    if (!matches)
                        continue;
                }

                socket_accept_result_t *result = malloc(sizeof(socket_accept_result_t));
                result->real_localport = socket_local_port;

                if (option.no_delay)
                {
                    tcp_nodelay(hio_fd(io), 1);
                }

                hio_detach(io);

                hloop_t *worker_loop = loops[state->last_round_tindex];

                hevent_t ev;
                memset(&ev, 0, sizeof(ev));
                ev.loop = worker_loop;
                ev.cb = filter->cb;

                result->tid = state->last_round_tindex;
                result->io = io;
                result->tunnel = filter->tunnel;
                ev.userdata = result;
                state->last_round_tindex++;
                if (state->last_round_tindex >= threads_count)
                    state->last_round_tindex = 0;
                hloop_post_event(worker_loop, &ev);
                hmutex_unlock(&(state->mutex));

                return;
            }
        }
    }

    hmutex_unlock(&(state->mutex));

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};

    LOGE("SocketManager: Couldnot find consumer for socket FD:%x [%s] <= [%s]",
         (int)hio_fd(io),
         SOCKADDR_STR(hio_localaddr(io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    hio_close(io);
}

static void on_accept_tcp_single(hio_t *io)
{
    on_accept(io, true, sockaddr_port((sockaddr_u *)hio_localaddr(io)));
}

static void on_accept_tcp_multi_iptable(hio_t *io)
{
    unsigned char pbuf[28] = {0};
    socklen_t size = 16; // todo ipv6 value is 28
    if (getsockopt(hio_fd(io), SOL_IP, SO_ORIGINAL_DST, &(pbuf[0]), &size) < 0)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN] = {0};

        LOGE("SocketManger: multiport failure getting origin port FD:%x [%s] <= [%s]",
             (int)hio_fd(io),
             SOCKADDR_STR(hio_localaddr(io), localaddrstr),
             SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
        hio_close(io);
        return;
    }

    on_accept(io, true, (pbuf[2] << 8) | pbuf[3]);
}
static void listen_tcp(hloop_t *loop, uint8_t *ports_overlapped)
{
    for (int ri = (FILTERS_LEVELS - 1); ri >= 0; ri--)
    {
        c_foreach(k, filters_t, state->filters[ri])
        {
            socket_filter_t *filter = *(k.ref);
            if (filter->option.multiport_backend == multiport_backend_default)
            {
                if (state->iptables_installed)
                    filter->option.multiport_backend = multiport_backend_iptables;
                else
                    filter->option.multiport_backend = multiport_backend_sockets;
            }
            socket_filter_option_t option = filter->option;
            uint16_t port_min = option.port_min;
            uint16_t port_max = option.port_max;
            const char *proto_str = option.proto == socket_protocol_tcp ? "TCP" : "UDP";
            if (port_min > port_max)
            {
                LOGF("SocketManager: port min must be lower than port max");
                exit(1);
            }

            if (option.proto == socket_protocol_tcp)
            {
                if (option.multiport_backend == multiport_backend_iptables)
                {
                    if (!state->iptables_installed)
                    {

                        LOGF("SocketManager: multi port backend \"iptables\" colud not start, error: not installed");
                        exit(1);
                    }
                    if (port_min == port_max)
                        goto singleport;
                    state->iptables_used = true;
                    if (!state->iptable_cleaned)
                    {
                        if (!reset_iptables())
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
                                filter->listen_io = hloop_create_tcp_server(loop, option.host, main_port, on_accept_tcp_multi_iptable);
                                ports_overlapped[main_port] = 1;
                                if (filter->listen_io != NULL)
                                    break;

                                main_port--;
                            }
                        } while (main_port >= port_min);

                        if (filter->listen_io == NULL)
                        {
                            LOGF("SocketManager: stopping due to null socket handle");
                            exit(1);
                        }
                    }
                    redirect_port_range_tcp(port_min, port_max, main_port);
                    LOGI("SocketManager: listening on %s:[%u - %u] >> %d (%s)", option.host, port_min, port_max, main_port, proto_str);
                }
                else if (option.multiport_backend == multiport_backend_sockets)
                {
                    if (port_min == port_max)
                        goto singleport;
                    for (size_t p = port_min; p < port_max; p++)
                    {
                        if (ports_overlapped[p] == 1)
                        {
                            LOGW("SocketManager: Couldnot listen on %s:[%u] , skipped...", option.host, p, proto_str);
                            continue;
                        }
                        ports_overlapped[p] = 1;

                        filter->listen_io = hloop_create_tcp_server(loop, option.host, p, on_accept_tcp_single);

                        if (filter->listen_io == NULL)
                        {
                            LOGW("SocketManager: Couldnot listen on %s:[%u] , skipped...", option.host, p, proto_str);
                            continue;
                        }

                        LOGI("SocketManager: listening on %s:[%u] (%s)", option.host, p, proto_str);
                    }
                }
                else
                {
                singleport:;
                    if (ports_overlapped[port_min] == 1)
                        continue;
                    ports_overlapped[port_min] = 1;

                    LOGI("SocketManager: listening on %s:[%u] (%s)", option.host, port_min, proto_str);
                    filter->listen_io = hloop_create_tcp_server(loop, option.host, port_min, on_accept_tcp_single);

                    if (filter->listen_io == NULL)
                    {
                        LOGF("SocketManager: stopping due to null socket handle");
                        exit(1);
                    }
                }
            }
        }
    }
}

static HTHREAD_ROUTINE(accept_thread)
{
    hloop_t *loop = (hloop_t *)userdata;

    hmutex_lock(&(state->mutex));
    {
        uint8_t ports_overlapped[65536] = {0};
        listen_tcp(loop, ports_overlapped);
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

    state->iptables_installed = check_installed("iptables");
    state->lsof_installed = check_installed("lsof");
#if SUPOPRT_V6
    state->ip6tables_installed = check_installed("ip6tables");
#endif

    if (signal(SIGTERM, sig_handler) == SIG_ERR)
    {
        perror("Error setting SIGTERM signal handler");
        exit(1);
    }
    if (signal(SIGINT, sig_handler) == SIG_ERR)
    {
        perror("Error setting SIGINT signal handler");
        exit(1);
    }
    if (atexit(exit_hook) != 0)
    {
        perror("Error setting ATEXIT hook");
        exit(1);
    }

    return state;
}
