#include "socket_manager.h"
#include "ww.h"
#include "utils/procutils.h"
#include "hv/hthread.h"
#include "loggers/network_logger.h"

#define i_key socket_filter_t *
#define i_type filters_t
#define i_use_cmp // enable sorting/searhing using default <, == operators
#include "stc/vec.h"

#define SUPOPRT_V6 false
#define SO_ORIGINAL_DST 80

typedef struct socket_manager_s
{
    hthread_t accept_thread;
    hmutex_t mutex;
    filters_t filters;
    size_t last_round_tindex;
    bool iptables_installed;
    bool lsof_installed;
    bool iptable_cleaned;

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

void registerSocketAcceptor(tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{

    socket_filter_t *filter = malloc(sizeof(socket_filter_t));
    filter->tunnel = tunnel;
    filter->option = option;
    filter->cb = cb;
    filter->listen_io = NULL;
    hmutex_lock(&(state->mutex));
    filters_t_push(&state->filters, filter);
    hmutex_unlock(&(state->mutex));
}

static void on_accept_tcp(hio_t *io)
{
    // socket_manager_state_t *state = hevent_userdata(io);
    hmutex_lock(&(state->mutex));

    c_foreach(k, filters_t, state->filters)
    {
        socket_filter_t *filter = *(k.ref);
        socket_filter_option_t option = filter->option;
        uint16_t port_min = option.port_min;
        uint16_t port_max = option.port_max;

        sockaddr_u *laddr = (sockaddr_u *)hio_localaddr(io);
        uint16_t socket_port = sockaddr_port(laddr);

        if (option.proto == socket_protocol_tcp)
        {

            // single port or multi port per socket
            if (port_min <= socket_port && port_max >= socket_port)
            {
                socket_accept_result_t *result = malloc(sizeof(socket_accept_result_t));
                result->realport = 0;

                if (option.multiport_backend == multiport_backend_iptables)
                {
                    unsigned char pbuf[28]= {0};
                    int size = 16; // todo ipv6 value is 28
                    if (getsockopt(hio_fd(io), SOL_IP, SO_ORIGINAL_DST, &(pbuf[0]), &size) < 0)
                    {
                        LOGE("SocketManger: multiport failure getting origin port");
                        free(result);
                        hmutex_unlock(&(state->mutex));
                        return;
                    }

                    result->realport = (pbuf[2]<< 8) |  pbuf[3] ;
                }

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
                hmutex_unlock(&(state->mutex));
                hloop_post_event(worker_loop, &ev);

                return;
            }
        }
    }

    hmutex_unlock(&(state->mutex));

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};

    LOGE("SocketManager CouldNot find consumer for socket!\ntid=%ld connfd=%d [%s] <= [%s]\n",
         (long)hv_gettid(),
         (int)hio_fd(io),
         SOCKADDR_STR(hio_localaddr(io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    hio_close(io);
}

static HTHREAD_ROUTINE(accept_thread)
{
    hloop_t *loop = (hloop_t *)userdata;

    uint8_t ports_overlapped[65536] = {0};
    hmutex_lock(&(state->mutex));

    c_foreach(k, filters_t, state->filters)
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

                if (!state->iptable_cleaned)
                {
                    if (!reset_iptables())
                    {
                        LOGF("SocketManager: could not clear iptables rusles");
                        exit(1);
                    }
                    state->iptable_cleaned = true;
                }
                uint16_t main_port = port_min;
                // select main port
                {
                    for (size_t i = 0; i <= port_max - port_min; i++)
                    {
                        if (ports_overlapped[main_port] == 1)
                            continue;
                        filter->listen_io = hloop_create_tcp_server(loop, option.host, main_port, on_accept_tcp);
                        if (filter->listen_io != NULL)
                        {
                            ports_overlapped[main_port] = 1;
                            break;
                        }
                        main_port++;
                    }
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
                        continue;
                    ports_overlapped[port_min] = 1;

                    LOGI("SocketManager: listening on %s:[%u] (%s)", option.host, port_min, proto_str);
                    filter->listen_io = hloop_create_tcp_server(loop, option.host, port_min, on_accept_tcp);

                    if (filter->listen_io == NULL)
                    {
                        LOGF("filter->listen_io == NULL");
                        exit(1);
                    }

                    LOGI("SocketManager: listening on %s:[%u - %u] (%s)", option.host, port_min, port_max, proto_str);
                }
            }
            else
            {
            singleport:;
                if (ports_overlapped[port_min] == 1)
                    continue;
                ports_overlapped[port_min] = 1;

                LOGI("SocketManager: listening on %s:[%u] (%s)", option.host, port_min, proto_str);
                filter->listen_io = hloop_create_tcp_server(loop, option.host, port_min, on_accept_tcp);

                if (filter->listen_io == NULL)
                {
                    LOGF("SocketManager: stopping due to null socket handle");
                    exit(1);
                }
            }
        }
        else
        {
            // TODO UDP
            exit(1);
        }
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
    hloop_t *new_loop = hloop_new(HLOOP_FLAG_AUTO_FREE);
    state->accept_thread = hthread_create(accept_thread, new_loop);
}

socket_manager_state_t *createSocketManager()
{
    assert(state == NULL);
    state = malloc(sizeof(socket_manager_state_t));
    memset(state, 0, sizeof(socket_manager_state_t));
    state->filters = filters_t_init();
    hmutex_init(&state->mutex);

    state->iptables_installed = check_installed("iptables");
    state->lsof_installed = check_installed("lsof");

    return state;
}
