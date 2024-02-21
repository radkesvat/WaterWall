#include "socket_manager.h"
#include "hv/hv.h"
#include "loggers/core_logger.h"

#define i_key socket_filter_t *
#define i_type filters_t
#define i_use_cmp // enable sorting/searhing using default <, == operators
#include "stc/vec.h"


typedef struct socket_manager_s
{
    hmutex_t mutex;
    filters_t filters;

} socket_manager_state_t;

static socket_manager_state_t *state = NULL;


void registerSocketAcceptor(hloop_t **loops, tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{

    socket_filter_t *filter = malloc(sizeof(socket_filter_t));
    filter->loops = loops;
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
    socket_manager_state_t *state = hevent_userdata(io);
    hmutex_lock(&(state->mutex));

    c_foreach(k, filters_t, state->filters)
    {
        socket_filter_t *filter = *(k.ref);
        socket_filter_option_t option = filter->option;
        uint16_t port_min = option.port_min;
        uint16_t port_max = option.port_max;

        sockaddr_u *laddr = (sockaddr_u *)hio_localaddr(io);
        uint16_t socket_port = sockaddr_port(laddr);
        uint16_t redirected_port = 0;

        if (option.proto == socket_protocol_tcp)
        {

            if (redirected_port == 0)
            {
                // single port or multi port per socket
                if (port_min <= socket_port && port_max >= socket_port)
                {
                    char localaddrstr[SOCKADDR_STRLEN] = {0};
                    char peeraddrstr[SOCKADDR_STRLEN] = {0};
                    LOGD("SocketManager Accepted [%s] <= [%s]",
                         (long)hv_gettid(),
                         (int)hio_fd(io),
                         SOCKADDR_STR(hio_localaddr(io), localaddrstr),
                         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
                    hio_detach(io);
                    // TODO load balance threads
                    hloop_t *main_loop = filter->loops[0];

                    hevent_t ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.loop = main_loop;
                    ev.cb = filter->cb;

                    socket_accept_result_t *result = malloc(sizeof(socket_accept_result_t));
                    result->io = io;
                    result->tunnel = filter->tunnel;
                    ev.userdata = result;
                    hloop_post_event(main_loop, &ev);
                    hmutex_unlock(&(state->mutex));

                    return;
                }
            }
            else
            {
                // TODO: get redir port
                exit(1);
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
}

static HTHREAD_ROUTINE(accept_thread)
{
    hloop_t *loop = (hloop_t *)userdata;
    socket_manager_state_t *state = hloop_userdata(loop);

    uint8_t ports_overlapped[65536] = {0};
    hmutex_lock(&(state->mutex));

    c_foreach(k, filters_t, state->filters)
    {
        socket_filter_t *filter = *(k.ref);
        socket_filter_option_t option = filter->option;
        uint16_t port_min = option.port_min;
        uint16_t port_max = option.port_max;
        const char *poroto_str = option.proto == socket_protocol_tcp ? "TCP" : "UDP";
        assert(port_min <= port_max);

        if (option.proto != socket_protocol_tcp)
        {

            if (option.multiport_backend == multiport_backend_iptables)
            {
                // TODO iptable
                exit(1);
            }
            else
            {

                if (option.multiport_backend == multiport_backend_sockets)
                {
                    for (size_t p = port_min; p < port_max; p++)
                    {
                        if (ports_overlapped[p] == 1)
                            continue;
                        ports_overlapped[port_min] = 1;

                        LOGI("SocketManager will watch %s:{%u} (%s)", option.host, port_min, poroto_str);
                        filter->listen_io = hloop_create_tcp_server(loop, option.host, port_min, on_accept_tcp);

                        if (filter->listen_io == NULL)
                            exit(1);

                        LOGI("SocketManager will watch %s:{%u - %u} (%s)", option.host, port_min, port_max, poroto_str);
                    }
                }
                else
                {
                    if (ports_overlapped[port_min] == 1)
                        continue;
                    ports_overlapped[port_min] = 1;

                    LOGI("SocketManager will watch %s:{%u} (%s)", option.host, port_min, poroto_str);
                    filter->listen_io = hloop_create_tcp_server(loop, option.host, port_min, on_accept_tcp);

                    if (filter->listen_io == NULL)
                        exit(1);

                    LOGI("SocketManager will watch %s:{%u - %u} (%s)", option.host, port_min, port_max, poroto_str);
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

struct socket_manager_s *getSocketManager(){
    return state;
}

void setSocketManager(struct socket_manager_s * new_state){
    assert(state == NULL);
    state = new_state;
}

void startSocketManager()
{

    LOGI("Spawning AcceptThread...");
    hloop_t *new_loop = hloop_new(HLOOP_FLAG_AUTO_FREE);
    hloop_set_userdata(new_loop, state);

    hthread_create(accept_thread, new_loop);
}

socket_manager_state_t *createSocketManager()
{

    state = malloc(sizeof(socket_manager_state_t));
    memset(state, 0, sizeof(socket_manager_state_t));

    state->filters = filters_t_init();
    hmutex_init(&state->mutex);
}