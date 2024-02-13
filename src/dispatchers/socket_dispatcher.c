#include "socket_dispatcher.h"
#include "hv/hv.h"

typedef struct socket_filter_s
{
    hio_t *listen_io;

    socket_filter_option_t option;
    hloop_t *loop;
    tunnel_t *tunnel;
    onAccept cb;
} socket_filter_t;

#define i_key socket_filter_t *
#define i_type filters_t
#define i_use_cmp // enable sorting/searhing using default <, == operators
#include "stc/vec.h"

typedef struct socket_dispatcher_state_s
{

    filters_t filters;

} socket_dispatcher_state_t;

static socket_dispatcher_state_t *global_state = NULL;

void registerSocketAcceptor(hloop_t *loop, tunnel_t *tunnel, socket_filter_option_t option, onAccept cb)
{
    socket_filter_t *filter = malloc(sizeof(socket_filter_t));
    filter->loop = loop;
    filter->tunnel = tunnel;
    filter->option = option;
    filter->cb = cb;

    filters_t_push(&global_state->filters, filter);
}

static void on_accept_tcp(hio_t *io)
{

    c_foreach(k, filters_t, global_state->filters)
    {
        socket_filter_t *filter = *(k.ref);
        socket_filter_option_t option = filter->option;
        uint16_t port_min = option.port_min;
        uint16_t port_max = option.port_max;

        if (option.proto == socket_protocol_tcp)
        {
            sockaddr_u *laddr = (sockaddr_u *)hio_localaddr(io);
            uint16_t socket_port = sockaddr_port(laddr);
            uint16_t redirected_port = 0;
            // TODO: get redir port
            if (redirected_port == 0)
            {
                // single port or multi port per socket
                if (port_min <= socket_port && port_max >= socket_port)
                {
                    hio_detach(io);
                    hloop_t *main_loop = filter->loop;
                    hevent_t ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.loop = main_loop;
                    ev.cb = filter->cb;
                    ev.userdata = io;
                    hloop_post_event(main_loop, &ev);
                    return;
                }
            }
            else
            {
                exit(1);
            }
        }
    }
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    LOGE("SocketDispatcher CouldNot Find target for socket!\ntid=%ld connfd=%d [%s] <= [%s]\n",
         (long)hv_gettid(),
         (int)hio_fd(io),
         SOCKADDR_STR(hio_localaddr(io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
}

static HTHREAD_ROUTINE(accept_thread)
{
    hloop_t *loop = (hloop_t *)userdata;

    c_foreach(k, filters_t, global_state->filters)
    {
        socket_filter_t *filter = *(k.ref);
        socket_filter_option_t option = filter->option;
        uint16_t port_min = option.port_min;
        uint16_t port_max = option.port_max;
        const char *poroto_str = option.proto == socket_protocol_tcp ? "TCP" : "UDP";

        if (option.multiport_backend == multiport_backend_nothing)
        {
            LOGI("SocketDispatcher will watch %s:{%u} (%s)", option.host, port_min, poroto_str);
            hio_t *listenio = NULL;
            if (option.proto == socket_protocol_tcp)
            {
                hloop_create_tcp_server(loop, option.host, port_min, on_accept_tcp);
            }
            else
            {
                exit(1);
            }

            if (listenio == NULL)
            {
                exit(1);
            }
            filter->listen_io = listenio;
        }
        else
        {
            LOGI("SocketDispatcher will watch %s:{%u - %u} (%s)", option.host, port_min, port_max, poroto_str);
            exit(1);
        }
    }

    hloop_run(loop);
    return 0;
}

void startSocketDispatcher()
{

    LOGI("Spawning AcceptThread...", NULL);

    hthread_create(accept_thread, hloop_new(HLOOP_FLAG_AUTO_FREE));
}

void initSocketDispatcher()
{
    if (global_state != NULL)
    {
        LOGF("initSocketDispatcher called twice!", NULL);
        exit(1);
    }

    global_state = malloc(sizeof(socket_dispatcher_state_t));

    global_state->filters = filters_t_init();
}
