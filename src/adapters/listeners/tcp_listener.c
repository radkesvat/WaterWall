#include "tcp_listener.h"
#include "hv/hlog.h"
#include "utils/context_buffer.h"
#include <time.h>

#define STATE(x) ((tcp_listener_state_t *)((x)->state))
#define CSTATE(x) ((tcp_listener_con_state_t *)((((x)->base->chains_state)[self->chain_index])))

typedef void (*wantSocket)(tunnel_t *self, hio_t *io, uint16_t port, int proto);

typedef void (*registerSocketAcceptor)(tunnel_t *self, uint16_t pmin, uint16_t pmax, char *host, int proto,
                                       int multiport_backend, wantSocket);

typedef struct tcp_listener_state_s
{
    char *host;
    int port;
    hloop_t *loop;
    hio_t *listenio;

} tcp_listener_state_t;

typedef struct tcp_listener_con_state_s
{
    tunnel_t *tunnel;
    line_t *line;
    hio_t *io;
    context_buffer_t *queue;

    bool paused;
} tcp_listener_con_state_t;

static inline void upStream(tunnel_t *self, context_t *c)
{

    self->up->upStream(self->up, c);
}
static inline void downStream(tunnel_t *self, context_t *c)
{

    tcp_listener_con_state_t *cstate = CSTATE(c);
    cstate->io.upstream_io = c->src_io;
}

static void tcpListenerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void tcpListenerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void tcpListenerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void tcpListenerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

static void on_recv(hio_t *io, void *buf, int readbytes)
{
    line_t *base_con = (line_t *)(hevent_userdata(io));
    tunnel_t *self = ((tcp_listener_con_state_t *)base_con->chains_state[0])->tunnel;

    context_t *c = newContext(base_con);
    self->up->upStream(self->up, c);
}
static void on_close(hio_t *io) {}
void on_write_complete(hio_t *io, const void *buf, int writebytes)
{
    // line_t *base_con = (line_t *)(hevent_userdata(io));
    // tunnel_t *self = ((tcp_listener_con_state_t *)base_con->chains_state[0])->tunnel;

    hio_t *upstream_io = io->upstream_io;
    if (upstream_io && hio_write_is_complete(io))
    {
        // hio_setcb_write(io, NULL);
        hio_read(upstream_io);
    }
}

void hio_write_upstream(hio_t *io, void *buf, int bytes)
{
}

bool wants_socket(tunnel_t *self, hio_t *io)
{

    line_t *line = newLine();
    context_buffer_t *queue = newContextBuffer();
    tcp_listener_con_state_t *cstate = malloc(sizeof(tcp_listener_con_state_t));

    cstate->src_io = io;
    hevent_set_userdata(io, cstate);

    hio_setcb_read(io, on_recv);
    hio_setcb_close(io, on_close);
    hio_setcb_write(io, onWriteComplete);
    con->chains_state[0] = ;
    (() con->chains_state[0])->tunnel = self;

    return true;
}

static void on_accept(hio_t *io)
{

#ifdef DEBUG
    LOGD("on_accept connfd=%d\n", hio_fd(io));
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    LOGD("accept connfd=%d [%s] <= [%s]\n", hio_fd(io),
         SOCKADDR_STR(hio_localaddr(io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
#endif

    // hio_readbytes(io, 2);
}


tunnel_t *newTcpListeneristener(hloop_t *loop, cJSON* settings)
{
    tunnel_t *t = newTunnel();
    t->state = malloc(sizeof(tcp_listener_state_t));
    STATE(t)->loop = loop;
    STATE(t)->port = port;
    STATE(t)->host = host;
    STATE(t)->listenio = NULL;

    t->upStream = &tcpListenerUpStream;
    t->packetUpStream = &tcpListenerPacketUpStream;
    t->downStream = &tcpListenerDownStream;
    t->packetDownStream = &tcpListenerPacketDownStream;
}



void startTcpListeneristener(tunnel_t *self) {}