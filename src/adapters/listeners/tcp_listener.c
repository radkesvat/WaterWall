#include "tcp_listener.h"
#include "hv/hlog.h"
#include "utils/context_buffer.h"
#include <time.h>
#include "dispatchers/socket_dispatcher.h"
#include <string.h>

#define STATE(x) ((tcp_listener_state_t *)((x)->state))

#define CSTATE(x) ((tcp_listener_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

typedef struct tcp_listener_state_s
{
    hloop_t *loop;
    // settings
    char* host;
    int multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    char **white_list_raddr;
    char **black_list_raddr;

} tcp_listener_state_t;

typedef struct tcp_listener_con_state_s
{
    tunnel_t *tunnel;
    line_t *line;
    hio_t *io;
    context_buffer_t *queue;

    bool write_paused;
    bool established;
} tcp_listener_con_state_t;

static inline void upStream(tunnel_t *self, context_t *c)
{

    self->up->upStream(self->up, c);
}
static inline void downStream(tunnel_t *self, context_t *c)
{
    tcp_listener_con_state_t *cstate = CSTATE(c);

    if (c->est)
    {
        cstate->established = true;
        return;
    }

    if (c->payload != NULL)
    {
        hio_setup_upstream(cstate->io, c->src_io);
        hio_write(cstate->io, rawBuf(c->payload), len(c->payload));
    }
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

    hio_t *upstream_io = hio_get_upstream(io);
    if (upstream_io && hio_write_is_complete(io))
    {
        hio_read(upstream_io);
    }
}

// void hio_write_upstream(hio_t *io, void *buf, int bytes)
// {
// }

bool wants_socket(tunnel_t *self, hio_t *io)
{

    line_t *line = newLine();

    tcp_listener_con_state_t *cstate = malloc(sizeof(tcp_listener_con_state_t));
    cstate->queue = newContextBuffer();
    cstate->line = line;
    cstate->io = io;
    cstate->tunnel = self;
    cstate->write_paused = false;
    cstate->established = false;
    line->chains_state[self->chain_index] = cstate;

    hevent_set_userdata(io, cstate);

    // io->upstream_io = NULL;
    hio_setcb_read(io, on_recv);
    hio_setcb_close(io, on_close);
    hio_setcb_write(io, on_write_complete);

    // send the init packet
    context_t *context = newContext(line);
    context->init = true;
    context->src_io = io;

    self->upStream(self, context);

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

tunnel_t *newTcpListener(hloop_t *loop, cJSON *settings)
{
    tunnel_t *t = newTunnel();
    t->state = malloc(sizeof(tcp_listener_state_t));
    STATE(t)->loop = loop;

    const cJSON *host = cJSON_GetObjectItemCaseSensitive(settings, "host");
    if (cJSON_IsString(host) && (host->valuestring != NULL))
    {
        STATE(t)->host = malloc(strlen(host->valuestring) + 1);
        strcpy(STATE(t)->host, host->valuestring);
    }
    else
    {
        LOGF("JSON Error: TcpListener->settings->host (string field) : The data was empty or invalid.", NULL);
        exit(1);
    }

    const cJSON *port = cJSON_GetObjectItemCaseSensitive(settings, "port");

    if ((cJSON_IsNumber(port) && (port->valuedouble != 0)))
    {
        // single port given as a number
        STATE(t)->port_min = port->valuedouble;
        STATE(t)->port_max = port->valuedouble;
    }
    else
    {

        if (cJSON_IsArray(port))
        {
            const cJSON *port_minmax;
            int i = 0;
            // multi port given
            cJSON_ArrayForEach(port_minmax, port)
            {
                if (!(cJSON_IsNumber(port_minmax) && (port_minmax->valuedouble != 0)))
                {
                    LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid.", NULL);
                    LOGF("JSON Error: MultiPort parsing failed.", NULL);
                    exit(1);
                }
                if (i == 0)
                    STATE(t)->port_min = port_minmax->valuedouble;
                else if (i == 1)
                    STATE(t)->port_max = port_minmax->valuedouble;
                else
                {
                    LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid.", NULL);
                    LOGF("JSON Error: MultiPort port range has more data than expected.", NULL);
                    exit(1);
                }

                i++;
            }
        }
        else
        {
            LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid.", NULL);
            exit(1);
        }
    }

    t->upStream = &tcpListenerUpStream;
    t->packetUpStream = &tcpListenerPacketUpStream;
    t->downStream = &tcpListenerDownStream;
    t->packetDownStream = &tcpListenerPacketDownStream;


}
