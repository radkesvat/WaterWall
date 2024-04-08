#include "preconnect_server.h"
#include "buffer_stream.h"
#include "hv/hsocket.h"
#include "loggers/network_logger.h"

#define STATE(x) ((preconnect_server_state_t *)((x)->state))
#define CSTATE(x) ((preconnect_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef struct preconnect_server_state_s
{

} preconnect_server_state_t;

typedef struct preconnect_server_con_state_s
{
    bool init_sent;

} preconnect_server_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
        preconnect_server_con_state_t *cstate = CSTATE(c);
        if (c->first)
        {
            cstate->init_sent = true;
            self->up->upStream(self->up, newInitContext(c->line));
            if (!ISALIVE(c))
            {
                DISCARD_CONTEXT(c);
                destroyContext(c);
                return;
            }
        }
        self->up->upStream(self->up, c);
    }
    else if (c->init)
    {
        preconnect_server_con_state_t *cstate = malloc(sizeof(preconnect_server_con_state_t));
        cstate->init_sent = false;
        CSTATE_MUT(c) = cstate;
        destroyContext(c);
        return;
    }
    else if (c->fin)
    {
        preconnect_server_con_state_t *cstate = CSTATE(c);
        bool send_fin = cstate->init_sent;
        free(cstate);
        CSTATE_MUT(c) = NULL;
        if (send_fin)
            self->up->upStream(self->up, c);
        else
            destroyContext(c);

        return;
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    if (c->fin)
    {
        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }

    self->dw->downStream(self->dw, c);
}

static void preConnectServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void preConnectServerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void preConnectServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void preConnectServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newPreConnectServer(node_instance_context_t *instance_info)
{

    preconnect_server_state_t *state = malloc(sizeof(preconnect_server_state_t));
    memset(state, 0, sizeof(preconnect_server_state_t));

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &preConnectServerUpStream;
    t->packetUpStream = &preConnectServerPacketUpStream;
    t->downStream = &preConnectServerDownStream;
    t->packetDownStream = &preConnectServerPacketDownStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiPreConnectServer(tunnel_t *self, char *msg)
{
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyPreConnectServer(tunnel_t *self)
{
    return NULL;
}
tunnel_metadata_t getMetadataPreConnectServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}