#include "preconnect_server.h"
#include "buffer_stream.h"
#include "hv/hsocket.h"
#include "loggers/network_logger.h"

typedef struct preconnect_server_state_s
{

} preconnect_server_state_t;

typedef struct preconnect_server_con_state_s
{
    bool init_sent;

} preconnect_server_con_state_t;

static void upStream(tunnel_t *self, context_t *c, TunnelFlowRoutine upstream)
{

    if (c->payload != NULL)
    {
        preconnect_server_con_state_t *cstate = CSTATE(c);
        if (c->first)
        {
            cstate->init_sent = true;
            self->up->upStream(self->up, newInitContext(c->line));
            if (! isAlive(c->line))
            {
                reuseContextBuffer(c);
                destroyContext(c);
                return;
            }
        }
        upstream(self->up, c);
    }
    else if (c->init)
    {
        preconnect_server_con_state_t *cstate = malloc(sizeof(preconnect_server_con_state_t));
        cstate->init_sent                     = false;
        CSTATE_MUT(c)                         = cstate;
        destroyContext(c);
        return;
    }
    else if (c->fin)
    {
        preconnect_server_con_state_t *cstate   = CSTATE(c);
        bool                           send_fin = cstate->init_sent;
        free(cstate);
        CSTATE_MUT(c) = NULL;
        if (send_fin)
        {
            upstream(self->up, c);
        }
        else
        {
            destroyContext(c);
        }

        return;
    }
}

static inline void downStream(tunnel_t *self, context_t *c, TunnelFlowRoutine downstream)
{

    if (c->fin)
    {
        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }

    downstream(self->dw, c);
}

static void preConnectServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c, self->up->upStream);
}
static void preConnectServerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c, self->up->packetUpStream);
}
static void preConnectServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c, self->dw->downStream);
}
static void preConnectServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c, self->dw->packetDownStream);
}

tunnel_t *newPreConnectServer(node_instance_context_t *instance_info)
{
    (void) instance_info;
    preconnect_server_state_t *state = malloc(sizeof(preconnect_server_state_t));
    memset(state, 0, sizeof(preconnect_server_state_t));

    tunnel_t *t         = newTunnel();
    t->state            = state;
    t->upStream         = &preConnectServerUpStream;
    t->packetUpStream   = &preConnectServerPacketUpStream;
    t->downStream       = &preConnectServerDownStream;
    t->packetDownStream = &preConnectServerPacketDownStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiPreConnectServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0}; 
}

tunnel_t *destroyPreConnectServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataPreConnectServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}