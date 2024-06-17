#include "preconnect_server.h"
#include "buffer_stream.h"
#include "hsocket.h"
#include "loggers/network_logger.h"

typedef struct preconnect_server_state_s
{
    void *_;
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
            if (! isAlive(c->line))
            {
                reuseContextBuffer(c);
                destroyContext(c);
                return;
            }
        }
        self->up->upStream(self->up, c);
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
        CSTATE_DROP(c);
        if (send_fin)
        {
            self->up->upStream(self->up, c);
        }
        else
        {
            destroyContext(c);
        }

        return;
    }
}

static void downStream(tunnel_t *self, context_t *c)
{

    if (c->fin)
    {
        free(CSTATE(c));
        CSTATE_DROP(c);
    }

    self->dw->downStream(self->dw, c);
}

tunnel_t *newPreConnectServer(node_instance_context_t *instance_info)
{
    (void) instance_info;
    preconnect_server_state_t *state = malloc(sizeof(preconnect_server_state_t));
    memset(state, 0, sizeof(preconnect_server_state_t));

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    

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
tunnel_metadata_t getMetadataPreConnectServer(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
