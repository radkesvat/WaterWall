#include "logger_tunnel.h"
#include "buffer_pool.h"
#include "loggers/network_logger.h"
#include "tunnel.h"


typedef struct logger_tunnel_state_s
{
    void *_;
} logger_tunnel_state_t;

typedef struct logger_tunnel_con_state_s
{
    void *_;

} logger_tunnel_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {

        LOGD("upstream: %zu bytes [ %.*s ]", sbufGetBufLength(c->payload), min(sbufGetBufLength(c->payload), 200), sbufGetRawPtr(c->payload));
        if (self->up != NULL)
        {
            self->up->upStream(self->up, c);
        }
        else
        {

            // send back something
            {
                context_t *reply = contextCreateFrom(c);
                reply->payload   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                contextReusePayload(c);
                contextDestroy(c);
                sprintf((char *) sbufGetRawPtr(reply->payload), "%s", "salam");
                sbufSetLength(reply->payload, strlen("salam"));
                self->dw->downStream(self->dw, reply);
            }
        }
    }
    else
    {
        if (c->init)
        {
            LOGD("upstream init");
            if (self->up != NULL)
            {
                self->up->upStream(self->up, c);
            }
            else
            {
                context_t *est_reply = contextCreateFrom(c);
                contextDestroy(c);
                est_reply->est = true;
                self->dw->downStream(self->dw, est_reply);
            }
        }
        else if (c->fin)
        {
            LOGD("upstream fin");
            if (self->up != NULL)
            {
                self->up->upStream(self->up, c);
            }
            else
            {
                contextDestroy(c);
            }
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {

        LOGD("downstream: %zu bytes [ %.*s ]", sbufGetBufLength(c->payload), min(sbufGetBufLength(c->payload), 20), sbufGetRawPtr(c->payload));
        if (self->dw != NULL)
        {
            self->dw->downStream(self->dw, c);
        }
        else
        {

            // send back something
            // {
            //     context_t *reply = contextCreateFrom(c);
            //     reply->payload   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
            //     sprintf((char *) sbufGetRawPtr(reply->payload), "%s", "salam");
            //     sbufSetLength(reply->payload, strlen("salam"));
            //     self->up->upStream(self->up, reply);
            // }

            contextReusePayload(c);
            contextDestroy(c);
        }
    }
    else
    {
        if (c->init)
        {
            LOGD("downstream init");
            if (self->dw != NULL)
            {
                self->dw->downStream(self->dw, c);
            }
            else
            {
                context_t *reply = contextCreateFrom(c);
                reply->est       = true;
                contextDestroy(c);
                self->up->upStream(self->up, reply);
            }
        }
        else if (c->fin)
        {
            LOGD("downstream fin");
            if (self->dw != NULL)
            {
                self->dw->downStream(self->dw, c);
            }
            else
            {
                contextDestroy(c);
            }
        }
        else if (c->est)
        {
            LOGD("downstream est");
            if (self->dw != NULL)
            {
                self->dw->downStream(self->dw, c);
            }
            else
            {
                contextDestroy(c);
            }
        }
    }
}

tunnel_t *newLoggerTunnel(node_instance_context_t *instance_info)
{
    (void) instance_info;
    tunnel_t *t   = tunnelCreate();
    t->upStream   = &upStream;
    t->downStream = &downStream;
    return t;
}

api_result_t apiLoggerTunnel(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyLoggerTunnel(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataLoggerTunnel(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = kNodeFlagChainHead};
}
