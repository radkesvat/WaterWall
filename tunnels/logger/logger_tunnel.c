#include "logger_tunnel.h"
#include "buffer_pool.h"
#include "loggers/network_logger.h"
#include "tunnel.h"
#include "utils/mathutils.h"

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

        LOGD("upstream: %zu bytes [ %.*s ]", bufLen(c->payload), min(bufLen(c->payload), 200), rawBuf(c->payload));
        if (self->up != NULL)
        {
            self->up->upStream(self->up, c);
        }
        else
        {

            // send back something
            {
                context_t *reply = newContextFrom(c);
                reply->payload   = popBuffer(getContextBufferPool(c));
                reuseContextPayload(c);
                destroyContext(c);
                sprintf((char *) rawBuf(reply->payload), "%s", "salam");
                setLen(reply->payload, strlen("salam"));
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
                context_t *est_reply = newContextFrom(c);
                destroyContext(c);
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
                destroyContext(c);
            }
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {

        LOGD("downstream: %zu bytes [ %.*s ]", bufLen(c->payload), min(bufLen(c->payload), 20), rawBuf(c->payload));
        if (self->dw != NULL)
        {
            self->dw->downStream(self->dw, c);
        }
        else
        {

            // send back something
            // {
            //     context_t *reply = newContextFrom(c);
            //     reply->payload   = popBuffer(getContextBufferPool(c));
            //     sprintf((char *) rawBuf(reply->payload), "%s", "salam");
            //     setLen(reply->payload, strlen("salam"));
            //     self->up->upStream(self->up, reply);
            // }

            reuseContextPayload(c);
            destroyContext(c);
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
                context_t *reply = newContextFrom(c);
                reply->est       = true;
                destroyContext(c);
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
                destroyContext(c);
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
                destroyContext(c);
            }
        }
    }
}

tunnel_t *newLoggerTunnel(node_instance_context_t *instance_info)
{
    (void) instance_info;
    tunnel_t *t   = newTunnel();
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
