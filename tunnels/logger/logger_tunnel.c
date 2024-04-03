#include "logger_tunnel.h"
#include "buffer_pool.h"
#include "loggers/network_logger.h"

#define STATE(x) ((logger_tunnel_state_t *)((x)->state))
#define CSTATE(x) ((logger_tunnel_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

#undef min
static inline size_t min(size_t x, size_t y) { return (((x) < (y)) ? (x) : (y)); }

typedef struct logger_tunnel_state_s
{

} logger_tunnel_state_t;

typedef struct logger_tunnel_con_state_s
{

} logger_tunnel_con_state_t;

static inline void upStream(tunnel_t *self, context_t *c)
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
                reply->payload = popBuffer(buffer_pools[c->line->tid]);
                DISCARD_CONTEXT(c);
                destroyContext(c);
                sprintf((char*)rawBuf(reply->payload), "%s", "salam");
                setLen(reply->payload, strlen("salam"));
                self->dw->downStream(self->dw, reply);
            }
            // context_t *reply = newFinContext(c->line);
            // destroyContext(c);
            // self->dw->downStream(self->dw, reply);
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
                context_t *replyx = newContextFrom(c);
                destroyContext(c);
                replyx->est = true;
                self->dw->downStream(self->dw, replyx);
            }
        }
        if (c->fin)
        {
            LOGD("upstream fin");
            if (self->up != NULL)
            {
                self->up->upStream(self->up, c);
            }
            else
                destroyContext(c);
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
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
            {
                context_t *reply = newContextFrom(c);
                reply->payload = popBuffer(buffer_pools[c->line->tid]);
                sprintf((char*)rawBuf(reply->payload), "%s", "salam");
                setLen(reply->payload, strlen("salam"));
                self->up->upStream(self->up, reply);
            }

            DISCARD_CONTEXT(c);
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
                reply->est = true;
                destroyContext(c);
                self->up->upStream(self->up, reply);
            }
        }
        if (c->fin)
        {
            LOGD("downstream fin");
            if (self->dw != NULL)
            {
                self->dw->downStream(self->dw, c);
            }
        }
        if (c->est)
        {
            LOGD("downstream est");
            if (self->dw != NULL)
            {
                self->dw->downStream(self->dw, c);
            }
        }
    }
}

static void loggerTunnelUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void loggerTunnelPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void loggerTunnelDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void loggerTunnelPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newLoggerTunnel(node_instance_context_t *instance_info)
{

    tunnel_t *t = newTunnel();

    t->upStream = &loggerTunnelUpStream;
    t->packetUpStream = &loggerTunnelPacketUpStream;
    t->downStream = &loggerTunnelDownStream;
    t->packetDownStream = &loggerTunnelPacketDownStream;
    return t;
}

api_result_t apiLoggerTunnel(tunnel_t *self, char *msg)
{
    LOGE("logger-tunnel API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyLoggerTunnel(tunnel_t *self)
{
    LOGE("logger-tunnel DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataLoggerTunnel()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}