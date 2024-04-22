#include "mux_client.h"
#include "hlog.h"
#include "utils/context_queue.h"
#include <time.h>

typedef struct zero_rtt_uuid_s
{
    uint32_t epoch_sec;
    uint32_t epoch_nsec;
} zero_rtt_uuid_t;

typedef struct zero_rtt_con_s
{

    // connection_t *up;
    line_t *dw;

    bool paused;
    context_queue_t *queue;

    bool est_sent;

} zero_rtt_con_t;

typedef void *zero_rtt_con_state_t;

typedef struct zero_rtt_state_s
{
    zero_rtt_uuid_t uuid;
} zero_rtt_state_t;

#define STATE(x) ((zero_rtt_state_t *)(x->state))

#define CSTATE(x) ((zero_rtt_con_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

#define VEC_INIT_CAP 10

static zero_rtt_uuid_t global_last_uuid = {0};

static zero_rtt_uuid_t newUUID()
{
    struct timespec ts;

    while (true)
    {
        timespec_get(&ts, TIME_UTC);
        zero_rtt_uuid_t uuid = {0};
        uuid.epoch_sec = (uint32_t)ts.tv_sec;
        uuid.epoch_nsec = (uint32_t)ts.tv_nsec;
        
        if (uuid.epoch_sec == global_last_uuid.epoch_sec && uuid.epoch_nsec == global_last_uuid.epoch_nsec)
        {
            return uuid;
        }


    }
}

static void restablish(tunnel_t *self, context_t *src_base_ctx)
{
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    zero_rtt_con_t *cstate = CSTATE(c);

    if (cstate == NULL)
    {
        cstate = malloc(sizeof(zero_rtt_con_t));
        cstate->queue = newContextQueue();
        cstate->dw = c->line;
        shiftl(c->payload, sizeof(STATE(self)->uuid.epoch_sec));
        writeUI32(c->payload, STATE(self)->uuid.epoch_sec);
        shiftl(c->payload, sizeof(STATE(self)->uuid.epoch_nsec));
        writeUI32(c->payload, STATE(self)->uuid.epoch_nsec);

        // initiation

        self->up->upStream(self->up, c);
        // }
        // else
        // {
        //     // up is closed!
        //     cstate->paused = true;
        //     hio_read_stop(c->src_io);
        //     push(cstate->queue, c);
        //     context_t *forward = newContext(c->line);
        //     forward->src_io = c->src_io;
        //     forward->init = true;
        //     self->up->upStream(self->up, forward);
        // }

        return;
    }
    if (c->fin)
    {
        destroyContextQueue(cstate->queue);
        free(cstate);
        CSTATE_MUT(c) = NULL;
        self->up->upStream(self->up, c);
        return;
    }

    if (cstate->paused)
    {
        cstate->paused = true;
        hio_read_stop(c->src_io);
        contextQueuePush(cstate->queue, c);
        return;
    }

    self->up->upStream(self->up, c);
}
static inline void downStream(tunnel_t *self, context_t *c)
{
    zero_rtt_con_t *cstate = CSTATE(c);
    if (c->est)
    {
        assert(cstate != NULL);

        if (!cstate->est_sent)
        {
            cstate->est_sent = true;
            self->dw->downStream(self->dw, c);
        }
        else
        {
            assert(cstate!= NULL); // we got the io
            destroyContext(c);

            if (cstate->paused)
            {
                while(contextQueueLen(cstate->queue)>0){
                    context_t* buffered_c = contextQueuePop(cstate->queue);
                    hio_read(buffered_c->src_io);
                    self->up->upStream(self->up, buffered_c);
                    
                }

                cstate->paused = false;
            }
        }

        return;
    }
    // we get no header back
    // dont pass fin packet, just re connect
    if (c->fin)
    {
        LOGW("zerortt reconnecting",NULL);
        cstate->paused = true;

        context_t *forward = newContext(cstate->dw);
        forward->src_io = NULL;
        forward->init = true;
        self->up->upStream(self->up, forward);
        return;
    }

    self->dw->downStream(self->dw, c);
}

static void zrttUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void zrttPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void zrttDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void zrttPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newZeroRttClientTunnel()
{

    tunnel_t *t = newTunnel();
    t->state = malloc(sizeof(zero_rtt_state_t));
    memset(t->state, 0, sizeof(zero_rtt_state_t));

    STATE(t)->uuid = newUUID();

    t->upStream = &zrttUpStream;
    t->packetUpStream = &zrttPacketUpStream;
    t->downStream = &zrttDownStream;

    t->packetDownStream = &zrttPacketDownStream;
}
