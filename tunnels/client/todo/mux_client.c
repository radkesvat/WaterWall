#include "mux_client.h"
#include "loggers/network_logger.h"
#include "hv.h"
#include "hloop.h"
#include <time.h>

#define TSTATE(x) ((mux_state_t *)((x)->state))

#define CSTATE(x) ((line_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

#define CHILDREN_VEC_INIT_CAP 1024
#define CONNECT_TIME_OUT 3
// 2 bytes id 2 bytes hsize
#define HEADER_SIZE 4

#define i_type hmap_iio //NOLINT
#define i_key uint16_t //NOLINT
#define i_val line_t * //NOLINT

#include "stc/hmap.h"

typedef struct up_con_s
{
    line_t *connection;

    size_t init_epoch;
    size_t est_epoch;
    bool init_sent;
    bool established;
    line_t *current_child;
    uint16_t bytes_left;
    char header[HEADER_SIZE];
    size_t h_index;

} up_con_t;

typedef struct mux_state_s
{
    int run_mode;
    size_t parallel_lines;

    up_con_t *up_cons;

    hmap_iio dw_cons;
    hmap_iio waiters;

    // hio_t *dw_cons[1 << 16]; // 600 KB

    uint16_t last_child_id;

} mux_state_t;

static inline uint16_t newid(mux_state_t *ms)
{
    do
    {
        ++(ms->last_child_id);
    } while (ms->last_child_id == 0 || !hmap_iio_contains(&ms->dw_cons, ms->last_child_id));
    return ms->last_child_id;
}

static void closeChildern(tunnel_t *self, int up_id)
{
    mux_state_t *state = TSTATE(self);

#ifdef DEBUG
    assert(up_id != 0);
#endif
    c_foreach(n, hmap_iio, state->dw_cons)
    {
        if (n.ref->first % up_id == 0)
        {
            context_t *icx = newContext(n.ref->second);
            icx->fin = true;
            self->dw->downStream(self->dw, icx);
            destroyContext((context_t *)n.ref->second);
        }
    }
    hmap_iio_clear(&(state->dw_cons));
    c_foreach(n, hmap_iio, state->waiters)
    {
        if (n.ref->first % up_id == 0)
        {
            context_t *icx = newContext(n.ref->second);
            icx->fin = true;
            self->dw->downStream(self->dw, icx);
            destroyContext((context_t *)n.ref->second);
        }
    }
    hmap_iio_clear(&(state->waiters));
}

static void checkUpCon(tunnel_t *self, size_t up_id)
{
    mux_state_t *state = TSTATE(self);
    up_con_t *upcon = &state->up_cons[up_id];
    struct timespec ts;

    if (!upcon->init_sent)
    {
        LOGI("Mux Connecting...");

        timespec_get(&ts, TIME_UTC);
        upcon->init_epoch = ts.tv_sec;
        upcon->connection = newLine();
        upcon->connection->id = up_id;
        context_t *clone = newContext(upcon->connection);
        clone->init = true;
        self->up->upStream(self->up, clone);
        return;
    }
    if (!upcon->established)
    {
        timespec_get(&ts, TIME_UTC);
        if (upcon->init_epoch - ts.tv_sec > CONNECT_TIME_OUT)
        {
            LOGW("Mux Connect Timeout!");
            context_t *clone = newContext(upcon->connection);
            clone->fin = true;
            self->up->upStream(self->up, clone);
            memset(upcon, 0, sizeof(up_con_t));

            return;
        }
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
    mux_state_t *state = TSTATE(self);
    // find proper up id

    // child id
    if (c->line->id == 0)
    {
        uint16_t id = newid(state);
        c->line->id = id; // modify base context with new id
    }
    uint16_t up_id = c->line->id % state->parallel_lines;

    if (c->init)
    {
        if (state->up_cons[up_id].established == false)
        {
            hmap_iio_insert(&state->waiters, c->line->id, c->line);
            checkUpCon(self, up_id);
        }
        else
        {
            // its already established!
            hmap_iio_insert(&state->dw_cons, c->line->id, c->line);
            // c->line->dest_io = state->up_cons[up_id].connection->dest_io;
            c->init = false;
            c->est = true;
            self->dw->downStream(self->dw, c);
            return;
        }
    }

    if (c->first)
    {
        assert(state->up_cons[up_id].established); // you must not send data when not connected
        CSTATE_MUT(c) = &(state->up_cons[up_id].connection);
    }
    else if (CSTATE(c) != (void *)(state->up_cons[up_id].connection))
    {
        // is from a destroyed previous mux line
        LOGW("A destroyedLine's dw_cons is talking to MuxUpStream");
        reuseContextBuffer(c);
        c->fin = true;
        self->dw->downStream(self->dw, c);
        return;
    }
    context_t *redir_context = newContext(state->up_cons[up_id].connection);
    redir_context->src_io = c->src_io;
    redir_context->line->id = c->line->id;

    if (c->fin)
    {
        // forget this con
        if (CSTATE(c) != NULL)
        {
            redir_context->payload = popBuffer();
            CSTATE_MUT(c) = NULL;
            hmap_iio_iter f_iter = hmap_iio_find(&state->dw_cons, c->line->id);
            assert(f_iter.ref != hmap_iio_end(&state->dw_cons).ref);
            line_t *dw_con = f_iter.ref->second;
            destroyContext(c);
            destroyContext((context_t *)dw_con);
            hmap_iio_erase_at(&state->dw_cons, f_iter);
        }
        else
        {
            hmap_iio_iter f_iter = hmap_iio_find(&state->waiters, c->line->id);
            assert(f_iter.ref != hmap_iio_end(&state->waiters).ref);
            line_t *dw_con = f_iter.ref->second;

            destroyContext(c);
            destroyContext((context_t *)dw_con);
            hmap_iio_erase_at(&state->waiters, f_iter);
            return;
        }
    }
    else
    {
        redir_context->payload = c->payload;
    }

    // id header
    shiftl(redir_context->payload, sizeof(redir_context->line->id));
    writeUI16(redir_context->payload, redir_context->line->id);
    // size header
    shiftl(redir_context->payload, sizeof(uint16_t));
    writeUI16(redir_context->payload, (uint16_t)bufLen(redir_context->payload));

    self->up->upStream(self->up, redir_context);
}

static void downStream(tunnel_t *self, context_t *c)
{
    mux_state_t *state = TSTATE(self);

#ifdef DEBUG
    assert(c->line->id != 0);
#endif
    uint16_t up_id = c->line->id;

    if (c->fin)
    {
        // bad news
        closeChildern(self, up_id);
        destroyContext(c);
        memset(&state->up_cons[up_id], 0, sizeof(up_con_t));
        return;
    }

    if (c->est)
    {
        struct timespec ts;
        timespec_get(&ts, TIME_UTC);

        state->up_cons[up_id].established = true;
        state->up_cons[up_id].est_epoch = ts.tv_sec;

        // state->up_cons[up_id].connection->dest_io = c->line->dest_io;
        c_foreach(n, hmap_iio, state->waiters)
        {
            if (n.ref->first % up_id == 0)
            {
                // CSTATE_MUT((n.ref->second)) = NULL;

                // (n.ref->second)->dest_io = state->up_cons[up_id].connection->dest_io;
                context_t *icx = newContext((n.ref->second));
                icx->est = true;

                self->dw->downStream(self->dw, icx);
            }
        }
        destroyContext(c);

        return;
    }

    // extract header correctly even if buffering is required
    // without blocking the flow!
process:;
    if (bufLen(c->payload) <= 0)
    {
        reuseContextBuffer(c);
        destroyContext(c);
        return;
    }

    up_con_t *up_state = &(state->up_cons[up_id]);
    if (up_state->bytes_left > 0)
    {
        if (bufLen(c->payload) <= up_state->bytes_left)
        {
            // forward the buffer
            assert(up_state->current_child != 0);
            up_state->bytes_left -= bufLen(c->payload);

            self->dw->downStream(self->dw, c);
            return;
        }
        else
        {
            // shadow buffer
            shift_buffer_t *copybuf = newShallowShiftBuffer(c->payload);
            setLen(copybuf, up_state->bytes_left);

            context_t *ctx = newContext(state->up_cons[up_id].current_child);
            ctx->payload = copybuf;
            // we consumed bytes_left
            shiftr(c->payload, up_state->bytes_left);

            self->dw->downStream(self->dw, ctx);
            up_state->bytes_left = 0;
            goto process;
        }
    }
    else
    {
        size_t rq_bytes = (HEADER_SIZE - up_state->h_index) - bufLen(c->payload);
        if (rq_bytes > 0)
        {
            // incomplete header
            memcpy(&(up_state->header) + up_state->h_index, rawBuf(c->payload), bufLen(c->payload));
            up_state->h_index += bufLen(c->payload);
            reuseBuffer(c->payload);
            return;
        }
        else if (rq_bytes < 0)
        {
            // header + some of payload
            memcpy(&(up_state->header) + up_state->h_index, rawBuf(c->payload), (HEADER_SIZE - up_state->h_index));
            shiftr(c->payload, HEADER_SIZE - up_state->h_index);
            up_state->h_index = 0;
        }
        else
        {
            // just the header
            memcpy(&(up_state->header) + up_state->h_index, rawBuf(c->payload), (HEADER_SIZE - up_state->h_index));
            shiftr(c->payload, HEADER_SIZE - up_state->h_index);
            up_state->h_index = 0;
        }
    }

    // read back id & len from header
    uint16_t id = 0;
    memcpy(&id, &(up_state->header), sizeof(uint16_t));
    memcpy(&(up_state->bytes_left), (&(up_state->header)) + sizeof(uint16_t), sizeof(up_state->bytes_left));
    // current_child

    hmap_iio_iter f_iter = hmap_iio_find(&state->dw_cons, id);
    if (f_iter.ref == hmap_iio_end(&state->dw_cons).ref)
    {
        LOGE("MuxDownStream: Invalid child id");
        goto process;
    }
    line_t *con = f_iter.ref->second;
    up_state->current_child = con;

    // check if this is a close signal
    if (up_state->bytes_left == 0)
    {
        // con->dest_io = c->line->dest_io;
        context_t *ctx = newContext(con);

        ctx->fin = true;
        // forget this con
        hmap_iio_erase_at(&state->dw_cons, f_iter);
        destroyContext((context_t *)con);

        self->dw->downStream(self->dw, ctx);
        goto process;
    }
    else
    {
        // if we consumed all the data
        if (bufLen(c->payload) == 0)
        {
            return;
        }
        else
        {
            goto process;
        }
    }
}

static void muxUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void muxPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void muxDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void muxPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newMuxClientTunnel(size_t parallel_lines)
{

    tunnel_t *t = newTunnel();
    t->state = wwmGlobalMalloc(sizeof(mux_state_t));
    memset(t->state, 0, sizeof(mux_state_t));
    TSTATE(t)->parallel_lines = parallel_lines;

    t->upStream = &muxUpStream;
    t->packetUpStream = &muxPacketUpStream;
    t->downStream = &muxDownStream;
    t->packetDownStream = &muxPacketDownStream;

    assert(parallel_lines > 0);
    TSTATE(t)->up_cons = wwmGlobalMalloc(TSTATE(t)->parallel_lines * sizeof(up_con_t));

    TSTATE(t)->dw_cons = hmap_iio_with_capacity(CHILDREN_VEC_INIT_CAP);
    TSTATE(t)->waiters = hmap_iio_with_capacity(CHILDREN_VEC_INIT_CAP);

    // for (size_t i = 0; i < TSTATE(t)->parallel_lines; i++)
    // {
    //     TSTATE(t)->up_cons[i] = allocateUpCon(i, t->chain_index);
    // }
}
