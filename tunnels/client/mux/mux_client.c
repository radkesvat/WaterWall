#include "mux_client.h"
#include "buffer_stream.h"
#include "loggers/network_logger.h"
#include "mux_frame.h"
#include "utils/jsonutils.h"

enum concurrency_mode
{
    kCuncurrencyModeTimer   = 1,
    kCuncurrencyModeCounter = 2
};

#define i_type    vec_cons                        // NOLINT
#define i_key     struct mux_client_con_state_s * // NOLINT
#define i_use_cmp                                 // NOLINT
#include "stc/vec.h"

typedef struct thread_connection_pool_s
{
    vec_cons cons;
    size_t   round_index;

} thread_connection_pool_t;

typedef struct mux_client_state_s
{
    enum concurrency_mode    mode;
    uint32_t                 connection_cunc_duration;
    uint32_t                 connection_cunc_capacity;
    thread_connection_pool_t threadlocal_cons[];

} mux_client_state_t;

typedef struct mux_client_child_con_state_s
{

    struct mux_client_child_con_state_s *next, *prev;
    tunnel_t                            *tunnel;
    line_t                              *line;
    line_t                              *parent;
    uint32_t                             sent_nack;
    uint32_t                             recv_nack;
    uint16_t                             cid;
    bool                                 paused;

} mux_client_child_con_state_t;

typedef struct mux_client_con_state_s
{
    struct mux_client_child_con_state_s children_root;

    tunnel_t        *tunnel;
    line_t          *line;
    line_t          *current_writing_line;
    buffer_stream_t *read_stream;
    uint64_t         creation_epoch;
    uint16_t         last_cid;
    uint16_t         cid_min;
    uint16_t         cid_max;
    uint16_t         contained;

} mux_client_con_state_t;

static void onChildLinePaused(void *arg)
{
    mux_client_child_con_state_t *stream = (mux_client_child_con_state_t *) arg;
    pauseLineUpSide(stream->parent);
}
static void onChildLineResumed(void *arg)
{
    mux_client_child_con_state_t *stream = (mux_client_child_con_state_t *) arg;
    resumeLineUpSide(stream->parent);
}

static void onMainLinePaused(void *arg)
{
    mux_client_con_state_t *con  = (mux_client_con_state_t *) arg;
    tunnel_t               *self = con->tunnel;

    line_t *wline = con->current_writing_line;
    if (wline && isAlive(wline))
    {
        mux_client_child_con_state_t *child_con = LSTATE(wline);
        child_con->paused                       = true;
        pauseLineDownSide(child_con->line);
    }
}

static void onMainLineResumed(void *arg)
{
    mux_client_con_state_t       *con = (mux_client_con_state_t *) arg;
    mux_client_child_con_state_t *child_con_i;
    for (child_con_i = con->children_root.next; child_con_i;)
    {
        if (child_con_i->paused)
        {
            child_con_i->paused = false;
            resumeLineDownSide(child_con_i->line);
        }
        child_con_i = child_con_i->next;
    }
}

static void destroyChildConnecton(mux_client_child_con_state_t *child)
{
    tunnel_t *self    = child->tunnel;
    child->prev->next = child->next;
    if (child->next)
    {
        child->next->prev = child->prev;
    }
    doneLineUpSide(child->line);
    LSTATE_DROP(child->line);
    globalFree(child);
}

static mux_client_child_con_state_t *createChildConnection(mux_client_con_state_t *parent, line_t *child_line)
{
    mux_client_child_con_state_t *child = globalMalloc(sizeof(mux_client_con_state_t));

    *child = (mux_client_child_con_state_t) {.tunnel = parent->tunnel,
                                             .line   = child_line,
                                             .cid    = parent->last_cid++,
                                             .next   = parent->children_root.next,
                                             .prev   = &(parent->children_root)

    };

    parent->children_root.next = child;

    if (child->next)
    {
        child->next->prev = child;
    }
    setupLineDownSide(child->line, onChildLinePaused, child, onChildLineResumed);

    return child;
}

static void destroyMainConnecton(mux_client_con_state_t *con)
{
    tunnel_t *self = con->tunnel;

    mux_client_child_con_state_t *child_con_i;
    for (child_con_i = con->children_root.next; child_con_i;)
    {

        mux_client_child_con_state_t *next    = child_con_i;
        context_t                    *fin_ctx = newFinContext(child_con_i->line);
        tunnel_t                     *dest    = con->tunnel->dw;

        destroyChildConnecton(child_con_i);
        dest->downStream(dest, fin_ctx);
        child_con_i = next;
    }
    destroyBufferStream(con->read_stream);
    doneLineDownSide(con->line);
    LSTATE_DROP(con->line);
    globalFree(con);
}

static mux_client_con_state_t *createMainConnection(tunnel_t *self, tid_t tid)
{
    mux_client_con_state_t *con = globalMalloc(sizeof(mux_client_con_state_t));

    *con = (mux_client_con_state_t) {.tunnel         = self,
                                     .line           = newLine(tid),
                                     .children_root  = {0},
                                     .creation_epoch = hloop_now(WORKERS[tid].loop),
                                     .read_stream    = newBufferStream(WORKERS[tid].buffer_pool)};

    setupLineDownSide(con->line, onMainLinePaused, con, onMainLineResumed);

    LSTATE_MUT(con->line) = con;
    return con;
}

static mux_client_con_state_t *grabConnection(tunnel_t *self, tid_t tid)
{
    mux_client_state_t *state  = TSTATE(self);
    vec_cons           *vector = &(state->threadlocal_cons[tid].cons);

    if (vec_cons_size(vector) > 0)
    {
        c_foreach(k, vec_cons, *vector)
        {
            switch (state->mode)
            {
            default:
            case kCuncurrencyModeCounter:
                if ((*k.ref)->contained < state->connection_cunc_capacity)
                {
                    mux_client_con_state_t *con = (*k.ref);
                    con->contained += 1;
                    if (con->contained >= state->connection_cunc_capacity)
                    {
                        vec_cons_erase_at(vector, k);
                    }
                    return con;
                }
                else
                {
                    vec_cons_erase_at(vector, k);
                    return grabConnection(self, tid);
                }

                break;

            case kCuncurrencyModeTimer:
                if ((*k.ref)->creation_epoch < hloop_now(WORKERS[tid].loop) + state->connection_cunc_duration)
                {
                    return (*k.ref);
                    break;
                }
                else
                {
                    vec_cons_erase_at(vector, k);
                    return grabConnection(self, tid);
                }

                break;
            }
        }
    }

    mux_client_con_state_t *con = createMainConnection(self, tid);
    vec_cons_push(vector, con);
    return con;
}

static bool shouldClose(tunnel_t *self, mux_client_con_state_t *main_con)
{
    mux_client_state_t *state  = TSTATE(self);
    tid_t               tid    = main_con->line->tid;
    vec_cons           *vector = &(state->threadlocal_cons[tid].cons);

    switch (state->mode)
    {
    default:
    case kCuncurrencyModeCounter:
        if (main_con->contained >= state->connection_cunc_capacity && main_con->children_root.next == NULL)
        {
            vec_cons_iter find_result = vec_cons_find(vector, main_con);
            if (find_result.ref != vec_cons_end(vector).ref)
            {
                vec_cons_erase_at(vector, find_result);
            }
            return true;
        }
        break;

    case kCuncurrencyModeTimer:
        if (main_con->creation_epoch >= hloop_now(WORKERS[tid].loop) + state->connection_cunc_duration)
        {
            vec_cons_iter find_result = vec_cons_find(vector, main_con);
            if (find_result.ref != vec_cons_end(vector).ref)
            {
                vec_cons_erase_at(vector, find_result);
            }
            return true;
        }

        break;
    }
    return false;
}

static void upStream(tunnel_t *self, context_t *c)
{
    mux_client_child_con_state_t *child_con = CSTATE(c);
    if (c->payload != NULL)
    {
        line_t* current_writing_line = c->line;
        line_t* main_line = child_con->parent;

        switchLine(c, main_line);
        mux_client_con_state_t *main_con = CSTATE(c);

        makeDataFrame(c->payload, child_con->cid);

        lockLine(main_line);
        lockLine(current_writing_line);

        main_con->current_writing_line = current_writing_line;
        
        self->up->upStream(self->up, c);

        if(isAlive(main_line)){
            main_con->current_writing_line = NULL;
        }

        unLockLine(main_line);
        unLockLine(current_writing_line);

    }
    else
    {
        if (c->init)
        {
            mux_client_con_state_t *main_con = grabConnection(self, c->line->tid);
            child_con                        = createChildConnection(main_con, c->line);
            CSTATE_MUT(c)                    = child_con;
            self->dw->downStream(self->dw, newEstContext(c->line));
            if (! isAlive(c->line))
            {
                destroyContext(c);
                return;
            }

            context_t *data_init_ctx = newContext(main_con->line);
            data_init_ctx->payload   = popBuffer(getLineBufferPool(main_con->line));
            makeOpenFrame(data_init_ctx->payload, child_con->cid);
            self->up->upStream(self->up, data_init_ctx);

            destroyContext(c);
        }
        else
        {
            mux_client_con_state_t *main_con = LSTATE(child_con->parent);

            context_t *data_fin_ctx = newContext(child_con->parent);
            data_fin_ctx->payload   = popBuffer(getLineBufferPool(child_con->parent));
            makeCloseFrame(data_fin_ctx->payload, child_con->cid);
            destroyChildConnecton(child_con);
            self->up->upStream(self->up, data_fin_ctx);

            if (shouldClose(self, main_con))
            {
                context_t *main_con_fin_ctx = newFinContext(main_con->line);
                destroyMainConnecton(main_con);
                self->up->upStream(self->up, main_con_fin_ctx);
            }

            destroyContext(c);
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    mux_client_con_state_t *main_con = CSTATE(c);

    if (c->fin)
    {
        destroyMainConnecton(main_con);
        destroyContext(c);
        return;
    }

    bufferStreamPushContextPayload(main_con->read_stream, c);
    while (bufferStreamLen(main_con->read_stream) > sizeof(mux_frame_t))
    {
        uint16_t length;
        bufferStreamViewBytesAt(main_con->read_stream, 0, (uint8_t *) &length, 2);
        if (WW_UNLIKELY(length < 1))
        {
            LOGE("MuxClient: length < 1");
            destroyMainConnecton(main_con);
            destroyContext(c);
            return;
        }

        if (bufferStreamLen(main_con->read_stream) >= length + sizeof(length))
        {
            shift_buffer_t *frame_payload = bufferStreamRead(main_con->read_stream, length + sizeof(length));

            mux_frame_t frame;
            memcpy(&frame, rawBuf(frame_payload), sizeof(mux_frame_t));
            shiftr(frame_payload, sizeof(mux_frame_t));

            mux_client_child_con_state_t *child_con_i;
            for (child_con_i = main_con->children_root.next; child_con_i;)
            {
                if (child_con_i->cid == frame.cid)
                {
                    tunnel_t *dest = main_con->tunnel->dw;

                    switch (frame.flags)
                    {
                    case kMuxFlagClose: {
                        reuseBuffer(getLineBufferPool(c->line), frame_payload);
                        context_t *fin_ctx = newFinContext(child_con_i->line);
                        destroyChildConnecton(child_con_i);
                        dest->downStream(dest, fin_ctx);
                        frame_payload = NULL;
                    }

                    break;

                    case kMuxFlagData: {
                        context_t *data_ctx = newContext(child_con_i->line);
                        data_ctx->payload   = frame_payload;
                        dest->downStream(dest, data_ctx);
                        frame_payload = NULL;
                    }

                    break;

                    case kMuxFlagFlow:
                        LOGE("MuxClient: kMuxFlagFlow not implemented"); // fall through
                    case kMuxFlagOpen:
                    default:
                        LOGE("MuxClient: incorrect frame flag");
                        destroyMainConnecton(main_con);
                        destroyContext(c);
                        return;
                        break;
                    }
                    break;
                }
                child_con_i = child_con_i->next;
            }
            if (frame_payload != NULL)
            {
                LOGE("MuxClient: a payload could not find consumer cid: %d", (int) frame.cid);
                reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
            }
            else if (! isAlive(c->line))
            {
                destroyContext(c);
                return;
            }
        }
        else
        {
            break;
        }
    }
}

tunnel_t *newMuxClient(node_instance_context_t *instance_info)
{

    mux_client_state_t *state = globalMalloc(sizeof(mux_client_state_t));
    memset(state, 0, sizeof(mux_client_state_t));

    const cJSON *settings = instance_info->node_settings_json;
    (void) settings;

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiMuxClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyMuxClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataMuxClient(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
