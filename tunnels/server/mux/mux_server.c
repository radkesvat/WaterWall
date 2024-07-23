#include "mux_server.h"
#include "buffer_stream.h"
#include "loggers/network_logger.h"
#include "mux_frame.h"
#include "utils/jsonutils.h"

typedef struct mux_server_state_s
{
    void *_;

} mux_server_state_t;

typedef struct mux_server_child_con_state_s
{

    struct mux_server_child_con_state_s *next, *prev;
    tunnel_t                            *tunnel;
    line_t                              *line;
    line_t                              *parent;
    uint32_t                             sent_nack;
    uint32_t                             recv_nack;
    uint16_t                             cid;
    bool                                 paused;

} mux_server_child_con_state_t;

typedef struct mux_server_con_state_s
{
    struct mux_server_child_con_state_s children_root;

    tunnel_t        *tunnel;
    line_t          *line;
    line_t          *current_writing_line;
    buffer_stream_t *read_stream;
    uint16_t         last_cid;
    uint16_t         cid_min;
    uint16_t         cid_max;
    uint16_t         contained;

} mux_server_con_state_t;

static void onChildLinePaused(void *arg)
{
    mux_server_child_con_state_t *stream = (mux_server_child_con_state_t *) arg;
    pauseLineDownSide(stream->parent);
}
static void onChildLineResumed(void *arg)
{
    mux_server_child_con_state_t *stream = (mux_server_child_con_state_t *) arg;
    resumeLineDownSide(stream->parent);
}

static void onMainLinePaused(void *arg)
{
    mux_server_con_state_t *con  = (mux_server_con_state_t *) arg;
    tunnel_t               *self = con->tunnel;

    line_t *wline = con->current_writing_line;
    if (wline && isAlive(wline))
    {
        mux_server_child_con_state_t *child_con = LSTATE(wline);
        child_con->paused                       = true;
        pauseLineUpSide(child_con->line);
    }
}

static void onMainLineResumed(void *arg)
{
    mux_server_con_state_t       *con = (mux_server_con_state_t *) arg;
    mux_server_child_con_state_t *child_con_i;
    for (child_con_i = con->children_root.next; child_con_i;)
    {
        if (child_con_i->paused)
        {
            child_con_i->paused = false;
            resumeLineUpSide(child_con_i->line);
        }
        child_con_i = child_con_i->next;
    }
}

static void destroyChildConnecton(mux_server_child_con_state_t *child)
{
    tunnel_t *self    = child->tunnel;
    child->prev->next = child->next;
    if (child->next)
    {
        child->next->prev = child->prev;
    }
    else
    {
        mux_server_con_state_t *parent = LSTATE(child->parent);
        parent->children_root.prev     = NULL;
    }
    doneLineDownSide(child->line);
    LSTATE_DROP(child->line);
    globalFree(child);
}

static mux_server_child_con_state_t *createChildConnection(mux_server_con_state_t *parent, tid_t tid)
{
    mux_server_child_con_state_t *child = globalMalloc(sizeof(mux_server_con_state_t));

    *child = (mux_server_child_con_state_t) {.tunnel = parent->tunnel,
                                             .line   = newLine(tid),
                                             .cid    = parent->last_cid++,
                                             .next   = parent->children_root.next,
                                             .prev   = &(parent->children_root)

    };

    if (parent->children_root.next == NULL)
    {
        parent->children_root.prev = child;
    }
    parent->children_root.next = child;

    if (child->next)
    {
        child->next->prev = child;
    }
    setupLineDownSide(child->line, onChildLinePaused, child, onChildLineResumed);

    return child;
}

static void destroyMainConnecton(mux_server_con_state_t *con)
{
    tunnel_t *self = con->tunnel;

    mux_server_child_con_state_t *child_con_i;
    for (child_con_i = con->children_root.next; child_con_i;)
    {

        mux_server_child_con_state_t *next    = child_con_i;
        context_t                    *fin_ctx = newFinContext(child_con_i->line);
        tunnel_t                     *dest    = con->tunnel->up;

        destroyChildConnecton(child_con_i);
        dest->upStream(dest, fin_ctx);
        child_con_i = next;
    }
    destroyBufferStream(con->read_stream);
    doneLineUpSide(con->line);
    LSTATE_DROP(con->line);
    globalFree(con);
}

static mux_server_con_state_t *createMainConnection(tunnel_t *self, line_t *main_line)
{
    mux_server_con_state_t *con = globalMalloc(sizeof(mux_server_con_state_t));

    *con = (mux_server_con_state_t) {.tunnel        = self,
                                     .line          = main_line,
                                     .children_root = {0},
                                     .read_stream   = newBufferStream(getLineBufferPool(main_line))};

    setupLineDownSide(con->line, onMainLinePaused, con, onMainLineResumed);

    LSTATE_MUT(con->line) = con;
    return con;
}

static bool shouldClose(tunnel_t *self, mux_server_con_state_t *main_con)
{
    mux_server_state_t *state  = TSTATE(self);
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
    mux_server_con_state_t *main_con = CSTATE(c);
    if (c->payload != NULL)
    {
        bufferStreamPushContextPayload(main_con->read_stream, c);
        while (bufferStreamLen(main_con->read_stream) > sizeof(mux_frame_t))
        {
            mux_length_t length;
            bufferStreamViewBytesAt(main_con->read_stream, 0, (uint8_t *) &length, 2);
            if (WW_UNLIKELY(length < kMuxMinFrameLength))
            {
                LOGE("MuxServer: payload length < kMuxMinFrameLength");
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

                if (frame.flags == kMuxFlagOpen)
                {
                    if (WW_UNLIKELY(bufLen(frame_payload) <= 0))
                    {
                    }

                    if (! isAlive(c->line))
                    {
                        reuseBuffer(getLineBufferPool(c->line), frame_payload);
                        destroyContext(c);
                        return;
                    }

                    frame_payload = NULL;
                }

                mux_client_child_con_state_t *child_con_i;
                for (child_con_i = main_con->children_root.next; child_con_i;)
                {
                    if (child_con_i->cid == frame.cid)
                    {

                        switch (frame.flags)
                        {
                        case kMuxFlagOpen: {
                            if (WW_UNLIKELY(bufLen(frame_payload) <= 0))
                            {
                                LOGE("MuxServer: payload length < 0");
                                reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
                                destroyMainConnecton(main_con);
                                destroyContext(c);
                                return;
                            }
                            mux_server_child_con_state_t *child = createChildConnection(main_con, c->line->tid);
                            line_t* child_line = child->line;
                            lockLine(child_line);

                            self->up->upStream(self->up, newInitContext(child->line));

                            if(!isAlive(child_line)){
                            unLockLine(child_line);

                            } 
                            unLockLine(child_line);
                            context_t *data_ctx = newContext(child_con_i->line);
                            data_ctx->payload   = frame_payload;
                            self->dw->downStream(self->dw, data_ctx);
                            frame_payload = NULL;
                        }
                        break;

                        case kMuxFlagClose: {
                            reuseBuffer(getLineBufferPool(c->line), frame_payload);
                            context_t *fin_ctx = newFinContext(child_con_i->line);
                            destroyChildConnecton(child_con_i);
                            self->dw->downStream(self->dw, fin_ctx);
                            frame_payload = NULL;
                        }

                        break;

                        case kMuxFlagData: {
                            if (WW_UNLIKELY(bufLen(frame_payload) <= 0))
                            {
                                LOGE("MuxServer: payload length < 0");
                                reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
                                destroyMainConnecton(main_con);
                                destroyContext(c);
                                return;
                            }

                            context_t *data_ctx = newContext(child_con_i->line);
                            data_ctx->payload   = frame_payload;
                            self->dw->downStream(self->dw, data_ctx);
                            frame_payload = NULL;
                        }

                        break;

                        case kMuxFlagFlow:
                            LOGE("MuxServer: kMuxFlagFlow not implemented"); // fall through
                        case kMuxFlagOpen:
                        default:
                            LOGE("MuxServer: incorrect frame flag");
                            reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
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
                    LOGW("MuxServer: a frame could not find consumer cid: %d", (int) frame.cid);
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
    else
    {
        if (c->init)
        {
            main_con = createMainConnection(self, c->line);
            // child_con                          = createChildConnection(main_con, c->line);
            CSTATE_MUT(c) = main_con;
            self->dw->downStream(self->dw, newEstContext(c->line));
            destroyContext(c);
        }
        else
        {
            destroyMainConnecton(main_con);
            destroyContext(c);
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{
    mux_server_con_state_t *main_con = CSTATE(c);

    if (c->fin)
    {
        destroyMainConnecton(main_con);
        destroyContext(c);
        return;
    }
}

tunnel_t *newMuxServer(node_instance_context_t *instance_info)
{

    mux_server_state_t *state = globalMalloc(sizeof(mux_server_state_t));
    memset(state, 0, sizeof(mux_server_state_t));

    const cJSON *settings = instance_info->node_settings_json;
    (void) settings;

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiMuxServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyMuxServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataMuxServer(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
