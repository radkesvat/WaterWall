#include "mux_server.h"
#include "buffer_stream.h"
#include "loggers/network_logger.h"
#include "mux_frame.h"

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
    memoryFree(child);
}

static mux_server_child_con_state_t *createChildConnection(mux_server_con_state_t *parent, tid_t tid)
{
    mux_server_child_con_state_t *child = memoryAllocate(sizeof(mux_server_con_state_t));

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
    memoryFree(con);
}

static mux_server_con_state_t *createMainConnection(tunnel_t *self, line_t *main_line)
{
    mux_server_con_state_t *con = memoryAllocate(sizeof(mux_server_con_state_t));

    *con = (mux_server_con_state_t) {.tunnel        = self,
                                     .line          = main_line,
                                     .children_root = {0},
                                     .read_stream   = newBufferStream(getLineBufferPool(main_line))};

    setupLineDownSide(con->line, onMainLinePaused, con, onMainLineResumed);

    LSTATE_MUT(con->line) = con;
    return con;
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
            if (UNLIKELY(length < kMuxMinFrameLength))
            {
                LOGE("MuxServer: payload length < kMuxMinFrameLength");
                destroyMainConnecton(main_con);
                self->dw->downStream(self->dw, newFinContext(c->line));

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
                    if (UNLIKELY(bufLen(frame_payload) <= 0))
                    {
                        LOGE("MuxServer: payload length <= 0");
                        reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
                        destroyMainConnecton(main_con);
                        self->dw->downStream(self->dw, newFinContext(c->line));
                        destroyContext(c);
                        continue;
                    }

                    mux_server_child_con_state_t *child      = createChildConnection(main_con, c->line->tid);
                    line_t                       *child_line = child->line;
                    lockLine(child_line);

                    self->up->upStream(self->up, newInitContext(child->line));

                    if (! isAlive(child_line))
                    {
                        unLockLine(child_line);
                        reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
                        continue;
                    }
                    unLockLine(child_line);

                    context_t *data_ctx = newContext(child_line);
                    data_ctx->payload   = frame_payload;
                    self->up->upStream(self->up, data_ctx);

                    if (! isAlive(c->line))
                    {
                        destroyContext(c);
                        return;
                    }
                    continue;
                }

                mux_server_child_con_state_t *child_con_i;
                for (child_con_i = main_con->children_root.next; child_con_i;)
                {
                    if (child_con_i->cid == frame.cid)
                    {

                        switch (frame.flags)
                        {
                        case kMuxFlagClose: {
                            reuseBuffer(getLineBufferPool(c->line), frame_payload);
                            context_t *fin_ctx = newFinContext(child_con_i->line);
                            destroyChildConnecton(child_con_i);
                            self->dw->downStream(self->dw, fin_ctx);
                            frame_payload = NULL;
                        }

                        break;

                        case kMuxFlagData: {
                            if (UNLIKELY(bufLen(frame_payload) <= 0))
                            {
                                LOGE("MuxServer: payload length <= 0");
                                reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
                                destroyMainConnecton(main_con);
                                self->dw->downStream(self->dw, newFinContext(c->line));
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
                        default:
                            LOGE("MuxServer: incorrect frame flag");
                            reuseBuffer(getLineBufferPool(main_con->line), frame_payload);
                            destroyMainConnecton(main_con);
                            self->dw->downStream(self->dw, newFinContext(c->line));
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
    mux_server_child_con_state_t *child_con = CSTATE(c);

    if (c->payload != NULL)
    {
        line_t                 *current_writing_line = c->line;
        line_t                 *main_line            = child_con->parent;
        mux_server_con_state_t *main_con             = LSTATE(main_line);

        switchLine(c, main_line);

        lockLine(main_line);
        lockLine(current_writing_line);
        main_con->current_writing_line = current_writing_line;

        while (bufLen(c->payload) > kMuxMaxFrameLength)
        {
            shift_buffer_t *chunk = popBuffer(getContextBufferPool(c));
            chunk = sliceBufferTo(chunk, c->payload, kMuxMaxFrameLength);
            makeDataFrame(chunk, child_con->cid);

            context_t *data_chunk_ctx = newContextFrom(c);
            data_chunk_ctx->payload   = chunk;
            self->dw->downStream(self->dw, data_chunk_ctx);

            if (! isAlive(main_line))
            {
                unLockLine(main_line);
                unLockLine(current_writing_line);

                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
        }

        makeDataFrame(c->payload, child_con->cid);

        self->up->upStream(self->up, c);

        if (isAlive(main_line))
        {
            main_con->current_writing_line = NULL;
        }

        unLockLine(main_line);
        unLockLine(current_writing_line);
    }
    else
    {
        if (c->fin)
        {
            context_t *data_fin_ctx = newContext(child_con->parent);
            data_fin_ctx->payload   = popBuffer(getLineBufferPool(child_con->parent));
            makeCloseFrame(data_fin_ctx->payload, child_con->cid);
            destroyChildConnecton(child_con);
            self->dw->downStream(self->dw, data_fin_ctx);
            return;
        }
        if (UNLIKELY(c->est))
        {
            destroyContext(c);
            return;
        }
    }
}

tunnel_t *newMuxServer(node_instance_context_t *instance_info)
{
    (void) instance_info;
    mux_server_state_t *state = memoryAllocate(sizeof(mux_server_state_t));
    memset(state, 0, sizeof(mux_server_state_t));

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
