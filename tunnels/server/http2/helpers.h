#pragma once
#include "nghttp2/nghttp2.h"
#include "tunnel.h"
#include "types.h"

#define kMaxConcurrentStreams 0xffffffffU // NOLINT

static nghttp2_nv makeNV(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name     = (uint8_t *) name;
    nv.value    = (uint8_t *) value;
    nv.namelen  = strlen(name);
    nv.valuelen = strlen(value);
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static void printFrameHd(const nghttp2_frame_hd *hd)
{
    (void) hd;
    // LOGD("[frame] length=%d type=%x flags=%x stream_id=%d\n", (int) hd->length, (int) hd->type, (int) hd->flags,
    //      hd->stream_id);
}

static void addStream(http2_server_con_state_t *con, http2_server_child_con_state_t *stream)
{
    stream->next   = con->root.next;
    con->root.next = stream;
    stream->prev   = &con->root;
    if (stream->next)
    {
        stream->next->prev = stream;
    }
}
static void removeStream(http2_server_con_state_t *con, http2_server_child_con_state_t *stream)
{
    (void) con;
    stream->prev->next = stream->next;
    if (stream->next)
    {
        stream->next->prev = stream->prev;
    }
}

static void onStreamLinePaused(void *arg)
{
    http2_server_child_con_state_t *stream = (http2_server_child_con_state_t *) arg;
    pauseLineDownSide(stream->parent);
}
static void onStreamLineResumed(void *arg)
{
    http2_server_child_con_state_t *stream = (http2_server_child_con_state_t *) arg;
    resumeLineDownSide(stream->parent);
}

static void onH2LinePaused(void *arg)
{
    http2_server_con_state_t       *con = (http2_server_con_state_t *) arg;
    http2_server_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        pauseLineUpSide(stream_i->line);
        stream_i = stream_i->next;
    }
}

static void onH2LineResumed(void *arg)
{
    http2_server_con_state_t       *con = (http2_server_con_state_t *) arg;
    http2_server_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        resumeLineUpSide(stream_i->line);
        stream_i = stream_i->next;
    }
}

static http2_server_child_con_state_t *createHttp2Stream(http2_server_con_state_t *con, line_t *this_line,
                                                         tunnel_t *self, int32_t stream_id)
{
    http2_server_child_con_state_t *stream = wwmGlobalMalloc(sizeof(http2_server_child_con_state_t));

    *stream = (http2_server_child_con_state_t) {.stream_id             = stream_id,
                                                .grpc_buffer_stream    = NULL,
                                                .flowctl_buffer_stream = newBufferStream(getLineBufferPool(this_line)),
                                                .parent                = this_line,
                                                .line                  = newLine(this_line->tid),
                                                .tunnel                = self};

    if (con->content_type == kApplicationGrpc)
    {
        stream->grpc_buffer_stream = newBufferStream(getLineBufferPool(this_line));
    }

    LSTATE_MUT(stream->line) = stream;
    nghttp2_session_set_stream_user_data(con->session, stream_id, stream);
    setupLineDownSide(stream->line, onStreamLinePaused, stream, onStreamLineResumed);

    return stream;
}
static void deleteHttp2Stream(http2_server_child_con_state_t *stream)
{
    LSTATE_I_DROP(stream->line, stream->tunnel->chain_index);

    if (stream->grpc_buffer_stream)
    {
        destroyBufferStream(stream->grpc_buffer_stream);
    }
    destroyBufferStream(stream->flowctl_buffer_stream);

    doneLineDownSide(stream->line);
    destroyLine(stream->line);
    if (stream->request_path)
    {
        wwmGlobalFree(stream->request_path);
    }
    wwmGlobalFree(stream);
}

static http2_server_con_state_t *createHttp2Connection(tunnel_t *self, line_t *line)
{
    http2_server_state_t     *state = TSTATE(self);
    http2_server_con_state_t *con   = wwmGlobalMalloc(sizeof(http2_server_con_state_t));
    memset(con, 0, sizeof(http2_server_con_state_t));
    nghttp2_session_server_new2(&con->session, state->cbs, con, state->ngoptions);
    con->state   = kH2WantRecv;
    con->tunnel  = self;
    con->line    = line;
    con->actions = action_queue_t_with_capacity(16);
    setupLineUpSide(line, onH2LinePaused, con, onH2LineResumed);

    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, kMaxConcurrentStreams},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1U << 18)},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 18)},

    };
    nghttp2_submit_settings(con->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));
    con->state = kH2SendSettings;
    return con;
}
static void deleteHttp2Connection(http2_server_con_state_t *con)
{
    tunnel_t                       *self = con->tunnel;
    http2_server_child_con_state_t *stream_i;

    for (stream_i = con->root.next; stream_i;)
    {
        context_t                      *fin_ctx = newFinContext(stream_i->line);
        tunnel_t                       *dest    = stream_i->tunnel->up;
        http2_server_child_con_state_t *next    = stream_i->next;
        deleteHttp2Stream(stream_i);
        dest->upStream(dest, fin_ctx);
        stream_i = next;
    }

    c_foreach(k, action_queue_t, con->actions)
    {
        if (k.ref->buf)
        {
            reuseBuffer(getThreadBufferPool(con->line->tid), k.ref->buf);
        }
    }
    action_queue_t_drop(&con->actions);

    doneLineUpSide(con->line);
    nghttp2_session_del(con->session);
    LSTATE_DROP(con->line);
    wwmGlobalFree(con);
}
