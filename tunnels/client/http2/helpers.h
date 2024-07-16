#pragma once

#include "tunnel.h"
#include "types.h"

#define kMaxConcurrentStreams 0xffffffffU // NOLINT

enum
{
    kPingInterval = 10000
};

static void onPingTimer(htimer_t *timer);

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

static void onStreamLinePaused(void *arg)
{
    http2_client_child_con_state_t *stream = (http2_client_child_con_state_t *) arg;
    pauseLineUpSide(stream->parent);
}
static void onStreamLineResumed(void *arg)
{
    http2_client_child_con_state_t *stream = (http2_client_child_con_state_t *) arg;
    resumeLineUpSide(stream->parent);
}

static void onH2LinePaused(void *arg)
{
    http2_client_con_state_t *con  = (http2_client_con_state_t *) arg;
    tunnel_t                 *self = con->tunnel;

    line_t *stream_line = con->current_stream_write_line;
    if (stream_line && isAlive(stream_line))
    {
        http2_client_child_con_state_t *stream = LSTATE(stream_line);
        stream->paused                         = true;
        pauseLineDownSide(stream->line);
    }

    // ++(con->pause_counter);
    // if (con->pause_counter > 8)
    // {
    // http2_client_child_con_state_t *stream_i;
    // for (stream_i = con->root.next; stream_i;)
    // {
    //     pauseLineDownSide(stream_i->line);
    //     stream_i = stream_i->next;
    // }
    // }
}

static void onH2LineResumed(void *arg)
{
    http2_client_con_state_t *con = (http2_client_con_state_t *) arg;
    // con->pause_counter            = con->pause_counter > 0 ? (con->pause_counter - 1) : con->pause_counter;
    http2_client_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        if (stream_i->paused)
        {
            stream_i->paused = false;
            resumeLineDownSide(stream_i->line);
        }
        stream_i = stream_i->next;
    }
}

static void addStraem(http2_client_con_state_t *con, http2_client_child_con_state_t *stream)
{
    stream->next   = con->root.next;
    con->root.next = stream;
    stream->prev   = &con->root;
    if (stream->next)
    {
        stream->next->prev = stream;
    }
}
static void removeStream(http2_client_con_state_t *con, http2_client_child_con_state_t *stream)
{
    (void) con;
    stream->prev->next = stream->next;
    if (stream->next)
    {
        stream->next->prev = stream->prev;
    }
}

static http2_client_child_con_state_t *createHttp2Stream(http2_client_con_state_t *con, line_t *child_line)
{
    char       authority_addr[320];
    nghttp2_nv nvs[15];
    int        nvlen = 0;

    nvs[nvlen++] = makeNV(":method", httpMethodStr(con->method));
    nvs[nvlen++] = makeNV(":path", con->path);
    nvs[nvlen++] = makeNV(":scheme", con->scheme);

    if (con->host_port == 0 || con->host_port == DEFAULT_HTTP_PORT || con->host_port == DEFAULT_HTTPS_PORT)
    {
        nvs[nvlen++] = (makeNV(":authority", con->host));
    }
    else
    {
        snprintf(authority_addr, sizeof(authority_addr), "%s:%d", con->host, con->host_port);
        nvs[nvlen++] = (makeNV(":authority", authority_addr));
    }

    // HTTP2_FLAG_END_STREAM;
    int flags = NGHTTP2_FLAG_END_HEADERS;

    if (con->content_type == kApplicationGrpc)
    {
        // flags = HTTP2_FLAG_NONE;
        nvs[nvlen++] = (makeNV("content-type", "application/grpc+proto"));
    }
    // todo (match chrome) this one is same as curl, but not same as chrome
    nvs[nvlen++] = makeNV("Accept", "*/*");
    // chrome:
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");

    nvs[nvlen++] = makeNV("Accept-Language", "en,fa;q=0.9,zh-CN;q=0.8,zh;q=0.7");
    nvs[nvlen++] = makeNV("Cache-Control", "no-cache");
    nvs[nvlen++] = makeNV("Pragma", "no-cache");
    nvs[nvlen++] = makeNV("Sec-Ch-Ua", "Chromium\";v=\"122\", Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"");
    nvs[nvlen++] = makeNV("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
                                        "Gecko) Chrome/122.0.0.0 Safari/537.36");
    nvs[nvlen++] = makeNV("Sec-Ch-Ua-Platform", "\"Windows\"");

    http2_client_child_con_state_t *stream = wwmGlobalMalloc(sizeof(http2_client_child_con_state_t));
    memset(stream, 0, sizeof(http2_client_child_con_state_t));
    // stream->stream_id = nghttp2_submit_request2(con->session, NULL,  &nvs[0], nvlen, NULL,stream);
    stream->stream_id          = nghttp2_submit_headers(con->session, flags, -1, NULL, &nvs[0], nvlen, stream);
    stream->grpc_buffer_stream = newBufferStream(getLineBufferPool(con->line));
    stream->parent             = con->line;
    stream->line               = child_line;
    stream->tunnel             = con->tunnel;
    LSTATE_I_MUT(stream->line, stream->tunnel->chain_index) = stream;
    setupLineUpSide(stream->line, onStreamLinePaused, stream, onStreamLineResumed);

    addStraem(con, stream);

    return stream;
}
static void deleteHttp2Stream(http2_client_child_con_state_t *stream)
{

    LSTATE_I_DROP(stream->line, stream->tunnel->chain_index);
    destroyBufferStream(stream->grpc_buffer_stream);
    doneLineUpSide(stream->line);
    wwmGlobalFree(stream);
}

static http2_client_con_state_t *createHttp2Connection(tunnel_t *self, int tid)
{

    http2_client_state_t     *state = TSTATE(self);
    http2_client_con_state_t *con   = wwmGlobalMalloc(sizeof(http2_client_con_state_t));
    *con                            = (http2_client_con_state_t) {.queue        = newContextQueue(),
                                                                  .content_type = state->content_type,
                                                                  .path         = state->path,
                                                                  .host         = state->host,
                                                                  .host_port    = state->host_port,
                                                                  .scheme       = state->scheme,
                                                                  .method       = state->content_type == kApplicationGrpc ? kHttpPost : kHttpGet,
                                                                  .line         = newLine(tid),
                                                                  .ping_timer   = htimer_add(loops[tid], onPingTimer, kPingInterval, INFINITE),
                                                                  .tunnel       = self,
                                                                  .actions      = action_queue_t_with_capacity(16)};
    LSTATE_MUT(con->line)           = con;
    setupLineDownSide(con->line, onH2LinePaused, con, onH2LineResumed);

    hevent_set_userdata(con->ping_timer, con);
    nghttp2_session_client_new2(&con->session, state->cbs, con, state->ngoptions);
    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, kMaxConcurrentStreams},
                                         {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1U << 18)},
                                         {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 18)}

    };
    nghttp2_submit_settings(con->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));

    return con;
}
static void deleteHttp2Connection(http2_client_con_state_t *con)
{
    tunnel_t             *self  = con->tunnel;
    http2_client_state_t *state = TSTATE(self);

    vec_cons     *vector = &(state->thread_cpool[con->line->tid].cons);
    vec_cons_iter it     = vec_cons_find(vector, con);
    if (it.ref != vec_cons_end(vector).ref)
    {
        vec_cons_erase_at(vector, it);
    }

    http2_client_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        http2_client_child_con_state_t *next    = stream_i->next;
        context_t                      *fin_ctx = newFinContext(stream_i->line);
        tunnel_t                       *dest    = stream_i->tunnel->dw;
        deleteHttp2Stream(stream_i);
        dest->downStream(dest, fin_ctx);
        stream_i = next;
    }

    c_foreach(k, action_queue_t, con->actions)
    {
        if (k.ref->buf)
        {
            reuseBuffer(getThreadBufferPool(con->line->tid), k.ref->buf);
        }
        unLockLine(k.ref->stream_line);
    }

    action_queue_t_drop(&con->actions);
    doneLineDownSide(con->line);
    LSTATE_DROP(con->line);
    nghttp2_session_del(con->session);
    destroyContextQueue(con->queue);
    destroyLine(con->line);
    htimer_del(con->ping_timer);
    wwmGlobalFree(con);
}

static http2_client_con_state_t *takeHttp2Connection(tunnel_t *self, int tid)
{

    http2_client_state_t *state = TSTATE(self);
    // return createHttp2Connection(self, tid, io);
    vec_cons *vector = &(state->thread_cpool[tid].cons);

    if (vec_cons_size(vector) > 0)
    {
        http2_client_con_state_t *con = NULL;
        c_foreach(k, vec_cons, *vector)
        {
            if ((*k.ref)->childs_added < state->concurrency)
            {
                (*k.ref)->childs_added += 1;
                con = (*k.ref);
                break;
            }
        }

        if (con)
        {
            if (con->childs_added >= state->concurrency)
            {
                vec_cons_pop(vector);
            }
            return con;
        }

        con = createHttp2Connection(self, tid);
        vec_cons_push(vector, con);
        return con;
    }

    http2_client_con_state_t *con = createHttp2Connection(self, tid);
    vec_cons_push(vector, con);
    return con;
}

static void onPingTimer(htimer_t *timer)
{
    http2_client_con_state_t *con = hevent_userdata(timer);
    if (con->no_ping_ack)
    {
        LOGW("Http2Client: closing a session due to no ping reply");
        context_t *con_fc   = newFinContext(con->line);
        tunnel_t  *con_dest = con->tunnel->up;
        deleteHttp2Connection(con);
        con_dest->upStream(con_dest, con_fc);
    }
    else
    {
        con->no_ping_ack = true;
        nghttp2_submit_ping(con->session, 0, NULL);
        char   *data = NULL;
        size_t  len;
        line_t *h2line = con->line;
        lockLine(h2line);
        while (0 < (len = nghttp2_session_mem_send2(con->session, (const uint8_t **) &data)))
        {
            shift_buffer_t *send_buf = popBuffer(getLineBufferPool(h2line));
            setLen(send_buf, len);
            writeRaw(send_buf, data, len);
            context_t *req = newContext(h2line);
            req->payload   = send_buf;
            con->tunnel->up->upStream(con->tunnel->up, req);
            if (! isAlive(h2line))
            {
                unLockLine(h2line);
                return;
            }
        }
        unLockLine(h2line);
    }
}
