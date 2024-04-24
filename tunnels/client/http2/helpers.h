#pragma once

#include "types.h"

#define MAX_CONCURRENT_STREAMS 0xffffffffu
#define PING_INTERVAL          5000

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

static nghttp2_nv makeNV2(const char *name, const char *value, int namelen, int valuelen)
{
    nghttp2_nv nv;
    nv.name     = (uint8_t *) name;
    nv.value    = (uint8_t *) value;
    nv.namelen  = namelen;
    nv.valuelen = valuelen;
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static void printFrameHd(const nghttp2_frame_hd *hd)
{
    (void) hd;
    // LOGD("[frame] length=%d type=%x flags=%x stream_id=%d\n", (int) hd->length, (int) hd->type, (int) hd->flags,
    //      hd->stream_id);
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

static http2_client_child_con_state_t *createHttp2Stream(http2_client_con_state_t *con, line_t *child_line, hio_t *io)
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
    // nvs[nvlen++] = makeNV("Accept",
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    // nvs[nvlen++] = makeNV("Accept-Language", "en,fa;q=0.9,zh-CN;q=0.8,zh;q=0.7");
    // nvs[nvlen++] = makeNV("Cache-Control", "no-cache");
    // nvs[nvlen++] = makeNV("Pragma", "no-cache");
    // nvs[nvlen++] = makeNV("Sec-Ch-Ua", "Chromium\";v=\"122\", Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"");
    nvs[nvlen++] = makeNV("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
                                        "Gecko) Chrome/122.0.0.0 Safari/537.36");
    // nvs[nvlen++] = makeNV("Sec-Ch-Ua-Platform", "\"Windows\"");

    con->state                             = kH2SendHeaders;
    http2_client_child_con_state_t *stream = malloc(sizeof(http2_client_child_con_state_t));
    memset(stream, 0, sizeof(http2_client_child_con_state_t));
    // stream->stream_id = nghttp2_submit_request2(con->session, NULL,  &nvs[0], nvlen, NULL,stream);
    stream->stream_id = nghttp2_submit_headers(con->session, flags, -1, NULL, &nvs[0], nvlen, stream);
    stream->chunkbs   = newBufferStream(getLineBufferPool(con->line));
    stream->parent    = con->line;
    stream->line      = child_line;
    stream->io        = io;
    stream->tunnel    = con->tunnel->dw;

    stream->line->chains_state[stream->tunnel->chain_index + 1] = stream;
    addStraem(con, stream);
    // nghttp2_session_set_stream_user_data(con->session, stream->stream_id, stream);

    return stream;
}
static void deleteHttp2Stream(http2_client_child_con_state_t *stream)
{

    destroyBufferStream(stream->chunkbs);
    stream->line->chains_state[stream->tunnel->chain_index + 1] = NULL;
    free(stream);
}

static http2_client_con_state_t *createHttp2Connection(tunnel_t *self, int tid, hio_t *io)
{
    http2_client_state_t *    state = STATE(self);
    http2_client_con_state_t *con   = malloc(sizeof(http2_client_con_state_t));
    memset(con, 0, sizeof(http2_client_con_state_t));
    
    con->queue                                 = newContextQueue(getThreadBufferPool(tid));
    con->content_type                          = state->content_type;
    con->path                                  = state->path;
    con->host                                  = state->host;
    con->host_port                             = state->host_port;
    con->scheme                                = state->scheme;
    con->method                                = kHttpGet;
    con->line                                  = newLine(tid);
    con->ping_timer                            = htimer_add(con->line->loop, onPingTimer, PING_INTERVAL, INFINITE);
    con->tunnel                                = self;
    con->io                                    = io;
    con->line->chains_state[self->chain_index] = con;

    hevent_set_userdata(con->ping_timer, con);
    nghttp2_session_client_new2(&con->session, state->cbs, con, state->ngoptions);
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1U << 18)},
        };
    nghttp2_submit_settings(con->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));

    con->state = kH2SendMagic;

    if (state->content_type == kApplicationGrpc)
    {
        con->method = kHttpPost;
    }

    return con;
}
static void deleteHttp2Connection(http2_client_con_state_t *con)
{
    tunnel_t *            self  = con->tunnel;
    http2_client_state_t *state = STATE(self);

    vec_cons *    vector = &(state->thread_cpool[con->line->tid].cons);
    vec_cons_iter it     = vec_cons_find(vector, con);
    if (it.ref != vec_cons_end(vector).ref)
    {
        vec_cons_erase_at(vector, it);
    }

    http2_client_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        http2_client_child_con_state_t *next    = stream_i->next;
        context_t *                     fin_ctx = newFinContext(stream_i->line);
        tunnel_t *                      dest    = stream_i->tunnel;
        deleteHttp2Stream(stream_i);
        CSTATE_MUT(fin_ctx) = NULL;
        dest->downStream(dest, fin_ctx);
        stream_i = next;
    }
    nghttp2_session_del(con->session);
    con->line->chains_state[self->chain_index] = NULL;
    destroyContextQueue(con->queue);
    destroyLine(con->line);
    htimer_del(con->ping_timer);
    free(con);
}

static http2_client_con_state_t *takeHttp2Connection(tunnel_t *self, int tid, hio_t *io)
{

    http2_client_state_t *state = STATE(self);
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

        con = createHttp2Connection(self, tid, io);
        vec_cons_push(vector, con);
        return con;
    }

    http2_client_con_state_t *con = createHttp2Connection(self, tid, io);
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
        tunnel_t * con_dest = con->tunnel->up;
        deleteHttp2Connection(con);
        con_dest->upStream(con_dest, con_fc);
    }
    else
    {
        con->no_ping_ack = true;
        nghttp2_submit_ping(con->session, 0, NULL);
        char * data = NULL;
        size_t len;
        len = nghttp2_session_mem_send(con->session, (const uint8_t **) &data);
        if (len > 0)
        {
            shift_buffer_t *send_buf = popBuffer(getLineBufferPool(con->line));
            setLen(send_buf, len);
            writeRaw(send_buf, data, len);
            context_t *req = newContext(con->line);
            req->payload   = send_buf;
            req->src_io    = NULL;
            if (! con->first_sent)
            {
                con->first_sent = true;
                req->first      = true;
            }
            con->tunnel->up->upStream(con->tunnel->up, req);
        }
    }
}
