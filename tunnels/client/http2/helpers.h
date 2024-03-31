#pragma once

#include "types.h"

#define MAX_CONCURRENT_STREAMS 0xffffffffu
#define MAX_CHILD_PER_STREAM 400

#define STATE(x) ((http2_client_state_t *)((x)->state))
#define CSTATE(x) ((void *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

static nghttp2_nv make_nv(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name = (uint8_t *)name;
    nv.value = (uint8_t *)value;
    nv.namelen = strlen(name);
    nv.valuelen = strlen(value);
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static nghttp2_nv make_nv2(const char *name, const char *value,
                           int namelen, int valuelen)
{
    nghttp2_nv nv;
    nv.name = (uint8_t *)name;
    nv.value = (uint8_t *)value;
    nv.namelen = namelen;
    nv.valuelen = valuelen;
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static void print_frame_hd(const nghttp2_frame_hd *hd)
{
    printd("[frame] length=%d type=%x flags=%x stream_id=%d\n",
           (int)hd->length, (int)hd->type, (int)hd->flags, hd->stream_id);
}

static void add_stream(http2_client_con_state_t *con,
                       http2_client_child_con_state_t *stream)
{
    stream->next = con->root.next;
    con->root.next = stream;
    stream->prev = &con->root;
    if (stream->next)
    {
        stream->next->prev = stream;
    }
}
static void remove_stream(http2_client_con_state_t *con,
                          http2_client_child_con_state_t *stream)
{

    stream->prev->next = stream->next;
    if (stream->next)
    {
        stream->next->prev = stream->prev;
    }
}

static http2_client_child_con_state_t *
create_http2_stream(http2_client_con_state_t *con, line_t *child_line, hio_t *io)
{
    char authority_addr[320];
    nghttp2_nv nvs[15];
    int nvlen = 0;

    nvs[nvlen++] = make_nv(":method", http_method_str(con->method));
    nvs[nvlen++] = make_nv(":path", con->path);
    nvs[nvlen++] = make_nv(":scheme", con->scheme);

    if (con->host_port == 0 ||
        con->host_port == DEFAULT_HTTP_PORT ||
        con->host_port == DEFAULT_HTTPS_PORT)
    {
        nvs[nvlen++] = (make_nv(":authority", con->host));
    }
    else
    {
        snprintf(authority_addr, sizeof(authority_addr), "%s:%d", con->host, con->host_port);
        nvs[nvlen++] = (make_nv(":authority", authority_addr));
    }

    int flags = HTTP2_FLAG_END_STREAM;

    if (con->content_type == APPLICATION_GRPC)
    {
        flags = HTTP2_FLAG_NONE;
        nvs[nvlen++] = (make_nv("content-type", "application/grpc+proto"));
    }
    // nvs[nvlen++] = make_nv("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    // nvs[nvlen++] = make_nv("Accept-Language", "en,fa;q=0.9,zh-CN;q=0.8,zh;q=0.7");
    // nvs[nvlen++] = make_nv("Cache-Control", "no-cache");
    // nvs[nvlen++] = make_nv("Pragma", "no-cache");
    // nvs[nvlen++] = make_nv("Sec-Ch-Ua", "Chromium\";v=\"122\", Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"");
    nvs[nvlen++] = make_nv("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
    // nvs[nvlen++] = make_nv("Sec-Ch-Ua-Platform", "\"Windows\"");

    con->state = H2_SEND_HEADERS;
    http2_client_child_con_state_t *stream = malloc(sizeof(http2_client_child_con_state_t));
    memset(stream, 0, sizeof(http2_client_child_con_state_t));
    // stream->stream_id = nghttp2_submit_request2(con->session, NULL,  &nvs[0], nvlen, NULL,stream);
    stream->stream_id = nghttp2_submit_headers(con->session, flags, -1, NULL, &nvs[0], nvlen, stream);
    stream->chunkbs = newBufferStream(buffer_pools[con->line->tid]);
    stream->parent = con->line;
    stream->line = child_line;
    stream->io = io;
    stream->tunnel = con->tunnel->dw;

    stream->line->chains_state[stream->tunnel->chain_index + 1] = stream;
    add_stream(con, stream);
    // nghttp2_session_set_stream_user_data(con->session, stream->stream_id, stream);

    return stream;
}
static void delete_http2_stream(http2_client_child_con_state_t *stream)
{
   
    destroyBufferStream(stream->chunkbs);
    stream->line->chains_state[stream->tunnel->chain_index + 1] = NULL;
    free(stream);
}

static http2_client_con_state_t *create_http2_connection(tunnel_t *self, int tid, hio_t *io)
{
    http2_client_state_t *state = STATE(self);
    http2_client_con_state_t *con = malloc(sizeof(http2_client_con_state_t));

    memset(con, 0, sizeof(http2_client_con_state_t));
    con->queue = newContextQueue(buffer_pools[tid]);
    con->content_type = state->content_type;
    con->path = state->path;
    con->host = state->host;
    con->host_port = state->host_port;
    con->scheme = state->scheme;
    con->method = HTTP_GET;
    con->line = newLine(tid);
    con->tunnel = self;
    con->io = io;
    con->line->chains_state[self->chain_index] = con;
    nghttp2_session_client_new2(&con->session, state->cbs, con, state->ngoptions);

    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS}};
    nghttp2_submit_settings(con->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));

    con->state = H2_SEND_MAGIC;

    if (state->content_type == APPLICATION_GRPC)
    {
        con->method = HTTP_POST;
    }

    return con;
}
static void delete_http2_connection(http2_client_con_state_t *con)
{
    tunnel_t *self = con->tunnel;

    vec_cons *vector = &(STATE(self)->thread_cpool[con->line->tid].cons);
    vec_cons_iter it = vec_cons_find(vector, con);
    if (it.ref != vec_cons_end(vector).ref)
        vec_cons_erase_at(vector, it);

    http2_client_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        http2_client_child_con_state_t *next = stream_i->next;
        context_t *fin_ctx = newFinContext(stream_i->line);
        tunnel_t *dest = stream_i->tunnel;
        delete_http2_stream(stream_i);
        CSTATE_MUT(fin_ctx) = NULL;
        dest->downStream(dest, fin_ctx);
        stream_i = next;
    }
    nghttp2_session_del(con->session);
    con->line->chains_state[self->chain_index] = NULL;
    destroyContextQueue(con->queue);
    destroyLine(con->line);
    free(con);
}

static http2_client_con_state_t *take_http2_connection(tunnel_t *self, int tid, hio_t *io)
{
    http2_client_state_t *state = STATE(self);
    return create_http2_connection(self, tid, io);
    vec_cons *vector = &(state->thread_cpool[tid].cons);

    if (vec_cons_size(vector) > 0)
    {
        // http2_client_con_state_t * con = *vec_cons_at(vector, round_index);
        c_foreach(k, vec_cons, *vector)
        {
            if ((*k.ref)->childs_added < MAX_CHILD_PER_STREAM)
            {
                (*k.ref)->childs_added += 1;
                return (*k.ref);
            }
        }
        vec_cons_pop(vector);
        http2_client_con_state_t *con = create_http2_connection(self, tid, io);
        vec_cons_push(vector, con);
        return con;
    }
    else
    {
        http2_client_con_state_t *con = create_http2_connection(self, tid, io);
        vec_cons_push(vector, con);
        return con;
    }
}
