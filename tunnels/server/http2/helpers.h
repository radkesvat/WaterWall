#pragma once
#include "types.h"

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

static void add_stream(http2_server_con_state_t *con,
                       http2_server_child_con_state_t *stream)
{
    stream->next = con->root.next;
    con->root.next = stream;
    stream->prev = &con->root;
    if (stream->next)
    {
        stream->next->prev = stream;
    }
}
static void remove_stream(http2_server_con_state_t *con,
                          http2_server_child_con_state_t *stream)
{

    stream->prev->next = stream->next;
    if (stream->next)
    {
        stream->next->prev = stream->prev;
    }
}
http2_server_child_con_state_t *
create_http2_stream(http2_server_con_state_t *con, line_t *this_line, tunnel_t *target_tun, int32_t stream_id)
{
    http2_server_child_con_state_t *stream;
    stream = malloc(sizeof(http2_server_child_con_state_t));
    memset(stream, 0, sizeof(http2_server_child_con_state_t));
    stream->stream_id = stream_id;
    stream->parent = this_line;
    stream->line = newLine(this_line->tid);
    stream->line->chains_state[target_tun->chain_index - 1] = stream;
    stream->tunnel = target_tun;
    add_stream(con, stream);
    nghttp2_session_set_stream_user_data(con->session, stream_id, stream);

    return stream;
}
static void delete_http2_stream(http2_server_child_con_state_t *stream)
{

    stream->line->chains_state[stream->tunnel->chain_index - 1] = NULL;
    destroyLine(stream->line);
    if (stream->request_path)
        free(stream->request_path);
    free(stream);
}

static void delete_http2_connection(http2_server_con_state_t *con)
{
    tunnel_t *self = con->tunnel;
    http2_server_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        context_t *fin_ctx = newFinContext(stream_i->line);

        http2_server_child_con_state_t *next = stream_i->next;
        delete_http2_stream(stream_i);
        stream_i->tunnel->upStream(stream_i->tunnel, fin_ctx);
        stream_i = next;
    }

    nghttp2_session_del(con->session);
    con->line->chains_state[self->chain_index] = NULL;
    free(con);

}
