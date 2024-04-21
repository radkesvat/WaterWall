#pragma once
#include "types.h"

#define MAX_CONCURRENT_STREAMS 0xffffffffu

static nghttp2_nv makeNv(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name     = (uint8_t *) name;
    nv.value    = (uint8_t *) value;
    nv.namelen  = strlen(name);
    nv.valuelen = strlen(value);
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static nghttp2_nv makeNv2(const char *name, const char *value, int namelen, int valuelen)
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
    LOGD("[frame] length=%d type=%x flags=%x stream_id=%d\n", (int) hd->length, (int) hd->type, (int) hd->flags,
         hd->stream_id);
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
http2_server_child_con_state_t *createHttp2Stream(http2_server_con_state_t *con, line_t *this_line,
                                                  tunnel_t *target_tun, int32_t stream_id)
{
    http2_server_child_con_state_t *stream;
    stream = malloc(sizeof(http2_server_child_con_state_t));
    memset(stream, 0, sizeof(http2_server_child_con_state_t));
    stream->stream_id                                       = stream_id;
    stream->chunkbs                                         = newBufferStream(buffer_pools[this_line->tid]);
    stream->parent                                          = this_line;
    stream->line                                            = newLine(this_line->tid);
    stream->line->chains_state[target_tun->chain_index - 1] = stream;
    stream->io                                              = NULL;
    stream->tunnel                                          = target_tun;
    nghttp2_session_set_stream_user_data(con->session, stream_id, stream);

    return stream;
}
static void deleteHttp2Stream(http2_server_child_con_state_t *stream)
{

    stream->line->chains_state[stream->tunnel->chain_index - 1] = NULL;
    destroyBufferStream(stream->chunkbs);
    destroyLine(stream->line);
    if (stream->request_path)
    {
        free(stream->request_path);
    }
    free(stream);
}

static http2_server_con_state_t *createHttp2Connection(tunnel_t *self, line_t *line, hio_t *io)
{
    http2_server_state_t *    state = STATE(self);
    http2_server_con_state_t *con   = malloc(sizeof(http2_server_con_state_t));
    memset(con, 0, sizeof(http2_server_con_state_t));

    nghttp2_session_server_new2(&con->session, state->cbs, con, state->ngoptions);
    con->state  = kH2WantRecv;
    con->tunnel = self;
    con->line   = line;
    con->io     = io;

    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS}};
    nghttp2_submit_settings(con->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));
    con->state = kH2SendSettings;
    return con;
}
static void deleteHttp2Connection(http2_server_con_state_t *con)
{
    tunnel_t *                      self = con->tunnel;
    http2_server_child_con_state_t *stream_i;
    for (stream_i = con->root.next; stream_i;)
    {
        context_t *                     fin_ctx = newFinContext(stream_i->line);
        tunnel_t *                      dest    = stream_i->tunnel;
        http2_server_child_con_state_t *next    = stream_i->next;
        deleteHttp2Stream(stream_i);
        CSTATE_MUT(fin_ctx) = NULL;
        dest->upStream(dest, fin_ctx);
        stream_i = next;
    }

    nghttp2_session_del(con->session);

    con->line->chains_state[self->chain_index] = NULL;
    free(con);
}
