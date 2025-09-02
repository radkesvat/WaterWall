#include "structure.h"

#include "loggers/network_logger.h"

static inline nghttp2_nv makeNV(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name     = (uint8_t *) name;
    nv.value    = (uint8_t *) value;
    nv.namelen  = stringLength(name);
    nv.valuelen = stringLength(value);
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}


void httpclientV2TunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    // LOGD("closing -> %d", (int) ls->stream_id);

    
    int flags = NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_END_HEADERS;

    if (ls->content_type == kApplicationGrpc)
    {
        nghttp2_nv nv = makeNV("grpc-status", "0");
        nghttp2_submit_headers(ls->session, flags, ls->stream_id, NULL, &nv, 1, NULL);
    }
    else
    {
        nghttp2_submit_headers(ls->session, flags, ls->stream_id, NULL, NULL, 0, NULL);
    }

    nghttp2_session_set_stream_user_data(ls->session, ls->stream_id, NULL);

  
    if (! httpclientV2PullAndSendNgHttp2SendableData(t, ls))
    {
        return;
    }
   
    httpclientV2LinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
}
