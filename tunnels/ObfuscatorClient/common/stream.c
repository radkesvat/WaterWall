#include "loggers/network_logger.h"
#include "structure.h"

static void closeStream(tunnel_t *t, line_t *l)
{
    obfuscatorclient_lstate_t *ls              = lineGetState(l, t);
    const bool                 from_downstream = ls->initialized_from_downstream;
    lineRef(l);
    obfuscatorclientLinestateDestroy(ls);
    /* Finish the borrowed side before notifying the source that owns this line. */
    if (from_downstream)
    {
        tunnelPrevDownStreamFinish(t, l);
        if (lineIsAlive(l))
            tunnelNextUpStreamFinish(t, l);
    }
    else
    {
        tunnelNextUpStreamFinish(t, l);
        if (lineIsAlive(l))
            tunnelPrevDownStreamFinish(t, l);
    }
    lineUnref(l);
}

void obfuscatorclientEncodeStream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorclient_tstate_t *ts             = tunnelGetState(t);
    const size_t               incoming_bytes = sbufGetLength(buf);
    sbuf_t                    *out = obfuscatorEncodeStream(lineGetBufferPool(l), buf, ts->skip, ts->xor_key);
    if (! out)
    {
        LOGW("ObfuscatorClient: closing connection: encoded aggregate allocation geometry refused (input_bytes=%zu)",
             incoming_bytes);
        closeStream(t, l);
        return;
    }
    tunnelNextUpStreamPayload(t, l, out);
}

void obfuscatorclientDecodeStream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorclient_tstate_t *ts = tunnelGetState(t);
    obfuscatorclient_lstate_t *ls = lineGetState(l, t);
    sbuf_t                    *out;
    const size_t               retained_bytes = bufferstreamGetLength(&ls->read_stream);
    const size_t               incoming_bytes = sbufGetLength(buf);
    switch (obfuscatorDecodeStream(lineGetBufferPool(l), &ls->read_stream, buf, ts->skip, ts->xor_key, &out))
    {
    case kObfuscatorDecodeReady:
        tunnelPrevDownStreamPayload(t, l, out);
        return;
    case kObfuscatorDecodeIncomplete:
        return;
    case kObfuscatorDecodeInvalid:
        LOGW("ObfuscatorClient: closing connection: invalid TLS-like record type or version");
        closeStream(t, l);
        return;
    case kObfuscatorDecodeOverflow:
        LOGW("ObfuscatorClient: closing connection: receive retention limit exceeded "
             "(retained_bytes=%zu, incoming_bytes=%zu, limit_bytes=%u)",
             retained_bytes,
             incoming_bytes,
             (unsigned) kObfuscatorMaxBufferedStreamBytes);
        closeStream(t, l);
        return;
    }
}
