#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    encryptionclient_tstate_t *ts = tunnelGetState(t);
    encryptionclient_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&(ls->read_stream), buf);

    while (true)
    {
        sbuf_t                   *frame_buffer = NULL;
        encryption_frame_result_t read_result =
            encryptionReadFrame(&ls->read_stream, ts->max_frame_payload, &frame_buffer);

        if (read_result == kEncryptionFrameNeedMore)
        {
            return;
        }

        if (read_result == kEncryptionFrameInvalid)
        {
            LOGW("EncryptionClient: invalid encrypted frame received, closing line");
            encryptionclientCloseLineBidirectional(t, l);
            return;
        }

        if (encryptionDecodeFrame(ts->algorithm, ts->key, frame_buffer) != kWCryptoOk)
        {
            LOGW("EncryptionClient: failed to decrypt frame, closing line");
            lineReuseBuffer(l, frame_buffer);
            encryptionclientCloseLineBidirectional(t, l);
            return;
        }

        if (! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, frame_buffer))
        {
            return;
        }
    }
}
