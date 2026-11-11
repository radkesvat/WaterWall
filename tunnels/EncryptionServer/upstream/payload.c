#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    encryptionserver_tstate_t *ts = tunnelGetState(t);
    encryptionserver_lstate_t *ls = lineGetState(l, t);

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
            uint8_t header[kEncryptionTlsHeaderSize];
            bufferstreamCopyBytesAt(&ls->read_stream, 0, header, sizeof(header));
            const unsigned body_bytes     = ((unsigned) header[3] << 8) | header[4];
            const bool     header_invalid = header[0] != kEncryptionTlsApplicationData ||
                                        header[1] != kEncryptionTlsVersionMajor ||
                                        header[2] != kEncryptionTlsVersionMinor;
            LOGW("EncryptionServer: closing connection: invalid encrypted frame %s "
                 "(body_bytes=%u, minimum_body_bytes=%u, effective_body_limit_bytes=%u, max_frame_payload=%u)",
                 header_invalid ? "type/version" : "body length",
                 body_bytes,
                 (unsigned) (kEncryptionNonceSize + kEncryptionTagSize),
                 ts->max_frame_payload + kEncryptionNonceSize + kEncryptionTagSize,
                 ts->max_frame_payload);
            encryptionserverCloseLineBidirectional(t, l);
            return;
        }

        if (encryptionDecodeFrame(ts->algorithm, ts->key, frame_buffer) != kWCryptoOk)
        {
            LOGW("EncryptionServer: failed to decrypt frame, closing line");
            lineReuseBuffer(l, frame_buffer);
            encryptionserverCloseLineBidirectional(t, l);
            return;
        }

        if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, frame_buffer))
        {
            return;
        }
    }
}
