#include "structure.h"

#include "loggers/network_logger.h"

static bool decodeAndForward(tunnel_t *t, line_t *l, const encryptionclient_tstate_t *ts, sbuf_t *frame)
{
    if (encryptionDecodeFrame(ts->algorithm, ts->key, frame) != kWCryptoOk)
    {
        LOGW("EncryptionClient: failed to decrypt frame, closing line");
        lineReuseBuffer(l, frame);
        encryptionclientCloseLineBidirectional(t, l);
        return false;
    }

    return lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, frame);
}

void encryptionclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    encryptionclient_tstate_t *ts = tunnelGetState(t);
    encryptionclient_lstate_t *ls = lineGetState(l, t);

    if (ls->datagram)
    {
        if (! encryptionDatagramHasFrame(buf, ts->max_frame_payload))
        {
            LOGW("EncryptionClient: closing line: invalid encrypted datagram record");
            lineReuseBuffer(l, buf);
            encryptionclientCloseLineBidirectional(t, l);
            return;
        }
        discard decodeAndForward(t, l, ts, buf);
        return;
    }

    bufferstreamPush(&ls->read_stream, buf);

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
            LOGW("EncryptionClient: closing connection: invalid encrypted frame %s "
                 "(body_bytes=%u, minimum_body_bytes=%u, effective_body_limit_bytes=%u, max_frame_payload=%u)",
                 header_invalid ? "type/version" : "body length",
                 body_bytes,
                 (unsigned) (kEncryptionNonceSize + kEncryptionTagSize),
                 ts->max_frame_payload + kEncryptionNonceSize + kEncryptionTagSize,
                 ts->max_frame_payload);
            encryptionclientCloseLineBidirectional(t, l);
            return;
        }

        if (! decodeAndForward(t, l, ts, frame_buffer))
        {
            return;
        }
    }
}
