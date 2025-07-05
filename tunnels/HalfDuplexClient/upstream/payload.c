#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexclient_tstate_t* state = tunnelGetState(t);

    halfduplexclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->first_packet_sent))
    {
        ls->first_packet_sent = true;
        uint64_t identifier = atomicIncRelaxed(&state->identifier);
        uint32_t cids[2]   = {0};
        uint8_t *cid_bytes = (uint8_t *) &(cids[0]);

        PUT_BE64(cid_bytes,identifier);

        sbuf_t *intro_download_payload = bufferpoolGetSmallBuffer(getWorkerBufferPool(lineGetWID(ls->download_line)));
        sbufSetLength(intro_download_payload, sizeof(cids));

        cid_bytes[0] = cid_bytes[0] | (kHLFDCmdDownload);
        sbufWrite(intro_download_payload, cid_bytes, sizeof(cids));
        line_t *download_line = ls->download_line;

        lineLock(download_line);

        tunnelNextUpStreamPayload(t, ls->download_line, intro_download_payload);

        if (! lineIsAlive(download_line))
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(download_line)), buf);
            lineUnlock(download_line);
            return;
        }
        lineUnlock(download_line);

        cid_bytes[0] = cid_bytes[0] & kHLFDCmdUpload;

        sbuf_t *intro_upload_payload =
            sbufCreateWithPadding(sbufGetLength(buf), sizeof(cids) + tunnelGetChain(t)->sum_padding_left);

        sbufSetLength(intro_upload_payload, sbufGetLength(buf));
        memoryCopyLarge(sbufGetMutablePtr(intro_upload_payload), sbufGetRawPtr(buf), sbufGetLength(buf));
        sbufShiftLeft(intro_upload_payload, sizeof(cids));
        sbufWrite(intro_upload_payload, cid_bytes, sizeof(cids));

        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);

        line_t *upload_line = ls->upload_line;
        tunnelNextUpStreamPayload(t, upload_line, intro_upload_payload);
    }
    else
    {
        tunnelNextUpStreamPayload(t, ls->upload_line, buf);
    }
}
