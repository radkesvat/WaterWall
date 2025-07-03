#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! ls->first_packet_sent))
    {
        ls->first_packet_sent = true;
        // 63 bits of random is enough and is better than hashing sender addr on halfduplex server, i believe so...
        uint32_t cids[2]   = {fastRand(), fastRand()};
        uint8_t *cid_bytes = (uint8_t *) &(cids[0]);
        cid_bytes[0]       = cid_bytes[0] & kHLFDCmdUpload;

        sbuf_t *intro_upload_payload =
            sbufCreateWithPadding(sbufGetLength(buf), sizeof(cids) + tunnelGetChain(t)->sum_padding_left);

        sbufSetLength(intro_upload_payload, sbufGetLength(buf));
        memoryCopyLarge(sbufGetMutablePtr(intro_upload_payload), sbufGetRawPtr(buf), sbufGetLength(buf));
        sbufShiftLeft(intro_upload_payload, sizeof(cids));
        sbufWrite(intro_upload_payload, cid_bytes, sizeof(cids));

        line_t *upload_line = ls->upload_line;
        lineLock(upload_line);
        tunnelNextUpStreamPayload(t, upload_line, intro_upload_payload);

        if (! lineIsAlive(upload_line))
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(upload_line)), buf);
            lineUnlock(upload_line);
            return;
        }
        lineUnlock(upload_line);

        sbuf_t *intro_download_payload = bufferpoolGetSmallBuffer(getWorkerBufferPool(lineGetWID(ls->download_line)));
        sbufSetLength(intro_download_payload, sizeof(cids));

        cid_bytes[0] = cid_bytes[0] | (kHLFDCmdDownload); 
        sbufWrite(intro_download_payload, cid_bytes, sizeof(cids));
        tunnelNextUpStreamPayload(t, ls->download_line, intro_download_payload);
    }
    else
    {
        tunnelNextUpStreamPayload(t, ls->upload_line, buf);
    }
}
