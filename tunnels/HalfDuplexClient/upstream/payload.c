#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *createDownloadIntroPayload(halfduplexclient_lstate_t *ls, uint8_t *cid_bytes, uint32_t cids_size)
{
    sbuf_t *intro_download_payload = bufferpoolGetSmallBuffer(getWorkerBufferPool(lineGetWID(ls->download_line)));
    sbufSetLength(intro_download_payload, cids_size);
    
    cid_bytes[0] = cid_bytes[0] | (kHLFDCmdDownload);
    sbufWrite(intro_download_payload, cid_bytes, cids_size);
    
    return intro_download_payload;
}

static bool sendDownloadIntro(tunnel_t *t, halfduplexclient_lstate_t *ls, sbuf_t *intro_download_payload, sbuf_t *buf)
{
    line_t *download_line = ls->download_line;
    
    lineLock(download_line);
    tunnelNextUpStreamPayload(t, ls->download_line, intro_download_payload);
    
    if (!lineIsAlive(download_line))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(download_line)), buf);
        lineUnlock(download_line);
        return false;
    }
    
    lineUnlock(download_line);
    return true;
}

static sbuf_t *createUploadIntroPayload(tunnel_t *t, sbuf_t *buf, uint8_t *cid_bytes, uint32_t cids_size)
{
    // this function is the last written function in the upstream payload, so no line lock/unlock is needed

    cid_bytes[0] = cid_bytes[0] & kHLFDCmdUpload;
    
    sbuf_t *intro_upload_payload = sbufCreateWithPadding(sbufGetLength(buf), 
                                                         cids_size + tunnelGetChain(t)->sum_padding_left);
    
    sbufSetLength(intro_upload_payload, sbufGetLength(buf));
    memoryCopyLarge(sbufGetMutablePtr(intro_upload_payload), sbufGetRawPtr(buf), sbufGetLength(buf));
    sbufShiftLeft(intro_upload_payload, cids_size);
    sbufWrite(intro_upload_payload, cid_bytes, cids_size);
    
    return intro_upload_payload;
}

static void handleFirstPacket(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexclient_lstate_t *ls)
{
    halfduplexclient_tstate_t *state = tunnelGetState(t);
    
    ls->first_packet_sent = true;
    uint64_t identifier = atomicIncRelaxed(&state->identifier);
    uint32_t cids[2] = {0};
    uint8_t *cid_bytes = (uint8_t *)&(cids[0]);
    
    PUT_BE64(cid_bytes, identifier);
    
    sbuf_t *intro_download_payload = createDownloadIntroPayload(ls, cid_bytes, sizeof(cids));
    
    if (!sendDownloadIntro(t, ls, intro_download_payload, buf))
    {
        return;
    }
    
    sbuf_t *intro_upload_payload = createUploadIntroPayload(t, buf, cid_bytes, sizeof(cids));
    
    bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    
    line_t *upload_line = ls->upload_line;
    tunnelNextUpStreamPayload(t, upload_line, intro_upload_payload);
}

void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);
    
    if (UNLIKELY(!ls->first_packet_sent))
    {
        handleFirstPacket(t, l, buf, ls);
    }
    else
    {
        tunnelNextUpStreamPayload(t, ls->upload_line, buf);
    }
}
