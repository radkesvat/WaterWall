#include "structure.h"

#include "loggers/network_logger.h"

static sbuf_t *createDownloadIntroPayload(halfduplexclient_lstate_t *ls, const uint8_t pair_id[kHLFDPairIdSize])
{
    sbuf_t *intro_download_payload = bufferpoolGetSmallBuffer(getWorkerBufferPool(lineGetWID(ls->download_line)));
    sbufSetLength(intro_download_payload, kHLFDIntroSize);

    uint8_t *intro            = sbufGetMutablePtr(intro_download_payload);
    intro[kHLFDCommandOffset] = kHLFDCmdDownload;
    memoryCopy(intro + kHLFDPairIdOffset, pair_id, kHLFDPairIdSize);

    return intro_download_payload;
}

static bool sendDownloadIntro(tunnel_t *t, halfduplexclient_lstate_t *ls, sbuf_t *intro_download_payload, sbuf_t *buf)
{
    line_t *download_line = ls->download_line;

    lineRef(download_line);
    tunnelNextUpStreamPayload(t, ls->download_line, intro_download_payload);

    if (! lineIsAlive(download_line))
    {
        lineReuseBuffer(download_line, buf);
        lineUnref(download_line);
        return false;
    }

    lineUnref(download_line);
    return true;
}

static sbuf_t *createUploadIntroPayload(tunnel_t *t, sbuf_t *buf, const uint8_t pair_id[kHLFDPairIdSize])
{
    // this is the last operation in upstream payload handling, so no line
    // reference or liveness recheck is needed.

    const uint32_t payload_size = sbufGetLength(buf);
    assert(payload_size <= UINT32_MAX - kHLFDIntroSize);
    const uint32_t framed_size          = payload_size + kHLFDIntroSize;
    sbuf_t        *intro_upload_payload = sbufCreateWithPadding(framed_size, tunnelGetChain(t)->sum_padding_left);

    sbufSetLength(intro_upload_payload, framed_size);
    uint8_t *framed            = sbufGetMutablePtr(intro_upload_payload);
    framed[kHLFDCommandOffset] = kHLFDCmdUpload;
    memoryCopy(framed + kHLFDPairIdOffset, pair_id, kHLFDPairIdSize);
    memoryCopyLarge(framed + kHLFDIntroSize, sbufGetRawPtr(buf), payload_size);

    return intro_upload_payload;
}

static void handleFirstPacket(tunnel_t *t, line_t *l, sbuf_t *buf, halfduplexclient_lstate_t *ls)
{
    uint8_t pair_id[kHLFDPairIdSize];
    PUT_BE64(pair_id, fastRand64());
    PUT_BE64(pair_id + (kHLFDPairIdSize / 2), fastRand64());

    sbuf_t *intro_download_payload = createDownloadIntroPayload(ls, pair_id);

    if (! sendDownloadIntro(t, ls, intro_download_payload, buf))
    {
        return;
    }

    ls->first_packet_sent = true;

    sbuf_t *intro_upload_payload = createUploadIntroPayload(t, buf, pair_id);

    lineReuseBuffer(l, buf);

    line_t *upload_line = ls->upload_line;
    tunnelNextUpStreamPayload(t, upload_line, intro_upload_payload);
}

void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(! ls->first_packet_sent))
    {
        handleFirstPacket(t, l, buf, ls);
    }
    else
    {
        tunnelNextUpStreamPayload(t, ls->upload_line, buf);
    }
}
