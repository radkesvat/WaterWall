#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->k_handle == NULL))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    // any recv indicates that connection is still alive
    ls->last_recv = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    ls->ping_sent = false;

    if (ls->fec_decoder != NULL)
    {
        if (! tcpoverudpFecDecodePacket(ls->fec_decoder,
                                        (const uint8_t *) sbufGetRawPtr(buf),
                                        sbufGetLength(buf),
                                        tcpoverudpserverInputKcpPacket,
                                        ls))
        {
            LOGW("TcpOverUdpServer: dropped invalid FEC packet");
        }
    }
    else
    {
        ikcp_input(ls->k_handle, (const char *) sbufGetRawPtr(buf), (long) sbufGetLength(buf));
    }
    lineReuseBuffer(l, buf);

    // Update KCP state after input to process received data

    if (! tcpoverudpserverUpdateKcp(ls, false))
    {
        return;
    }

    lineLock(l);
    while (true)
    {
        sbuf_t *large_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));

        int read = ikcp_recv(
            ls->k_handle, (void *) sbufGetMutablePtr(large_buf), (int) sbufGetMaximumWriteableSize(large_buf));

        if (read <= 0)
        {
            lineReuseBuffer(l, large_buf);
            break; // No more data available
        }

        sbufSetLength(large_buf, (uint32_t) read);
        uint8_t frame_flag = sbufReadUI8(large_buf);
        sbufShiftRight(large_buf, kFrameHeaderLength);

        if (! ls->can_upstream)
        {
            lineReuseBuffer(l, large_buf);
            break;
        }

        if (frame_flag == kFrameFlagData)
        {
            if (UNLIKELY(sbufGetLength(large_buf) == 0))
            {
                // peers never send empty data frames, discard
                lineReuseBuffer(l, large_buf);
                continue;
            }
            tunnelNextUpStreamPayload(t, l, large_buf);
        }
        else if (frame_flag == kFrameFlagClose)
        {
            lineReuseBuffer(l, large_buf);

            tcpoverudpserverLinestateDestroy(ls);
            tunnelNextUpStreamFinish(t, l);
            if (lineIsAlive(l))
            {
                tunnelPrevDownStreamFinish(t, l);
            }
            break;
        }
        else if (frame_flag == kFrameFlagPing)
        {
            // kcp it self will send ack
            lineReuseBuffer(l, large_buf);
        }
        else
        {
            LOGE("TcpOverUdpServer: Unknown frame flag: %02X", frame_flag);
            lineReuseBuffer(l, large_buf);

            break;
        }

        if (! lineIsAlive(l) || ls->k_handle == NULL)
        {
            break; // Exit the loop if the line is no longer alive
        }
    }

    lineUnlock(l);
}
