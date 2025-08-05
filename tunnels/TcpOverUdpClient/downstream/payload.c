#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    // any recv indicates that connection is still alive
    ls->last_recv = wloopNowMS(getWorkerLoop(lineGetWID(l)));
    ls->ping_sent = false;

    ikcp_input(ls->k_handle, (void *) sbufGetMutablePtr(buf), (int) sbufGetLength(buf));
    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);

    // Update KCP state after input to process received data

    if (! tcpoverudpclientUpdateKcp(ls, false))
    {
        return;
    }

    lineLock(l);
    while (true)
    {
        sbuf_t *large_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));

        int read =
            ikcp_recv(ls->k_handle, (void *) sbufGetMutablePtr(large_buf), (int) sbufGetRightCapacity(large_buf));

        if (read <= 0)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(l), large_buf);
            break; // No more data available
        }

        sbufSetLength(large_buf, (uint32_t) read);
        uint8_t frame_flag = sbufReadUI8(large_buf);
        sbufShiftRight(large_buf, kFrameHeaderLength);

        if (! ls->can_downstream)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(l), large_buf);
            break;
        }

        if (frame_flag == kFrameFlagData)
        {
            tunnelPrevDownStreamPayload(t, l, large_buf);
        }
        else if (frame_flag == kFrameFlagClose)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(l), large_buf);

            tcpoverudpclientLinestateDestroy(ls);
            tunnelNextUpStreamFinish(t, l);
            tunnelPrevDownStreamFinish(t, l);
            break;
        }
        else if (frame_flag == kFrameFlagPing)
        {
            // kcp it self will send ack
            bufferpoolReuseBuffer(lineGetBufferPool(l), large_buf);
        }
        else
        {
            LOGE("TcpOverUdpClient: Unknown frame flag: %02X", frame_flag);
            bufferpoolReuseBuffer(lineGetBufferPool(l), large_buf);

            break;
        }

        if (! lineIsAlive(l))
        {
            break; // Exit the loop if the line is no longer alive
        }
    }

    lineUnlock(l);
}
