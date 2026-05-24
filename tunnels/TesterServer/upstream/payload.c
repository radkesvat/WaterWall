#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    testerserver_lstate_t *ls = lineGetState(l, t);
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (ts->packet_mode)
    {
        ls->response_to_next = false;
        if (ts->packet_stateless)
        {
            testerserverHandlePacketStatelessRequestPayload(t, l, buf);
            return;
        }

        testerserverHandlePacketRequestPayload(t, l, buf);
        return;
    }

    if (ls->response_ready)
    {
        lineReuseBuffer(l, buf);
        testerserverFail(t, l, "received extra request payload after request verification completed");
        return;
    }

    bufferstreamPush(&ls->read_stream, buf);
    bool request_progressed = false;

    if (bufferstreamGetBufLen(&ls->read_stream) > testerserverGetRemainingBytes(t, ls->request_rx_index))
    {
        testerserverFail(t, l, "buffered request exceeds remaining expected bytes");
        return;
    }

    const uint8_t chunk_count = testerserverGetChunkCount(t);

    while (ls->request_rx_index < chunk_count &&
           bufferstreamGetBufLen(&ls->read_stream) >= testerserverGetChunkSize(t, ls->request_rx_index))
    {
        uint32_t bad_offset   = 0;
        uint8_t  expected     = 0;
        uint8_t  actual       = 0;
        sbuf_t  *chunk_buffer = bufferstreamReadExact(&ls->read_stream, testerserverGetChunkSize(t, ls->request_rx_index));

        if (! testerserverVerifyChunk(t, l, chunk_buffer, ls->request_rx_index, kTesterServerDirectionRequest,
                                      &bad_offset, &expected, &actual))
        {
            lineReuseBuffer(l, chunk_buffer);
            LOGE("TesterServer: worker %u request chunk %u mismatch at byte %u (expected=0x%02x actual=0x%02x)",
                 (unsigned int) lineGetWID(l), (unsigned int) ls->request_rx_index, (unsigned int) bad_offset,
                 (unsigned int) expected, (unsigned int) actual);
            terminateProgram(1);
            return;
        }

        lineReuseBuffer(l, chunk_buffer);
        ls->request_rx_index += 1;
        request_progressed = true;
    }

    if (ls->request_rx_index == chunk_count)
    {
        if (! bufferstreamIsEmpty(&ls->read_stream))
        {
            testerserverFail(t, l, "request stream has trailing bytes after expected sequence");
            return;
        }

        ls->response_ready = true;
        testerserverScheduleResponseSend(t, l, ls);
        return;
    }

    if (request_progressed && ts->streaming_response)
    {
        testerserverScheduleResponseSend(t, l, ls);
    }
}
