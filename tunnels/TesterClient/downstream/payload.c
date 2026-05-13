#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    testerclient_lstate_t *ls = lineGetState(l, t);
    testerclient_tstate_t *ts = tunnelGetState(t);

    if (ts->packet_mode)
    {
        uint32_t bad_offset = 0;
        uint8_t  expected   = 0;
        uint8_t  actual     = 0;
        uint8_t  chunk_count = testerclientGetChunkCount(t);

        if (! ls->request_complete)
        {
            lineReuseBuffer(l, buf);
            testerclientFail(t, l, "received packet-mode response payload before request send completed");
            return;
        }

        if (ls->response_complete)
        {
            lineReuseBuffer(l, buf);
            testerclientFail(t, l, "received extra packet-mode response payload after verification completed");
            return;
        }

        if (ls->response_rx_index >= chunk_count)
        {
            lineReuseBuffer(l, buf);
            testerclientFail(t, l, "received more packet-mode responses than expected");
            return;
        }

        if (! testerclientVerifyChunk(t, l, buf, ls->response_rx_index, kTesterClientDirectionResponse, &bad_offset,
                                      &expected, &actual))
        {
            LOGE("TesterClient: worker %u packet response chunk %u mismatch (size=%u expected_size=%u bad_offset=%u "
                 "expected=0x%02x actual=0x%02x)",
                 (unsigned int) lineGetWID(l), (unsigned int) ls->response_rx_index, (unsigned int) sbufGetLength(buf),
                 (unsigned int) testerclientGetChunkSize(t, ls->response_rx_index), (unsigned int) bad_offset,
                 (unsigned int) expected, (unsigned int) actual);
            lineReuseBuffer(l, buf);
            terminateProgram(1);
            return;
        }

        lineReuseBuffer(l, buf);
        ls->response_rx_index += 1;

        if (ls->response_rx_index == chunk_count)
        {
            ls->response_complete = true;
            testerclientMarkWorkerComplete(t, l);
        }
        return;
    }

    if (! ls->request_complete && ! ts->allow_early_response)
    {
        lineReuseBuffer(l, buf);
        testerclientFail(t, l, "received response payload before request send completed");
        return;
    }

    if (ls->response_complete)
    {
        lineReuseBuffer(l, buf);
        testerclientFail(t, l, "received extra response payload after verification completed");
        return;
    }

    bufferstreamPush(&ls->read_stream, buf);

    if (bufferstreamGetBufLen(&ls->read_stream) > testerclientGetRemainingBytes(t, ls->response_rx_index))
    {
        testerclientFail(t, l, "buffered response exceeds remaining expected bytes");
        return;
    }

    const uint8_t chunk_count = testerclientGetChunkCount(t);

    while (ls->response_rx_index < chunk_count &&
           bufferstreamGetBufLen(&ls->read_stream) >= testerclientGetChunkSize(t, ls->response_rx_index))
    {
        uint32_t bad_offset   = 0;
        uint8_t  expected     = 0;
        uint8_t  actual       = 0;
        sbuf_t  *chunk_buffer = bufferstreamReadExact(&ls->read_stream, testerclientGetChunkSize(t, ls->response_rx_index));

        if (! testerclientVerifyChunk(t, l, chunk_buffer, ls->response_rx_index, kTesterClientDirectionResponse,
                                      &bad_offset, &expected, &actual))
        {
            lineReuseBuffer(l, chunk_buffer);
            LOGE("TesterClient: worker %u response chunk %u mismatch at byte %u (expected=0x%02x actual=0x%02x)",
                 (unsigned int) lineGetWID(l), (unsigned int) ls->response_rx_index, (unsigned int) bad_offset,
                 (unsigned int) expected, (unsigned int) actual);
            terminateProgram(1);
            return;
        }

        lineReuseBuffer(l, chunk_buffer);
        ls->response_rx_index += 1;
    }

    if (ls->response_rx_index == chunk_count)
    {
        if (! bufferstreamIsEmpty(&ls->read_stream))
        {
            testerclientFail(t, l, "response stream has trailing bytes after expected sequence");
            return;
        }

        ls->response_complete = true;
        testerclientMarkWorkerComplete(t, l);
    }
}
