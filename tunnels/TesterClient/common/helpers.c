#include "structure.h"

#include "loggers/network_logger.h"

static const uint32_t kTesterClientChunkSizes[kTesterClientChunkCount] = {
    1U,
    2U,
    4U,
    32U,
    512U,
    1024U,
    4096U,
    32768U,
    32769U,
    1 * 1024U * 1024U,
    2 * 1024U * 1024U,
};

static const uint32_t kTesterClientPacketChunkSizes[kTesterClientChunkCount] = {
    1U,
    2U,
    4U,
    32U,
    64U,
    128U,
    256U,
    512U,
    1024U,
    1499U,
    1500U,
};

static const uint32_t kTesterClientPacketChunkSizeMax = 1500U;

static inline const uint32_t *testerclientGetChunkTable(tunnel_t *t)
{
    testerclient_tstate_t *ts = tunnelGetState(t);

    return ts->packet_mode ? kTesterClientPacketChunkSizes : kTesterClientChunkSizes;
}

static uint8_t testerclientFlowMarker(uint8_t flow_id, testerclient_direction_e direction)
{
    return (uint8_t) (flow_id ^ ((direction == kTesterClientDirectionResponse) ? 0xC3U : 0x3CU));
}

static uint8_t testerclientPatternByte(uint32_t offset, uint8_t chunk_index, uint8_t flow_id,
                                       testerclient_direction_e direction)
{
    // The very first byte carries the client-selected flow id so the far end can
    // derive the deterministic pattern even if adapters remap the connection to a
    // different worker.
    if (chunk_index == 0 && offset == 0)
    {
        return testerclientFlowMarker(flow_id, direction);
    }

    uint32_t value = offset;
    value ^= value >> 13;
    value *= 0x45d9f3bu;
    value ^= ((uint32_t) chunk_index + 1U) * 0x27d4eb2du;
    value ^= ((uint32_t) flow_id + 1U) * 0x165667b1u;
    value ^= (direction == kTesterClientDirectionResponse) ? 0xA5A5A5A5u : 0x5A5A5A5Au;
    value ^= value >> 16;
    return (uint8_t) value;
}

static uint8_t testerclientGetFlowId(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls = lineGetState(l, t);

    return ls->flow_id;
}

static void testerclientFillPayloadForFlow(uint8_t flow_id, sbuf_t *buf, uint8_t chunk_index, uint32_t chunk_offset,
                                           testerclient_direction_e direction)
{
    uint32_t payload_len = sbufGetLength(buf);
    uint8_t *ptr         = sbufGetMutablePtr(buf);

    for (uint32_t i = 0; i < payload_len; ++i)
    {
        ptr[i] = testerclientPatternByte(chunk_offset + i, chunk_index, flow_id, direction);
    }
}

void testerclientFail(tunnel_t *t, line_t *l, const char *reason)
{
    LOGE("TesterClient: worker %u failed: %s", (unsigned int) lineGetWID(l), reason);
    discard t;
    terminateProgram(1);
}

uint32_t testerclientGetChunkSize(tunnel_t *t, uint8_t index)
{
    assert(index < kTesterClientChunkCount);
    return testerclientGetChunkTable(t)[index];
}

uint64_t testerclientGetRemainingBytes(tunnel_t *t, uint8_t index)
{
    uint64_t        remaining   = 0;
    const uint32_t *chunk_sizes = testerclientGetChunkTable(t);

    for (uint8_t i = index; i < kTesterClientChunkCount; ++i)
    {
        remaining += chunk_sizes[i];
    }

    return remaining;
}

sbuf_t *testerclientCreatePayload(tunnel_t *t, line_t *l, uint8_t chunk_index, uint32_t chunk_offset,
                                  uint32_t payload_len, testerclient_direction_e direction)
{
    buffer_pool_t         *pool = lineGetBufferPool(l);
    testerclient_tstate_t *ts   = tunnelGetState(t);
    sbuf_t                *buf  = NULL;

    if (ts->packet_mode)
    {
        if (payload_len != testerclientGetChunkSize(t, chunk_index))
        {
            testerclientFail(t, l, "packet-mode payload generation attempted to split a packet chunk");
            return NULL;
        }

        if (bufferpoolGetSmallBufferSize(pool) < kTesterClientPacketChunkSizeMax)
        {
            testerclientFail(t, l, "packet-mode requires small buffers with at least 1500 bytes write capacity");
            return NULL;
        }

        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (payload_len <= bufferpoolGetSmallBufferSize(pool))
    {
        buf = bufferpoolGetSmallBuffer(pool);
    }
    else if (payload_len <= bufferpoolGetLargeBufferSize(pool))
    {
        buf = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        testerclientFail(t, l, "stream-mode payload generation exceeded large buffer size");
        return NULL;
    }

    sbufSetLength(buf, payload_len);
    testerclientFillPayloadForFlow(testerclientGetFlowId(t, l), buf, chunk_index, chunk_offset, direction);

    return buf;
}

bool testerclientVerifyChunk(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t chunk_index,
                             testerclient_direction_e direction, uint32_t *bad_offset, uint8_t *expected,
                             uint8_t *actual)
{
    const uint8_t *ptr         = sbufGetRawPtr(buf);
    uint32_t       payload_len = sbufGetLength(buf);
    uint8_t        flow_id     = testerclientGetFlowId(t, l);

    if (payload_len != testerclientGetChunkSize(t, chunk_index))
    {
        if (bad_offset != NULL)
        {
            *bad_offset = payload_len;
        }
        return false;
    }

    for (uint32_t i = 0; i < payload_len; ++i)
    {
        uint8_t expected_byte = testerclientPatternByte(i, chunk_index, flow_id, direction);
        if (ptr[i] != expected_byte)
        {
            if (bad_offset != NULL)
            {
                *bad_offset = i;
            }
            if (expected != NULL)
            {
                *expected = expected_byte;
            }
            if (actual != NULL)
            {
                *actual = ptr[i];
            }
            return false;
        }
    }

    return true;
}

void testerclientScheduleRequestSend(tunnel_t *t, line_t *l, testerclient_lstate_t *ls)
{
    if (ls->request_send_scheduled || ls->request_complete || ! ls->est_received)
    {
        return;
    }

    ls->request_send_scheduled = true;
    lineScheduleTask(l, testerclientRequestSendTask, t);
}

void testerclientRequestSendTask(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls = lineGetState(l, t);
    buffer_pool_t         *pool = lineGetBufferPool(l);

    ls->request_send_scheduled = false;

    while (! ls->request_paused && ls->request_tx_index < kTesterClientChunkCount)
    {
        uint32_t chunk_size = testerclientGetChunkSize(t, ls->request_tx_index);
        uint32_t remaining  = chunk_size - ls->request_tx_offset;
        uint32_t max_len    = bufferpoolGetLargeBufferSize(pool);

        if (max_len == 0)
        {
            testerclientFail(t, l, "large buffer pool reports zero writable payload capacity");
            return;
        }

        uint32_t payload_len = (remaining < max_len) ? remaining : max_len;
        sbuf_t  *buf         = testerclientCreatePayload(
            t, l, ls->request_tx_index, ls->request_tx_offset, payload_len, kTesterClientDirectionRequest);

        if (buf == NULL)
        {
            return;
        }

        ls->request_tx_offset += payload_len;
        if (ls->request_tx_offset == chunk_size)
        {
            ls->request_tx_index += 1;
            ls->request_tx_offset = 0;
        }

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
        {
            return;
        }
    }

    if (ls->request_tx_index == kTesterClientChunkCount)
    {
        ls->request_complete = true;
    }
}

void testerclientWatchdogTask(tunnel_t *t, line_t *l)
{
    testerclient_lstate_t *ls = lineGetState(l, t);

    discard t;

    if (! ls->response_complete)
    {
        LOGE("TesterClient: worker %u timed out after %u ms (request_complete=%d, response_index=%u)",
             (unsigned int) lineGetWID(l),
             (unsigned int) kTesterClientWatchdogMs,
             (int) ls->request_complete,
             (unsigned int) ls->response_rx_index);
        terminateProgram(1);
    }
}

void testerclientMarkWorkerComplete(tunnel_t *t, line_t *l)
{
    testerclient_tstate_t       *ts   = tunnelGetState(t);
    testerclient_worker_state_t *slot = &ts->workers[lineGetWID(l)];
    tunnel_chain_t              *tc   = tunnelGetChain(t);
    unsigned int                 done;

    if (slot->completed)
    {
        return;
    }

    slot->completed = true;
    slot->line      = NULL;

    done = (unsigned int) atomicIncRelaxed(&ts->completed_workers) + 1U;

    LOGI("TesterClient: worker %u completed integrity round-trip", (unsigned int) lineGetWID(l));

    if (done == (unsigned int) tc->workers_count)
    {
        LOGI("TesterClient: all %u worker lines completed successfully", (unsigned int) tc->workers_count);
        terminateProgram(0);
    }
}
