#include "HttpCommon/websocket_decoder.h"

static bool httpWebSocketOpcodeIsSupported(uint8_t opcode)
{
    return opcode == 0 || opcode == 1 || opcode == 2 || opcode == 8 || opcode == 9 || opcode == 10;
}

http_websocket_result_t httpWebSocketDecoderStep(http_websocket_decoder_t *state, buffer_stream_t *stream,
                                                 bool expect_masked, sbuf_t **out)
{
    assert(state != NULL && stream != NULL && stream->pool != NULL && out != NULL);
    *out = NULL;

    for (;;)
    {
        size_t available = bufferstreamGetBufLen(stream);
        if (! state->active)
        {
            if (available < 2)
                return kHttpWebSocketNeedMore;

            uint8_t head[14];
            bufferstreamViewBytesAt(stream, 0, head, 2);
            const bool    fin    = (head[0] & 0x80U) != 0;
            const uint8_t opcode = head[0] & 0x0FU;
            const bool    masked = (head[1] & 0x80U) != 0;
            uint64_t      length = head[1] & 0x7FU;
            size_t        header = 2;

            if (masked != expect_masked || ! httpWebSocketOpcodeIsSupported(opcode) || ((opcode & 0x08U) != 0 && ! fin))
                return kHttpWebSocketError;

            if (length == 126)
            {
                if (available < 4)
                    return kHttpWebSocketNeedMore;
                bufferstreamViewBytesAt(stream, 2, head + 2, 2);
                length = ((uint64_t) head[2] << 8) | head[3];
                header = 4;
            }
            else if (length == 127)
            {
                if (available < 10)
                    return kHttpWebSocketNeedMore;
                bufferstreamViewBytesAt(stream, 2, head + 2, 8);
                length = 0;
                for (size_t i = 2; i < 10; ++i)
                    length = (length << 8) | head[i];
                header = 10;
            }

            if (length > UINT32_MAX || ((opcode & 0x08U) != 0 && length > 125))
                return kHttpWebSocketError;
            if (available < header + (masked ? 4U : 0U))
                return kHttpWebSocketNeedMore;

            *state = (http_websocket_decoder_t) {
                .remaining = (uint32_t) length, .opcode = opcode, .active = true, .masked = masked};
            if (masked)
            {
                bufferstreamViewBytesAt(stream, header, state->mask_key, 4);
                header += 4;
            }
            sbuf_t *framing = bufferstreamReadExact(stream, header);
            bufferpoolReuseBuffer(stream->pool, framing);
            available -= header;
        }

        const bool control = (state->opcode & 0x08U) != 0;
        if (control && available < state->remaining)
            return kHttpWebSocketNeedMore;
        if (! control && state->remaining != 0 && available == 0)
            return kHttpWebSocketNeedMore;

        const uint32_t take =
            control ? state->remaining
                    : (uint32_t) min((size_t) min(state->remaining, kHttpWebSocketBodySliceBytes), available);
        if (take > 0)
        {
            *out = bufferstreamReadExact(stream, take);
            if (state->masked)
            {
                uint8_t *data = sbufGetMutablePtr(*out);
                for (uint32_t i = 0; i < take; ++i)
                    data[i] ^= state->mask_key[(state->mask_offset + i) & 3U];
                state->mask_offset = (uint8_t) ((state->mask_offset + take) & 3U);
            }
            state->remaining -= take;
        }

        const uint8_t opcode = state->opcode;
        if (state->remaining == 0)
            *state = (http_websocket_decoder_t) {0};

        if (opcode == 8)
            return kHttpWebSocketClose;
        if (opcode == 9)
            return kHttpWebSocketPing;
        if (opcode == 10)
            return kHttpWebSocketPong;
        if (take > 0)
            return kHttpWebSocketData;
        /* Empty data frames carry no application bytes. Continue to the next
         * header so they cannot leave already-buffered following frames idle. */
    }
}
