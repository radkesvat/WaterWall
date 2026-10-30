#include "HttpCommon/chunk_decoder.h"

static int httpChunkHexDigit(uint8_t byte)
{
    if (byte >= '0' && byte <= '9')
        return byte - '0';
    if (byte >= 'a' && byte <= 'f')
        return byte - 'a' + 10;
    if (byte >= 'A' && byte <= 'F')
        return byte - 'A' + 10;
    return -1;
}

static bool httpChunkSizeByte(http_chunk_decoder_t *decoder, uint8_t byte)
{
    if (++decoder->metadata_bytes > kHttpChunkMaxSizeLineBytes)
        return false;

    if (decoder->saw_cr)
    {
        if (byte != '\n' || ! decoder->size_digits)
            return false;
        decoder->phase          = decoder->remaining == 0 ? kHttpChunkTrailers : kHttpChunkBody;
        decoder->metadata_bytes = 0;
        decoder->saw_cr         = false;
        return true;
    }

    if (byte == '\r')
        decoder->saw_cr = true;
    else if (decoder->size_extension)
    {
        if ((byte < 0x20 && byte != '\t') || byte == 0x7f)
            return false;
    }
    else
    {
        const int digit = httpChunkHexDigit(byte);
        if (digit >= 0 && ! decoder->size_padding)
        {
            if (decoder->remaining > ((uint64_t) INT64_MAX - (unsigned) digit) / 16)
                return false;
            decoder->remaining   = decoder->remaining * 16 + (unsigned) digit;
            decoder->size_digits = true;
        }
        else if (decoder->size_digits && byte == ';')
            decoder->size_extension = true;
        else if (decoder->size_digits && (byte == ' ' || byte == '\t'))
            decoder->size_padding = true;
        else
            return false;
    }

    /* A complete CRLF must fit, not just the prefix received so far. */
    return decoder->metadata_bytes < kHttpChunkMaxSizeLineBytes;
}

static bool httpChunkTrailerByte(http_chunk_decoder_t *decoder, uint8_t byte)
{
    if (++decoder->metadata_bytes > kHttpChunkMaxTrailerBytes)
        return false;
    ++decoder->line_bytes;
    if (decoder->saw_cr && byte == '\n')
    {
        if (decoder->line_bytes == 2)
        {
            decoder->phase = kHttpChunkComplete;
            return true;
        }
        decoder->line_bytes = 0;
    }
    decoder->saw_cr = byte == '\r';
    return decoder->metadata_bytes < kHttpChunkMaxTrailerBytes;
}

static bool httpChunkTailByte(http_chunk_decoder_t *decoder, uint8_t byte)
{
    if (! decoder->saw_cr)
    {
        if (byte != '\r')
            return false;
        decoder->saw_cr = true;
        return true;
    }
    if (byte != '\n')
        return false;
    *decoder = (http_chunk_decoder_t) {0};
    return true;
}

static void httpChunkConsumeMetadata(http_chunk_decoder_t *decoder, buffer_stream_t *stream)
{
    uint8_t      bytes[256];
    const size_t count = min(bufferstreamGetBufLen(stream), sizeof(bytes));
    assert(count != 0);
    bufferstreamViewBytesAt(stream, 0, bytes, count);

    const http_chunk_phase_t phase    = decoder->phase;
    size_t                   consumed = 0;
    while (consumed < count && decoder->phase == phase)
    {
        const uint8_t byte = bytes[consumed++];
        bool          valid;
        switch (phase)
        {
        case kHttpChunkSize:
            valid = httpChunkSizeByte(decoder, byte);
            break;
        case kHttpChunkTail:
            valid = httpChunkTailByte(decoder, byte);
            break;
        case kHttpChunkTrailers:
            valid = httpChunkTrailerByte(decoder, byte);
            break;
        default:
            assert(false);
            valid = false;
            break;
        }
        if (! valid)
            decoder->phase = kHttpChunkInvalid;
    }
    sbuf_t *framing = bufferstreamReadExact(stream, consumed);
    bufferpoolReuseBuffer(stream->pool, framing);
}

http_chunk_result_t httpChunkDecoderStep(http_chunk_decoder_t *decoder, buffer_stream_t *stream, sbuf_t **out)
{
    assert(decoder != NULL && stream != NULL && out != NULL);
    *out = NULL;
    while (true)
    {
        if (decoder->phase == kHttpChunkComplete)
            return kHttpChunkDone;
        if (decoder->phase == kHttpChunkInvalid)
            return kHttpChunkError;

        const size_t available = bufferstreamGetBufLen(stream);
        if (available == 0)
            return kHttpChunkNeedMore;
        if (decoder->phase == kHttpChunkBody)
        {
            const size_t count =
                (size_t) min(decoder->remaining, (uint64_t) min(available, (size_t) kHttpChunkMaxOutputBytes));
            assert(count != 0);
            decoder->remaining -= count;
            if (decoder->remaining == 0)
                decoder->phase = kHttpChunkTail;
            *out = bufferstreamReadExact(stream, count);
            return kHttpChunkData;
        }
        httpChunkConsumeMetadata(decoder, stream);
    }
}
