#pragma once

#include "wwapi.h"

/* Receive limits apply to retained, incomplete input and to nested deliveries.
 * A synchronous delivery can contain several complete protocol messages. */
enum
{
    kAuthenticationStreamChargeLimit     = 32U * 1024U * 1024U,
    kAuthenticationStreamEntryLimit      = 1024,
    kAuthenticationStreamReentryHeadroom = 2U * 1024U * 1024U
};

static inline size_t authenticationStreamCharge(const buffer_stream_t *stream)
{
    size_t charge = 0;
    c_foreach(entry, bs_doublequeue_t, stream->q)
    {
        const size_t next = sbufGetAllocationCharge(*entry.ref);
        if (next > kAuthenticationStreamChargeLimit - charge)
            return kAuthenticationStreamChargeLimit + 1U;
        charge += next;
    }
    return charge;
}

/* Copy once instead of repeatedly growing/merging a fragmented large message.
 * The caller has bounded bytes by the authentication wire/retention limits. */
static inline sbuf_t *authenticationStreamCopyExact(buffer_stream_t *stream, uint32_t bytes)
{
    sbuf_t *result = bufferpoolGetBestFit(stream->pool, bytes, bufferpoolGetSmallBufferPadding(stream->pool));
    bufferstreamMoveExactBytesTo(stream, result, bytes);
    return result;
}

static inline sbuf_t *authenticationStreamReadExact(buffer_stream_t *stream, uint32_t bytes)
{
    assert(bytes != 0 && bytes <= bufferstreamGetBufLen(stream));
    if (sbufGetLength(*bs_doublequeue_t_front(&stream->q)) >= bytes)
        return bufferstreamReadExact(stream, bytes);
    return authenticationStreamCopyExact(stream, bytes);
}

/* Nested callbacks cannot drain recursively. Compact before refusing fragmented
 * storage, while keeping the older unread suffix ahead of the new delivery.
 * On refusal the caller still owns input; on success the stream owns its bytes. */
static inline bool authenticationStreamPushNestedBounded(buffer_stream_t *stream, sbuf_t *input, size_t limit,
                                                         size_t charge_limit, size_t entry_limit)
{
    const size_t buffered = bufferstreamGetBufLen(stream);
    const size_t incoming = sbufGetLength(input);
    if (buffered > limit || incoming > limit - buffered)
        return false;

    const size_t charge = authenticationStreamCharge(stream);
    if (charge <= charge_limit && sbufGetAllocationCharge(input) <= charge_limit - charge &&
        (size_t) bs_doublequeue_t_size(&stream->q) < entry_limit)
    {
        bufferstreamPush(stream, input);
        return true;
    }

    const uint32_t bytes   = (uint32_t) (buffered + incoming);
    sbuf_t        *compact = bufferpoolGetBestFit(stream->pool, bytes, bufferpoolGetSmallBufferPadding(stream->pool));
    bufferstreamMoveExactBytesTo(stream, compact, buffered);
    sbufConcatNoCheck(compact, input);
    bufferpoolReuseBuffer(stream->pool, input);
    bufferstreamPush(stream, compact);
    assert(authenticationStreamCharge(stream) <= charge_limit);
    return true;
}

static inline bool authenticationStreamPushNested(buffer_stream_t *stream, sbuf_t *input, uint32_t max_message)
{
    return authenticationStreamPushNestedBounded(stream,
                                                 input,
                                                 (size_t) max_message + kAuthenticationStreamReentryHeadroom,
                                                 kAuthenticationStreamChargeLimit,
                                                 kAuthenticationStreamEntryLimit);
}

/* Parsing consumed every complete message, so only one incomplete message can
 * remain. Fragment count and pool tier must not turn it into an oversized one. */
static inline void authenticationStreamCompactIncompleteBounded(buffer_stream_t *stream, uint32_t max_message,
                                                                size_t charge_limit, size_t entry_limit)
{
    const size_t bytes = bufferstreamGetBufLen(stream);
    assert(bytes < max_message);
    discard max_message;
    if (bytes != 0 &&
        (authenticationStreamCharge(stream) > charge_limit || (size_t) bs_doublequeue_t_size(&stream->q) > entry_limit))
    {
        sbuf_t *compact = authenticationStreamCopyExact(stream, (uint32_t) bytes);
        bufferstreamPush(stream, compact);
    }
    assert(authenticationStreamCharge(stream) <= charge_limit);
}

static inline void authenticationStreamCompactIncomplete(buffer_stream_t *stream, uint32_t max_message)
{
    authenticationStreamCompactIncompleteBounded(
        stream, max_message, kAuthenticationStreamChargeLimit, kAuthenticationStreamEntryLimit);
}
