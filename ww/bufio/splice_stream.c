#include "splice_stream.h"
#include "loggers/internal_logger.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

splice_stream_t *splicestreamCreate(buffer_pool_t *pool, uint32_t header_size)
{
    if (UNLIKELY((uint64_t) header_size + sizeof(splice_stream_t) > SIZE_MAX))
        return NULL;
    splice_stream_t *s = memoryAllocateZero(sizeof(*s) + (size_t) header_size);
    if (UNLIKELY(s == NULL))
        return NULL;
    s->pool        = pool;
    s->header_size = header_size;
    s->discard_fd  = -1;
    bufferqueueInitEmpty(&s->pending);
    return s;
}

static sbuf_t *streamHead(splice_stream_t *s)
{
    if (s->head == NULL)
    {
        s->head = bufferqueuePopFront(&s->pending);
        if (s->head != NULL)
            s->head_charge = sbufGetQueueCharge(s->head);
    }
    return s->head;
}

static sbuf_t *streamDetachHead(splice_stream_t *s)
{
    sbuf_t *head = s->head;
    s->charge -= s->head_charge;
    s->head        = NULL;
    s->head_charge = 0;
    return head;
}

static void streamRecycleEmptyHead(splice_stream_t *s)
{
    const size_t charge = sbufGetQueueCharge(s->head);
    assert(charge <= s->head_charge);
    s->charge -= s->head_charge - charge;
    s->head_charge = charge;
    if (sbufGetLength(s->head) == 0)
        bufferpoolReuseBuffer(s->pool, streamDetachHead(s));
}

static void streamFillHeader(splice_stream_t *s)
{
    while (s->header_filled < s->header_size && streamHead(s) != NULL)
    {
        sbuf_t        *head  = s->head;
        const uint32_t count = min(s->header_size - s->header_filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, s->header + s->header_filled, count);
        s->header_filled += count;
        streamRecycleEmptyHead(s);
    }
}

bool splicestreamPush(splice_stream_t *s, sbuf_t *input)
{
    const uint32_t length = sbufGetLength(input);
    if (length == 0)
    {
        bufferpoolReuseBuffer(s->pool, input);
        return true;
    }
    size_t cost;
    if (UNLIKELY(! sbufTryGetQueueCharge(input, &cost) || s->charge > SIZE_MAX - cost || s->total > SIZE_MAX - length ||
                 ! bufferqueueReserveExtra(&s->pending, 1)))
    {
        bufferpoolReuseBuffer(s->pool, input);
        return false;
    }
    /* Append only into existing ordinary tail space, without moving older bytes
     * or changing its allocation charge. */
    sbuf_t *tail = bufferqueueGetBufCount(&s->pending) != 0 ? *ww_sbuffer_queue_t_back(&s->pending.q) : s->head;
    if (tail != NULL && ! sbufIsSplice(tail) && ! sbufIsSplice(input) && length <= sbufGetTailCapacity(tail))
    {
        sbufMoveTo(tail, input, length);
        if (tail != s->head)
            s->pending.total_len += length;
        bufferpoolReuseBuffer(s->pool, input);
    }
    else
    {
        if (s->head == NULL && bufferqueueGetBufCount(&s->pending) == 0)
        {
            s->head        = input;
            s->head_charge = cost;
        }
        else
            input = bufferqueuePushBack(&s->pending, input); // Reserved above, cannot fail.
        assert(sbufGetQueueCharge(input) == cost);
        s->charge += cost;
    }
    s->total += length;
    streamFillHeader(s);
    return true;
}

const uint8_t *splicestreamPeekHeader(const splice_stream_t *s)
{
    return s->header_filled == s->header_size ? s->header : NULL;
}

size_t splicestreamLength(const splice_stream_t *s)
{
    return s->total;
}

size_t splicestreamBodyBytes(const splice_stream_t *s)
{
    return s->header_filled == s->header_size ? s->total - s->header_size : 0;
}

size_t splicestreamCharge(const splice_stream_t *s)
{
    return s->charge;
}

bool splicestreamCompact(splice_stream_t *s)
{
    const size_t      bytes = s->total - s->header_filled;
    buffer_pool_fit_t fit;
    if (bytes == 0 || ! bufferpoolQueryBestFit(s->pool, bytes, bufferpoolGetLargeBufferPadding(s->pool), &fit) ||
        fit.allocation_charge >= s->charge)
        return false;

    // Reserve all destination storage before consuming any source. The active
    // head stores the result, so no FIFO allocation or callback is needed.
    sbuf_t *combined = bufferpoolGetBestFit(s->pool, (uint32_t) bytes, fit.left_padding);
    while (streamHead(s) != NULL)
    {
        sbuf_t *source = streamDetachHead(s);
        if (sbufIsSplice(source))
            sbufSpliceReadToBuffer(source, combined, sbufGetLength(source));
        else
            sbufMoveTo(combined, source, sbufGetLength(source));
        bufferpoolReuseBuffer(s->pool, source);
    }
    assert(s->charge == 0 && sbufGetLength(combined) == bytes);
    s->head        = combined;
    s->head_charge = sbufGetQueueCharge(combined);
    s->charge      = s->head_charge;
    assert(s->charge == fit.allocation_charge);
    return true;
}

static inline void streamAssertFrame(const splice_stream_t *s, const sbuf_t *destination, uint32_t bytes)
{
    assert(s->header_filled == s->header_size);
    assert(bytes <= splicestreamBodyBytes(s));
    assert(destination == NULL || sbufGetLength(destination) == 0);
    discard s;
    discard destination;
    discard bytes;
}

static void streamFinishFrame(splice_stream_t *s, uint32_t bytes)
{
    s->total -= (size_t) s->header_size + bytes;
    s->header_filled = 0;
    streamFillHeader(s);
}

static sbuf_t *streamMoveBody(splice_stream_t *s, sbuf_t *dest, uint32_t bytes)
{
    const uint16_t padding   = bufferpoolGetLargeBufferPadding(s->pool);
    uint32_t       remaining = bytes;
    while (remaining != 0)
    {
        sbuf_t        *source = streamHead(s);
        const uint32_t count  = min(remaining, sbufGetLength(source));
        dest                  = sbufMoveRangeTo(s->pool, source, dest, count, bytes, padding);
        remaining -= count;
        streamRecycleEmptyHead(s);
    }
    streamFinishFrame(s, bytes);
    return dest;
}

sbuf_t *splicestreamMoveFrame(splice_stream_t *s, sbuf_t *dest, uint32_t bytes)
{
    streamAssertFrame(s, dest, bytes);
    const uint16_t padding    = bufferpoolGetLargeBufferPadding(s->pool);
    sbuf_t        *head       = streamHead(s);
    const uint32_t head_bytes = head == NULL ? 0 : min(bytes, sbufGetLength(head));
    bool           has_pipe   = head != NULL && head_bytes > sbufGetResidentPrefixLength(head);
    if (bytes != 0 && head != NULL && sbufGetLength(head) == bytes && sbufGetLeftCapacity(head) >= padding &&
        (! sbufIsSplice(head) || (has_pipe && dest != NULL && sbufIsSplice(dest))))
    {
        if (dest != NULL)
            bufferpoolReuseBuffer(s->pool, dest);
        dest = streamDetachHead(s);
        streamFinishFrame(s, bytes);
        return dest;
    }
    uint32_t remaining = bytes - head_bytes;
    c_foreach(i, ww_sbuffer_queue_t, s->pending.q)
    {
        if (remaining == 0 || has_pipe)
            break;
        const uint32_t count = min(remaining, sbufGetLength(*i.ref));
        has_pipe             = count > sbufGetResidentPrefixLength(*i.ref);
        remaining -= count;
    }
    if (dest != NULL && sbufIsSplice(dest))
    {
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(dest);
        if (! has_pipe || bytes == 0 || sbufGetLeftCapacity(dest) < padding || metadata.pipefd[1] < 0)
        {
            bufferpoolReuseBuffer(s->pool, dest);
            dest = NULL;
        }
    }
    if (dest == NULL)
        dest = bufferpoolGetBestFit(s->pool, bytes, padding);
    return streamMoveBody(s, dest, bytes);
}

void splicestreamMoveFrameToOrdinary(splice_stream_t *s, sbuf_t *dest, uint32_t bytes)
{
    streamAssertFrame(s, dest, bytes);
    if (UNLIKELY(sbufIsSplice(dest) || bytes > sbufGetMaximumWriteableSize(dest)))
    {
        LOGF("SpliceStream: insufficient ordinary destination");
        abortProgramNow(1);
    }
    discard streamMoveBody(s, dest, bytes);
}

static void streamDiscardPipe(splice_stream_t *s, sbuf_t *source, uint32_t bytes)
{
#if WW_HAVE_SPLICE
    if (s->discard_fd == -1)
    {
        do
            s->discard_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        while (s->discard_fd < 0 && errno == EINTR);
        if (s->discard_fd < 0)
            s->discard_fd = -2;
    }
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(source);
    while (bytes != 0 && s->discard_fd >= 0)
    {
        const ssize_t result = splice(metadata.pipefd[0], NULL, s->discard_fd, NULL, bytes, SPLICE_F_NONBLOCK);
        if (result > 0)
        {
            sbufSpliceConsumeBody(source, (uint32_t) result);
            bytes -= (uint32_t) result;
            continue;
        }
        const int error = result < 0 ? errno : 0;
        if (result < 0 && error == EINTR)
            continue;
        if (result < 0 && (error == EINVAL || error == ENOSYS || error == EOPNOTSUPP || error == EPERM))
        {
            close(s->discard_fd);
            s->discard_fd = -2;
            break;
        }
        /* A read fallback handles temporary splice refusal, and still fails
         * fatally if the exclusively owned pipe lacks any claimed bytes. */
        if (result < 0 && (error == EAGAIN || error == ENOMEM))
            break;
        LOGF("SpliceStream: invalid discard pipe (result=%lld errno=%d)", (long long) result, error);
        abortProgramNow(1);
    }
    if (bytes != 0)
    {
        uint8_t scratch[4096];
        do
        {
            const uint32_t count = min(bytes, (uint32_t) sizeof(scratch));
            sbufReadRangeToMemory(source, scratch, count);
            bytes -= count;
        } while (bytes != 0);
    }
#else
    discard s;
    discard source;
    discard bytes;
    LOGF("SpliceStream: pipe source on unsupported build");
    abortProgramNow(1);
#endif
}

void splicestreamDiscardFrame(splice_stream_t *s, uint32_t bytes)
{
    streamAssertFrame(s, NULL, bytes);
    uint32_t remaining = bytes;
    while (remaining != 0)
    {
        sbuf_t        *source = streamHead(s);
        const uint32_t count  = min(remaining, sbufGetLength(source));
        const uint32_t prefix = min(count, sbufGetResidentPrefixLength(source));
        sbufShiftRight(source, prefix);
        if (count != prefix)
            streamDiscardPipe(s, source, count - prefix);
        remaining -= count;
        streamRecycleEmptyHead(s);
    }
    streamFinishFrame(s, bytes);
}

void splicestreamDestroy(splice_stream_t *s)
{
    if (s == NULL)
        return;
    while (streamHead(s) != NULL)
        bufferpoolReuseBuffer(s->pool, streamDetachHead(s));
    bufferqueueDestroy(&s->pending);
    assert(s->charge == 0);
#if WW_HAVE_SPLICE
    if (s->discard_fd >= 0)
        close(s->discard_fd);
#endif
    memoryFree(s);
}
