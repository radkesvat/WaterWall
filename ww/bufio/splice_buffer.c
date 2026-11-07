/*
 * Implements representation-level operations for kernel-backed splice buffers.
 */

#include "splice_buffer.h"

#include "buffer_pool.h"
#include "loggers/internal_logger.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>

static void spliceReadPipe(int fd, uint8_t *dest, size_t bytes, const char *caller)
{
    size_t consumed = 0;
    while (consumed < bytes)
    {
        const ssize_t result = read(fd, dest + consumed, bytes - consumed);
        if (LIKELY(result > 0))
        {
            consumed += (size_t) result;
            continue;
        }

        const int read_error = result < 0 ? errno : 0;
        if (UNLIKELY(result < 0 && read_error == EINTR))
        {
            continue;
        }
        /* Claimed splice bytes must already exist in the private pipe. */
        LOGF("%s: incomplete read from pipe (requested=%zu, consumed=%zu, result=%lld, errno=%d)",
             caller,
             bytes,
             consumed,
             (long long) result,
             read_error);
        abortProgramNow(1);
    }
}
#endif

sbuf_t *sbufEnsureOrdinary(buffer_pool_t *pool, sbuf_t *buf)
{
    sbuf_t *ordinary = sbufTryEnsureOrdinary(pool, buf);
    if (UNLIKELY(ordinary == NULL))
    {
        LOGF("sbufEnsureOrdinary: payload cannot be represented as ordinary storage");
        abortProgramNow(1);
    }
    return ordinary;
}

sbuf_t *sbufTryEnsureOrdinary(buffer_pool_t *pool, sbuf_t *buf)
{
    assert(pool != NULL && buf != NULL);
    if (! sbufIsSplice(buf))
    {
        return buf;
    }

    const size_t length   = sbufGetLength(buf);
    sbuf_t      *ordinary = bufferpoolTryGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    if (ordinary == NULL)
    {
        return NULL;
    }
    sbufSpliceReadToBuffer(buf, ordinary, length);
    bufferpoolReuseBuffer(pool, buf);
    return ordinary;
}

sbuf_t *sbufEnsureLeftCapacity(buffer_pool_t *pool, sbuf_t *buf, uint16_t need)
{
    assert(pool != NULL && buf != NULL);
    if (sbufGetHeadroom(buf) >= need)
        return buf;

    const size_t   length  = sbufGetLength(buf);
    const uint16_t padding = max(bufferpoolGetLargeBufferPadding(pool), need);
#ifndef NDEBUG
    buffer_pool_fit_t fit;
    assert(bufferpoolQueryBestFit(pool, length, padding, &fit));
#endif
    sbuf_t *wrapped = sbufIsSplice(buf) ? bufferpoolGetSpliceBuffer(pool) : NULL;
    if (wrapped != NULL && sbufGetHeadroom(wrapped) < padding)
    {
        bufferpoolReuseBuffer(pool, wrapped);
        wrapped = NULL;
    }
    wrapped = sbufMoveRangeTo(pool, buf, wrapped, length, length, padding);
    bufferpoolReuseBuffer(pool, buf);
    return wrapped;
}

sbuf_t *sbufSpliceMaterializeToBuffer(sbuf_t *buf, sbuf_t *dest, buffer_pool_t *pool)
{
    if (UNLIKELY(buf == NULL || ! sbufIsSplice(buf)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: requires kSbufFlagSplice");
        abortProgramNow(1);
    }
    assert(dest != NULL && pool != NULL);
    if (UNLIKELY(sbufIsSplice(dest)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: destination must be an ordinary buffer");
        abortProgramNow(1);
    }
#if WW_HAVE_SPLICE
    const size_t source_headroom = sbufGetHeadroom(buf);
    const size_t prefix_bytes    = sbufGetResidentPrefixLength(buf);
    const size_t body_bytes      = buf->len - prefix_bytes;

    if (UNLIKELY(source_headroom > sbufGetTotalCapacity(dest)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: destination too small for left headroom "
             "(capacity=%zu, left headroom=%zu)",
             sbufGetTotalCapacity(dest),
             source_headroom);
        abortProgramNow(1);
    }
    dest->data = dest->head + source_headroom;
    if (UNLIKELY(sbufGetLength(buf) > sbufGetMaximumWriteableSize(dest)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: destination too small "
             "(capacity=%zu, left headroom=%zu, payload=%zu)",
             sbufGetTotalCapacity(dest),
             source_headroom,
             sbufGetLength(buf));
        abortProgramNow(1);
    }

    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    if (UNLIKELY(body_bytes != 0 && metadata.pipefd[0] < 0))
    {
        LOGF("sbufSpliceMaterializeToBuffer: descriptor pipe must already be initialized");
        abortProgramNow(1);
    }

    sbufByteCopy(dest->data, sbufGetRawPtr(buf), prefix_bytes);
    spliceReadPipe(metadata.pipefd[0], dest->head + buf->initial_headroom, body_bytes, __func__);

    sbufSetLength(dest, buf->len);
    dest->flags = buf->flags & (uint16_t) ~(kSbufFlagSplice | kSbufFlagSplicePooled | kSbufFlagRecalculateChecksum);
    sbufSetLength(buf, 0);
    bufferpoolReuseBuffer(pool, buf);
    return dest;
#else
    discard dest;
    discard pool;
    LOGF("sbufSpliceMaterializeToBuffer: splice is unsupported on this build");
    abortProgramNow(1);
#endif
}

sbuf_t *sbufSpliceReadToBuffer(sbuf_t *buf, sbuf_t *dest, size_t bytes)
{
    if (UNLIKELY(buf == NULL || ! sbufIsSplice(buf)))
    {
        LOGF("sbufSpliceReadToBuffer: requires kSbufFlagSplice");
        abortProgramNow(1);
    }
    if (UNLIKELY(dest == NULL || sbufIsSplice(dest)))
    {
        LOGF("sbufSpliceReadToBuffer: destination must be an ordinary buffer");
        abortProgramNow(1);
    }
#if WW_HAVE_SPLICE
    const size_t source_length   = sbufGetLength(buf);
    const size_t source_headroom = sbufGetHeadroom(buf);
    if (UNLIKELY(source_headroom > sbufGetInitialHeadroom(buf) || source_headroom > sbufGetTotalCapacity(buf) ||
                 source_length > sbufGetMaximumWriteableSize(buf)))
    {
        LOGF("sbufSpliceReadToBuffer: invalid source cursor or logical capacity");
        abortProgramNow(1);
    }
    const size_t prefix_bytes = (size_t) sbufGetInitialHeadroom(buf) - source_headroom;
    if (UNLIKELY(source_length < prefix_bytes || bytes > source_length))
    {
        LOGF("sbufSpliceReadToBuffer: requested bytes or prefix exceed source length "
             "(requested=%zu, prefix=%zu, length=%zu)",
             bytes,
             prefix_bytes,
             source_length);
        abortProgramNow(1);
    }

    const size_t dest_length   = sbufGetLength(dest);
    const size_t dest_headroom = sbufGetHeadroom(dest);
    if (UNLIKELY(dest_headroom > sbufGetTotalCapacity(dest) || dest_length > sbufGetMaximumWriteableSize(dest) ||
                 bytes > sbufGetMaximumWriteableSize(dest) - dest_length))
    {
        LOGF("sbufSpliceReadToBuffer: destination has insufficient append space "
             "(requested=%zu, length=%zu, cursor=%zu, capacity=%zu)",
             bytes,
             dest_length,
             dest_headroom,
             sbufGetTotalCapacity(dest));
        abortProgramNow(1);
    }
    if (UNLIKELY(bytes == 0))
    {
        return dest;
    }

    const size_t copied_prefix = min(bytes, prefix_bytes);
    const size_t body_bytes    = bytes - copied_prefix;
    uint8_t     *target        = sbufGetMutablePtr(dest) + dest_length;
    if (body_bytes != 0)
    {
        splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
        if (UNLIKELY(metadata.pipefd[0] < 0))
        {
            LOGF("sbufSpliceReadToBuffer: descriptor pipe must already be initialized");
            abortProgramNow(1);
        }
        spliceReadPipe(metadata.pipefd[0], target + copied_prefix, body_bytes, __func__);
    }
    sbufByteCopy(target, sbufGetRawPtr(buf), copied_prefix);
    sbufSetLength(dest, dest_length + bytes);

    sbufShiftRight(buf, copied_prefix);
    sbufSpliceConsumeBody(buf, body_bytes);
    return dest;
#else
    discard bytes;
    LOGF("sbufSpliceReadToBuffer: splice is unsupported on this build");
    abortProgramNow(1);
#endif
}

/* Progress is committed after each syscall. EAGAIN can mean destination slot
 * exhaustion even when nominal byte capacity remains; ordinary fallback then
 * validates the still-claimed source bytes through the exact read helper. */
static size_t spliceAppendAvailable(sbuf_t *source, sbuf_t *dest, size_t bytes)
{
#if WW_HAVE_SPLICE
    const splice_buffer_metadata_t target = sbufSpliceMetadata(dest);
    size_t                         moved  = 0;
    while (moved < bytes)
    {
        const size_t resident = sbufGetResidentPrefixLength(source);
        ssize_t      result;
        if (resident != 0)
            result = write(target.pipefd[1], sbufGetRawPtr(source), min(resident, bytes - moved));
        else
        {
            const splice_buffer_metadata_t origin = sbufSpliceMetadata(source);
            result = splice(origin.pipefd[0], NULL, target.pipefd[1], NULL, bytes - moved, SPLICE_F_NONBLOCK);
        }
        if (result > 0)
        {
            const size_t count = (size_t) result;
            if (resident != 0)
                sbufShiftRight(source, count);
            else
            {
                sbufSpliceConsumeBody(source, count);
            }
            moved += count;
            dest->len += count;
            dest->capacity = dest->initial_headroom + dest->len;
            continue;
        }
        if (UNLIKELY(result < 0 && errno == EINTR))
            continue;
        if (result < 0 && (errno == EAGAIN || errno == EINVAL || errno == ENOMEM))
            break;
        LOGF("splice range: invalid owned pipe (result=%lld errno=%d)", (long long) result, errno);
        abortProgramNow(1);
    }
    return moved;
#else
    discard source;
    discard dest;
    discard bytes;
    return 0;
#endif
}

sbuf_t *sbufMoveRangeTo(buffer_pool_t *pool, sbuf_t *source, sbuf_t *dest, size_t bytes, size_t final_size,
                        uint16_t padding)
{
    assert(bytes <= sbufGetLength(source) && bytes <= final_size);
    assert(dest == NULL || sbufGetLength(dest) <= final_size - bytes);
    size_t moved = 0;
    if (dest != NULL && sbufIsSplice(dest))
    {
        assert(dest->data == dest->head + dest->initial_headroom);
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(dest);
        if (metadata.pipefd[0] >= 0 && metadata.pipefd[1] >= 0)
            moved = spliceAppendAvailable(source, dest, bytes);
        if (moved == bytes)
            return dest;
    }
    if (dest == NULL || sbufIsSplice(dest))
    {
        sbuf_t *ordinary = bufferpoolGetBestFit(pool, final_size, padding);
        if (dest != NULL)
        {
            if (sbufGetLength(dest) != 0)
                sbufSpliceReadToBuffer(dest, ordinary, sbufGetLength(dest));
            bufferpoolReuseBuffer(pool, dest);
        }
        dest = ordinary;
    }
    if (sbufIsSplice(source))
        sbufSpliceReadToBuffer(source, dest, bytes - moved);
    else
        sbufMoveTo(dest, source, bytes - moved);
    return dest;
}

void sbufReadRangeToMemory(sbuf_t *source, void *destination, size_t bytes)
{
    assert(bytes <= sbufGetLength(source));
    const size_t prefix = min(bytes, sbufGetResidentPrefixLength(source));
    sbufByteCopy(destination, sbufGetRawPtr(source), prefix);
    sbufShiftRight(source, prefix);
    if (bytes != prefix)
    {
#if WW_HAVE_SPLICE
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(source);
        spliceReadPipe(metadata.pipefd[0], (uint8_t *) destination + prefix, bytes - prefix, __func__);
        sbufSpliceConsumeBody(source, bytes - prefix);
#else
        LOGF("splice range: pipe source on unsupported build");
        abortProgramNow(1);
#endif
    }
}
