/*
 * Implements representation-level operations for kernel-backed splice buffers.
 */

#include "splice_buffer.h"

#include "buffer_pool.h"
#include "loggers/internal_logger.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>

static void spliceReadPipe(int fd, uint8_t *dest, uint32_t bytes, const char *caller)
{
    uint32_t consumed = 0;
    while (consumed < bytes)
    {
        const ssize_t result = read(fd, dest + consumed, bytes - consumed);
        if (LIKELY(result > 0))
        {
            consumed += (uint32_t) result;
            continue;
        }

        const int read_error = result < 0 ? errno : 0;
        if (UNLIKELY(result < 0 && read_error == EINTR))
        {
            continue;
        }
        /* Claimed splice bytes must already exist in the private pipe. */
        LOGF("%s: incomplete read from pipe (requested=%u, consumed=%u, result=%lld, errno=%d)",
             caller,
             (unsigned int) bytes,
             (unsigned int) consumed,
             (long long) result,
             read_error);
        abortProgramNow(1);
    }
}
#endif

sbuf_t *sbufSpliceMaterializeToBuffer(sbuf_t *buf, sbuf_t *dest, buffer_pool_t *pool)
{
    if (UNLIKELY(buf == NULL || ! sbufIsSplice(buf)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: requires kSbufFlagSplice");
        abortProgramNow(1);
    }
    assert(sbufGetLifetime(buf) == NULL && "Splice buffers must not carry lifetime metadata");
    assert(dest != NULL && pool != NULL);
    if (UNLIKELY(sbufIsSplice(dest)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: destination must be an ordinary buffer");
        abortProgramNow(1);
    }
#if WW_HAVE_SPLICE
    const uint32_t prefix_bytes = sbufGetResidentPrefixLength(buf);
    const uint32_t body_bytes   = buf->len - prefix_bytes;

    if (UNLIKELY(buf->curpos > sbufGetTotalCapacity(dest)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: destination too small for left headroom "
             "(capacity=%u, left headroom=%u)",
             (unsigned int) sbufGetTotalCapacity(dest),
             (unsigned int) buf->curpos);
        abortProgramNow(1);
    }
    dest->curpos = buf->curpos;
    if (UNLIKELY(sbufGetLength(buf) > sbufGetMaximumWriteableSize(dest)))
    {
        LOGF("sbufSpliceMaterializeToBuffer: destination too small "
             "(capacity=%u, left headroom=%u, payload=%u)",
             (unsigned int) sbufGetTotalCapacity(dest),
             (unsigned int) buf->curpos,
             (unsigned int) sbufGetLength(buf));
        abortProgramNow(1);
    }

    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    if (UNLIKELY(body_bytes != 0 && metadata.pipefd[0] < 0))
    {
        LOGF("sbufSpliceMaterializeToBuffer: descriptor pipe must already be initialized");
        abortProgramNow(1);
    }

    sbufByteCopy(dest->buf + buf->curpos, sbufGetRawPtr(buf), prefix_bytes);
    spliceReadPipe(metadata.pipefd[0], dest->buf + buf->l_pad, body_bytes, __func__);

    sbufSetLength(dest, buf->len);
    dest->flags = buf->flags & (uint16_t) ~kSbufFlagSplice;
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

sbuf_t *sbufSpliceReadToBuffer(sbuf_t *buf, sbuf_t *dest, uint32_t bytes)
{
    if (UNLIKELY(buf == NULL || ! sbufIsSplice(buf)))
    {
        LOGF("sbufSpliceReadToBuffer: requires kSbufFlagSplice");
        abortProgramNow(1);
    }
    assert(sbufGetLifetime(buf) == NULL && "Splice buffers must not carry lifetime metadata");
    if (UNLIKELY(dest == NULL || sbufIsSplice(dest)))
    {
        LOGF("sbufSpliceReadToBuffer: destination must be an ordinary buffer");
        abortProgramNow(1);
    }
#if WW_HAVE_SPLICE
    const uint32_t source_length = sbufGetLength(buf);
    if (UNLIKELY(buf->curpos > sbufGetLeftPadding(buf) || buf->curpos > sbufGetTotalCapacity(buf) ||
                 source_length > sbufGetMaximumWriteableSize(buf)))
    {
        LOGF("sbufSpliceReadToBuffer: invalid source cursor or logical capacity");
        abortProgramNow(1);
    }
    const uint32_t prefix_bytes = (uint32_t) sbufGetLeftPadding(buf) - buf->curpos;
    if (UNLIKELY(source_length < prefix_bytes || bytes > source_length))
    {
        LOGF("sbufSpliceReadToBuffer: requested bytes or prefix exceed source length "
             "(requested=%u, prefix=%u, length=%u)",
             (unsigned int) bytes,
             (unsigned int) prefix_bytes,
             (unsigned int) source_length);
        abortProgramNow(1);
    }

    const uint32_t dest_length = sbufGetLength(dest);
    if (UNLIKELY(dest->curpos > sbufGetTotalCapacity(dest) || dest_length > sbufGetMaximumWriteableSize(dest) ||
                 bytes > sbufGetMaximumWriteableSize(dest) - dest_length))
    {
        LOGF("sbufSpliceReadToBuffer: destination has insufficient append space "
             "(requested=%u, length=%u, cursor=%u, capacity=%u)",
             (unsigned int) bytes,
             (unsigned int) dest_length,
             (unsigned int) dest->curpos,
             (unsigned int) sbufGetTotalCapacity(dest));
        abortProgramNow(1);
    }
    if (UNLIKELY(bytes == 0))
    {
        return dest;
    }

    const uint32_t copied_prefix = min(bytes, prefix_bytes);
    const uint32_t body_bytes    = bytes - copied_prefix;
    uint8_t       *target        = sbufGetMutablePtr(dest) + dest_length;
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
static uint32_t spliceAppendAvailable(sbuf_t *source, sbuf_t *dest, uint32_t bytes)
{
#if WW_HAVE_SPLICE
    const splice_buffer_metadata_t target = sbufSpliceMetadata(dest);
    uint32_t                       moved  = 0;
    while (moved < bytes)
    {
        const uint32_t resident = sbufGetResidentPrefixLength(source);
        ssize_t        result;
        if (resident != 0)
            result = write(target.pipefd[1], sbufGetRawPtr(source), min(resident, bytes - moved));
        else
        {
            const splice_buffer_metadata_t origin = sbufSpliceMetadata(source);
            result = splice(origin.pipefd[0], NULL, target.pipefd[1], NULL, bytes - moved, SPLICE_F_NONBLOCK);
        }
        if (result > 0)
        {
            const uint32_t count = (uint32_t) result;
            if (resident != 0)
                sbufShiftRight(source, count);
            else
            {
                sbufSpliceConsumeBody(source, count);
            }
            moved += count;
            dest->len += count;
            dest->capacity = dest->l_pad + dest->len;
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

sbuf_t *sbufMoveRangeTo(buffer_pool_t *pool, sbuf_t *source, sbuf_t *dest, uint32_t bytes, uint32_t final_size,
                        uint16_t padding)
{
    assert(bytes <= sbufGetLength(source) && bytes <= final_size);
    assert(dest == NULL || sbufGetLength(dest) <= final_size - bytes);
    uint32_t moved = 0;
    if (dest != NULL && sbufIsSplice(dest))
    {
        assert(dest->curpos == dest->l_pad);
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

void sbufReadRangeToMemory(sbuf_t *source, void *destination, uint32_t bytes)
{
    assert(bytes <= sbufGetLength(source));
    const uint32_t prefix = min(bytes, sbufGetResidentPrefixLength(source));
    sbufByteCopy(destination, sbufGetRawPtr(source), prefix);
    sbufShiftRight(source, prefix);
    if (bytes != prefix)
    {
#if WW_HAVE_SPLICE
        spliceReadPipe(
            sbufSpliceMetadata(source).pipefd[0], (uint8_t *) destination + prefix, bytes - prefix, __func__);
        sbufSpliceConsumeBody(source, bytes - prefix);
#else
        LOGF("splice range: pipe source on unsupported build");
        abortProgramNow(1);
#endif
    }
}
