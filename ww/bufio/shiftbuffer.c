/*
 * Implements sbuf creation, duplication, slicing, and concatenation routines.
 */

#include "shiftbuffer.h"
#include "loggers/internal_logger.h"
#include "master_pool.h"
#include "splice_buffer.h"
#if WW_HAVE_SPLICE
#include "global_state.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#include "wlibc.h"

static sbuf_t *sbufTryAllocate(uint32_t capacity, uint16_t pad_left);

#if WW_HAVE_SPLICE
/* Owned by GSTATE. Startup fixes both the inventory and aligned padding before
 * producers start. Checked-out entries include worker-local cached buffers. */
typedef struct sbuf_splice_inventory_s
{
    master_pool_t *pool;
    atomic_uint    count;
    atomic_ullong  capacity;
    int32_t        padding; // -1 during exclusive configuration; then the immutable aligned padding.
    int            discard_fd;
} sbuf_splice_inventory_t;

static master_pool_item_t *spliceBufferCreationForbidden(void *userdata)
{
    discard userdata;
    LOGF("SplicePool: buffer creation is restricted to startup");
    abortProgramNow(1);
}

static void destroySplicePoolBuffer(master_pool_item_t *item)
{
    sbuf_t *buf = item;
    sbufSpliceClosePipe(buf);
    memoryFreeAligned(buf);
}
#endif

void sbufSplicePoolCheckPadding(uint16_t padding)
{
#if WW_HAVE_SPLICE
    const sbuf_splice_inventory_t *inventory = GSTATE.splice_inventory;
    if (inventory != NULL && inventory->padding >= 0 && padding != inventory->padding)
    {
        LOGF("SplicePool: immutable padding changed from %d to %u", inventory->padding, padding);
        abortProgramNow(1);
    }
#else
    discard padding;
#endif
}

void sbufSpliceCheckBuffer(const sbuf_t *buf)
{
    if (! sbufIsPooledSplice(buf))
        return;
#if WW_HAVE_SPLICE
    if (GSTATE.splice_inventory == NULL)
    {
        LOGF("SplicePool: pooled buffer outlived its inventory");
        abortProgramNow(1);
    }
#endif
    sbufSplicePoolCheckPadding(buf->l_pad);
}

uint16_t sbufSplicePoolPadding(void)
{
#if WW_HAVE_SPLICE
    return GSTATE.splice_inventory != NULL && GSTATE.splice_inventory->padding >= 0
               ? (uint16_t) GSTATE.splice_inventory->padding
               : 0;
#else
    return 0;
#endif
}

bool sbufSplicePoolPrepare(void)
{
#if WW_HAVE_SPLICE
    assert(GSTATE.splice_inventory == NULL);
    sbuf_splice_inventory_t *inventory = memoryAllocate(sizeof(*inventory));
    if (inventory == NULL)
        return false;
    *inventory              = (sbuf_splice_inventory_t) {.padding = -1, .discard_fd = -1};
    GSTATE.splice_inventory = inventory;
    return true;
#else
    return false;
#endif
}

uint32_t sbufSplicePoolInitialize(uint64_t capacity_limit, uint32_t pipe_capacity, uint32_t max_pipe_count,
                                  uint16_t padding)
{
    assert(pipe_capacity > 0 && pipe_capacity <= INT_MAX);
    padding = sbufAlignLeftPadding(padding);
#if WW_HAVE_SPLICE
    if (GSTATE.splice_inventory == NULL && ! sbufSplicePoolPrepare())
        return 0;
    sbuf_splice_inventory_t *inventory = GSTATE.splice_inventory;
    assert(inventory->padding == -1);
    inventory->padding    = padding;
    const uint32_t target = (uint32_t) min(capacity_limit / pipe_capacity, (uint64_t) max_pipe_count);
    if (target == 0)
        return 0;
    inventory->pool = masterpoolCreateWithCapacity(target / 2U + target % 2U);
    if (inventory->pool == NULL)
        return 0;
    masterpoolInstallCallBacks(inventory->pool, spliceBufferCreationForbidden, destroySplicePoolBuffer);

    uint64_t acquired_capacity = 0;
    uint32_t acquired_count    = 0;
    for (uint32_t i = 0; i < target; ++i)
    {
        sbuf_t *buf = sbufTryAllocate(SPLICE_BUFFER_STORAGE_SIZE + (uint32_t) padding, padding);
        if (buf == NULL)
            break;
        int pair[2];
        if (pipe2(pair, O_NONBLOCK | O_CLOEXEC) != 0)
        {
            memoryFreeAligned(buf);
            break;
        }
        int capacity = fcntl(pair[0], F_GETPIPE_SZ);
        if (capacity > 0 && (uint32_t) capacity < pipe_capacity)
            capacity = fcntl(pair[0], F_SETPIPE_SZ, (int) pipe_capacity);
        if (capacity < 0 || (uint32_t) capacity < pipe_capacity ||
            (uint64_t) capacity > capacity_limit - acquired_capacity)
        {
            const int error = capacity < 0 ? errno : ENOBUFS;
            close(pair[0]);
            close(pair[1]);
            memoryFreeAligned(buf);
            errno = error;
            break;
        }
        buf->flags = kSbufFlagSplice | kSbufFlagSplicePooled;
        sbufSpliceSetMetadata(
            buf, (splice_buffer_metadata_t) {.pipefd = {pair[0], pair[1]}, .pipe_capacity = (uint32_t) capacity});
        acquired_capacity += (uint32_t) capacity;
        ++acquired_count;
        atomicStoreU64Explicit(&inventory->capacity, acquired_capacity, memory_order_relaxed);
        atomicStoreExplicit(&inventory->count, acquired_count, memory_order_relaxed);
        master_pool_item_t *item = buf;
        masterpoolReuseItems(inventory->pool, &item, 1);
    }
    if (acquired_count != 0)
    {
        do
        {
            inventory->discard_fd = open("/dev/null", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        } while (inventory->discard_fd < 0 && errno == EINTR);
    }
    return acquired_count;
#else
    discard capacity_limit;
    discard pipe_capacity;
    discard max_pipe_count;
    discard padding;
    return 0;
#endif
}

uint64_t sbufSplicePoolCapacity(void)
{
#if WW_HAVE_SPLICE
    const sbuf_splice_inventory_t *inventory = GSTATE.splice_inventory;
    return inventory != NULL ? atomicLoadU64Explicit(&inventory->capacity, memory_order_relaxed) : 0;
#else
    return 0;
#endif
}

uint32_t sbufSplicePoolCount(void)
{
#if WW_HAVE_SPLICE
    const sbuf_splice_inventory_t *inventory = GSTATE.splice_inventory;
    return inventory != NULL ? atomicLoadExplicit(&inventory->count, memory_order_relaxed) : 0;
#else
    return 0;
#endif
}

void sbufSplicePoolDestroy(void)
{
#if WW_HAVE_SPLICE
    sbuf_splice_inventory_t *inventory = GSTATE.splice_inventory;
    if (inventory == NULL)
        return;
    if (inventory->pool != NULL && masterpoolGetCheckedOut(inventory->pool) != 0)
    {
        LOGF("SplicePool: destroying inventory with an outstanding pipe lease");
        abortProgramNow(1);
    }
    masterpoolMakeEmpty(inventory->pool);
    masterpoolDestroy(inventory->pool);
    if (inventory->discard_fd >= 0)
        close(inventory->discard_fd);
    memoryFree(inventory);
    GSTATE.splice_inventory = NULL;
#endif
}

size_t sbufGetAllocationCharge(const sbuf_t *buf)
{
    assert(buf != NULL);
    const size_t storage = sbufIsSplice(buf) ? (size_t) sbufGetLeftPadding(buf) + SPLICE_BUFFER_STORAGE_SIZE
                                             : (size_t) sbufGetTotalCapacity(buf);
    return sizeof(sbuf_t) + storage + (size_t) kSbufAllocationAlignment;
}

bool sbufTryComputeQueueCharge(uint32_t capacity, size_t *charge)
{
    const size_t overhead = sizeof(sbuf_t) + (size_t) kSbufAllocationAlignment;
    if ((uint64_t) capacity > SIZE_MAX - overhead)
        return false;
    *charge = overhead + (size_t) capacity;
    return true;
}

bool sbufTryGetQueueCharge(const sbuf_t *buf, size_t *charge)
{
    return sbufTryComputeQueueCharge(sbufGetTotalCapacity(buf), charge);
}

size_t sbufGetQueueCharge(const sbuf_t *buf)
{
    size_t charge;
    if (UNLIKELY(! sbufTryGetQueueCharge(buf, &charge)))
    {
        printError("sbuf: unrepresentable queue capacity charge");
        abortProgramNow(1);
    }
    return charge;
}

uint16_t sbufAlignLeftPadding(uint16_t pad_left)
{
    const uint32_t aligned_pad = (((uint32_t) pad_left) + 31U) & ~31U;

    if (aligned_pad > UINT16_MAX)
    {
        printError("sbuf: left padding overflow after alignment");
        abortProgramNow(1);
    }

    return (uint16_t) aligned_pad;
}

void sbufDestroy(sbuf_t *b)
{
    if (sbufIsSplice(b))
    {
        sbufDestroySplice(b);
        return;
    }
    memoryFreeAligned(b);
}

static sbuf_t *sbufTryAllocate(uint32_t capacity, uint16_t pad_left)
{
    size_t  total_size = sizeof(sbuf_t) + (size_t) capacity;
    sbuf_t *b          = memoryAllocateAligned(total_size, kSbufAllocationAlignment);
    if (b == NULL)
    {
        return NULL;
    }

#ifdef DEBUG
    memorySet(b->buf, 0x55, capacity);
#else
    if (capacity > 2048)
    {
        volatile uint8_t *bytes     = b->buf;
        size_t            remaining = capacity;
        /* Prefault fresh storage, including padding, with a minimum page size
         * of 4096 bytes. Touch the last byte for a trailing unaligned page.
         * Volatile stores keep the compiler from removing these writes. */
        while (remaining > 4096)
        {
            *bytes = 0;
            bytes += 4096;
            remaining -= 4096;
        }
        bytes[0]             = 0;
        bytes[remaining - 1] = 0;
    }
#endif

    b->flags    = 0;
    b->len      = 0;
    b->curpos   = pad_left;
    b->capacity = capacity;
    b->l_pad    = pad_left;

    return b;
}

static sbuf_t *sbufAllocate(uint32_t capacity, uint16_t pad_left)
{
    sbuf_t *buffer = sbufTryAllocate(capacity, pad_left);
    if (buffer == NULL)
    {
        printError("sbuf: allocation failed");
        exit(1);
    }
    return buffer;
}

sbuf_t *sbufTryCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    uint32_t real_cap;
    if (! sbufTryComputeCapacity(minimum_capacity, pad_left, &real_cap))
    {
        return NULL;
    }
    return sbufTryAllocate(real_cap, sbufAlignLeftPadding(pad_left));
}

sbuf_t *sbufCreateWithPadding(uint32_t minimum_capacity, uint16_t pad_left)
{
    pad_left = sbufAlignLeftPadding(pad_left);

    /*
     * The rounding and the padding are both applied in 64-bit arithmetic by the
     * helper. Doing the cache-line round-up in 32-bit arithmetic first, as this
     * did, wraps for any request above UINT32_MAX - kCpuLineCacheSizeMin1: the
     * capacity collapsed to 0 and the "capacity overflow" check below it could
     * never fire, handing back a buffer of only pad_left bytes.
     *
     * Reaching this abort means a caller committed to a size that cannot exist.
     * There is no return value to fail through, and the request is already
     * nonsensical, so this is Category D. Callers holding an untrusted length
     * must pre-validate with sbufTryComputeCapacity() and fail locally instead.
     */
    uint32_t real_cap = 0;
    if (! sbufTryComputeCapacity(minimum_capacity, pad_left, &real_cap))
    {
        printError("sbuf: capacity overflow (minimum_capacity + pad_left)");
        abortProgramNow(1);
    }

    // Cannot wrap, and memoryAllocateAligned() cannot reject this for size: the
    // helper above accounted for the header and the alignment over-allocation,
    // which are the binding limits on 32-bit targets.
    return sbufAllocate(real_cap, pad_left);
}

sbuf_t *sbufCreate(uint32_t minimum_capacity)
{
    return sbufCreateWithPadding(minimum_capacity, 0);
}

sbuf_t *sbufCreateSplice(uint16_t pad_left)
{
    pad_left    = sbufAlignLeftPadding(pad_left);
    sbuf_t *buf = sbufAllocate(SPLICE_BUFFER_STORAGE_SIZE + (uint32_t) pad_left, pad_left);
    buf->flags  = kSbufFlagSplice;
    sbufSpliceSetMetadata(buf, (splice_buffer_metadata_t) {.pipefd = {-1, -1}});
    return buf;
}

bool sbufDuplicateTo(const sbuf_t *b, sbuf_t *dest)
{
    assert(b != NULL && dest != NULL);
    assert(b != dest);

    const uint32_t source_curpos = b->curpos;
    const uint32_t source_length = sbufGetLength(b);
    const uint32_t dest_capacity = sbufGetTotalCapacity(dest);

    if (UNLIKELY(source_curpos > dest_capacity || source_length > dest_capacity - source_curpos))
    {
        return false;
    }

    dest->curpos = source_curpos;
    sbufSetLength(dest, source_length);
    if (source_length > 0)
    {
        memoryCopyLarge(sbufGetMutablePtr(dest), sbufGetRawPtr(b), source_length);
    }
    return true;
}

sbuf_t *sbufDuplicate(sbuf_t *b)
{
    sbuf_t *newbuf = sbufCreateWithPadding(sbufGetTotalCapacityNoPadding(b), b->l_pad);

    if (UNLIKELY(! sbufDuplicateTo(b, newbuf)))
    {
        sbufDestroy(newbuf);
        printError("sbuf: an exactly sized duplicate buffer could not represent its source");
        abortProgramNow(1);
    }
    return newbuf;
}

sbuf_t *sbufConcat(sbuf_t *restrict root, const sbuf_t *restrict const buf)
{
    uint32_t root_length   = sbufGetLength(root);
    uint32_t append_length = sbufGetLength(buf);

    if (UNLIKELY(root_length > UINT32_MAX - append_length))
    {
        printError("sbuf: concat overflow (root=%u, append=%u)", root_length, append_length);
        abortProgramNow(1);
    }

    root = sbufReserveSpace(root, root_length + append_length);
    sbufSetLength(root, root_length + append_length);

    memoryCopyLarge(sbufGetMutablePtr(root) + root_length, sbufGetRawPtr(buf), append_length);

    return root;
}

sbuf_t *sbufMoveTo(sbuf_t *restrict dest, sbuf_t *restrict source, const uint32_t bytes)
{
    uint32_t dest_length = sbufGetLength(dest);

    assert(bytes <= sbufGetLength(source));
    assert(dest_length <= UINT32_MAX - bytes);
    assert(dest_length + bytes <= sbufGetMaximumWriteableSize(dest));

    memoryCopyLarge(sbufGetMutablePtr(dest) + dest_length, sbufGetRawPtr(source), bytes);
    sbufSetLength(dest, dest_length + bytes);

    sbufShiftRight(source, bytes);

    return dest;
}

sbuf_t *sbufSlice(sbuf_t *const b, const uint32_t bytes)
{
    assert(b != NULL && ! sbufIsSplice(b));
    assert(bytes <= sbufGetLength(b));
    sbuf_t *newbuf = sbufCreateWithPadding(bytes, b->l_pad);
    sbufMoveTo(newbuf, b, bytes);
    return newbuf;
}

uint32_t sbufSplicePoolGetBuffers(sbuf_t **buffers, uint32_t count, uint16_t padding)
{
    assert(buffers != NULL && count > 0);
    sbufSplicePoolCheckPadding(padding);
#if WW_HAVE_SPLICE
    sbuf_splice_inventory_t *inventory = GSTATE.splice_inventory;
    const uint32_t           taken     = inventory != NULL && inventory->pool != NULL
                                             ? masterpoolTryGetItems(inventory->pool, (void **) buffers, count)
                                             : 0;
    for (uint32_t i = 0; i < taken; ++i)
    {
        masterpoolRecordCheckout(inventory->pool);
        sbufSpliceCheckBuffer(buffers[i]);
    }
    if (taken == 0)
        errno = ENOBUFS;
    return taken;
#else
    discard buffers;
    discard count;
    errno = ENOSYS;
    return 0;
#endif
}

sbuf_t *sbufSplicePoolGet(uint16_t padding)
{
    sbuf_t *buf = NULL;
    sbufSplicePoolGetBuffers(&buf, 1, padding);
    return buf;
}

void sbufSpliceClosePipe(sbuf_t *buf)
{
    sbufSpliceCheckBuffer(buf);
#if WW_HAVE_SPLICE
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    if (metadata.pipefd[0] >= 0)
    {
        close(metadata.pipefd[0]);
        if (sbufIsPooledSplice(buf))
        {
            atomicSubU64Explicit(&GSTATE.splice_inventory->capacity, metadata.pipe_capacity, memory_order_relaxed);
            atomicSubExplicit(&GSTATE.splice_inventory->count, 1, memory_order_relaxed);
        }
    }
    if (metadata.pipefd[1] >= 0)
        close(metadata.pipefd[1]);
#endif
    sbufSpliceSetMetadata(buf, (splice_buffer_metadata_t) {.pipefd = {-1, -1}});
}

void sbufSpliceDiscard(sbuf_t *buf)
{
    assert(sbufIsSplice(buf));
    sbufSpliceCheckBuffer(buf);
    if (buf->len == 0)
    {
        buf->curpos = buf->l_pad;
        return;
    }
#if WW_HAVE_SPLICE
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    if (metadata.pipefd[0] >= 0)
    {
        const sbuf_splice_inventory_t *inventory  = GSTATE.splice_inventory;
        const int                      discard_fd = inventory != NULL ? inventory->discard_fd : -1;
        bool                           use_splice = discard_fd >= 0;
        uint8_t                        scratch[1024];
        for (;;)
        {
            ssize_t consumed;
            if (use_splice)
            {
                consumed = splice(metadata.pipefd[0], NULL, discard_fd, NULL, SPLICE_PAYLOAD_LIMIT, SPLICE_F_NONBLOCK);
                if (consumed < 0 && errno != EINTR && errno != EAGAIN)
                {
                    /* A refused splice must not retire a readable pipe. Fall
                     * back for this discard without changing the shared sink. */
                    use_splice = false;
                    continue;
                }
            }
            else
                consumed = read(metadata.pipefd[0], scratch, sizeof(scratch));
            if (consumed > 0)
                continue;
            if (UNLIKELY(consumed < 0 && errno == EINTR))
                continue;
            if (consumed < 0 && errno == EAGAIN)
                break;
            sbufSpliceClosePipe(buf);
            break;
        }
    }
#endif
    buf->len    = 0;
    buf->curpos = buf->l_pad;
}

bool sbufSpliceIsReusable(const sbuf_t *buf)
{
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    if (buf->len != 0)
        return false;
    if (metadata.pipefd[0] < 0)
        return metadata.pipefd[1] < 0;
#if WW_HAVE_SPLICE
    int bytes;
    return metadata.pipefd[1] >= 0 && ioctl(metadata.pipefd[0], FIONREAD, &bytes) == 0 && bytes == 0;
#else
    return false;
#endif
}

void sbufDestroySplice(sbuf_t *buf)
{
    sbufSpliceCheckBuffer(buf);
    if (! sbufIsPooledSplice(buf))
    {
        sbufSpliceClosePipe(buf);
        memoryFreeAligned(buf);
        return;
    }
#if WW_HAVE_SPLICE
    sbufSpliceDiscard(buf);
    master_pool_t *pool = GSTATE.splice_inventory->pool;
    if (sbufSpliceMetadata(buf).pipefd[0] >= 0)
    {
        buf->capacity            = (uint32_t) buf->l_pad + SPLICE_BUFFER_STORAGE_SIZE;
        master_pool_item_t *item = buf;
        masterpoolReuseItems(pool, &item, 1);
    }
    else
        memoryFreeAligned(buf);
    masterpoolRecordReturn(pool);
#endif
}
