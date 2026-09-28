#include "TlsBufferBio/buffer_bio.h"

#include "buffer_queue.h"
#include "wmutex.h"

#include <openssl/crypto.h>

typedef struct tls_buffer_bio_s
{
    buffer_pool_t     *pool;
    ww_sbuffer_queue_t buffers;
    size_t             pending;
    int                eof_return;
} tls_buffer_bio_t;

/* Unlike BufferStream, this FIFO never coalesces admitted input. It exclusively
 * owns every entry, so partial reads can advance the first entry and BIO writes
 * can append to the last without moving unread bytes or invalidating aliases. */
static sbuf_t *tlsbufferbioPop(tls_buffer_bio_t *state)
{
    if (ww_sbuffer_queue_t_is_empty(&state->buffers))
        return NULL;

    sbuf_t *buf = ww_sbuffer_queue_t_pull_front(&state->buffers);
    state->pending -= sbufGetLength(buf);
    return buf;
}

static void tlsbufferbioClear(tls_buffer_bio_t *state)
{
    sbuf_t *buf;
    while ((buf = tlsbufferbioPop(state)) != NULL)
        bufferpoolReuseBuffer(state->pool, buf);
}

static int tlsbufferbioDestroy(BIO *bio)
{
    tls_buffer_bio_t *state = BIO_get_data(bio);
    if (state != NULL)
    {
        tlsbufferbioClear(state);
        ww_sbuffer_queue_t_drop(&state->buffers);
        OPENSSL_free(state);
        BIO_set_data(bio, NULL);
    }
    return 1;
}

static int tlsbufferbioRead(BIO *bio, char *out, int length)
{
    tls_buffer_bio_t *state = BIO_get_data(bio);
    BIO_clear_retry_flags(bio);
    if (length <= 0)
        return 0;
    if (state->pending == 0)
    {
        if (state->eof_return != 0)
            BIO_set_retry_read(bio);
        return state->eof_return;
    }

    const size_t wanted = min((size_t) length, state->pending);
    size_t       copied = 0;
    while (copied < wanted)
    {
        sbuf_t        *buf = *ww_sbuffer_queue_t_front(&state->buffers);
        const uint32_t n   = (uint32_t) min(wanted - copied, (size_t) sbufGetLength(buf));
        memoryCopy(out + copied, sbufGetRawPtr(buf), n);
        sbufShiftRight(buf, n);
        state->pending -= n;
        copied += n;
        if (sbufGetLength(buf) == 0)
        {
            discard ww_sbuffer_queue_t_pull_front(&state->buffers);
            bufferpoolReuseBuffer(state->pool, buf);
        }
    }
    return (int) copied;
}

static int tlsbufferbioWrite(BIO *bio, const char *data, int length)
{
    tls_buffer_bio_t *state = BIO_get_data(bio);
    BIO_clear_retry_flags(bio);
    if (length <= 0)
        return 0;
    if ((size_t) length > kTlsBufferBioMaxBytes - state->pending)
        return -1;

    sbuf_t *buf = ww_sbuffer_queue_t_is_empty(&state->buffers) ? NULL : *ww_sbuffer_queue_t_back(&state->buffers);
    if (buf != NULL && (uint32_t) length <= sbufGetMaximumWriteableSize(buf) - sbufGetLength(buf))
    {
        const uint32_t previous = sbufGetLength(buf);
        memoryCopy(sbufGetMutablePtr(buf) + previous, data, (size_t) length);
        sbufSetLength(buf, previous + (uint32_t) length);
        state->pending += (size_t) length;
        return length;
    }

    if (ww_sbuffer_queue_t_size(&state->buffers) >= kTlsBufferBioMaxBuffers)
        return -1;

    buf = bufferpoolGetLargeBuffer(state->pool);
    buf = sbufReserveSpace(buf, (uint32_t) length);
    sbufWrite(buf, data, (uint32_t) length);
    sbufSetLength(buf, (uint32_t) length);
    if (ww_sbuffer_queue_t_push_back(&state->buffers, buf) == NULL)
    {
        bufferpoolReuseBuffer(state->pool, buf);
        return -1;
    }
    state->pending += (size_t) length;
    return length;
}

static long tlsbufferbioCtrl(BIO *bio, int command, long number, void *arg)
{
    discard           arg;
    tls_buffer_bio_t *state = BIO_get_data(bio);
    switch (command)
    {
    case BIO_CTRL_RESET:
        tlsbufferbioClear(state);
        BIO_clear_retry_flags(bio);
        return 1;
    case BIO_CTRL_EOF:
        return state->pending == 0;
    case BIO_CTRL_PENDING:
        return (long) state->pending;
    case BIO_CTRL_WPENDING:
        return 0;
    case BIO_CTRL_FLUSH:
        return 1;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
        assert(number <= 0 && number >= INT_MIN);
        state->eof_return = (int) number;
        return 1;
    default:
        return 0;
    }
}

static int     tlsbufferbioMethodIndex = -1;
static wonce_t tlsbufferbioMethodOnce  = WONCE_INIT;

static void tlsbufferbioMethodFree(void *parent, void *ptr, CRYPTO_EX_DATA *data, int index, long argl, void *argp)
{
    discard parent;
    discard data;
    discard index;
    discard argl;
    discard argp;
    BIO_meth_free(ptr);
}

static void tlsbufferbioMethodIndexInit(void)
{
    tlsbufferbioMethodIndex = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, tlsbufferbioMethodFree);
}

BIO *tlsbufferbioNew(SSL_CTX *ctx, buffer_pool_t *pool)
{
    assert(ctx != NULL && pool != NULL);
    wonce(&tlsbufferbioMethodOnce, tlsbufferbioMethodIndexInit);
    if (tlsbufferbioMethodIndex < 0)
        return NULL;

    BIO_METHOD *method = SSL_CTX_get_ex_data(ctx, tlsbufferbioMethodIndex);
    if (method == NULL)
    {
        method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "WaterWall owned buffers");
        if (method == NULL)
            return NULL;
        if (! BIO_meth_set_read(method, tlsbufferbioRead) || ! BIO_meth_set_write(method, tlsbufferbioWrite) ||
            ! BIO_meth_set_ctrl(method, tlsbufferbioCtrl) || ! BIO_meth_set_destroy(method, tlsbufferbioDestroy) ||
            ! SSL_CTX_set_ex_data(ctx, tlsbufferbioMethodIndex, method))
        {
            BIO_meth_free(method);
            return NULL;
        }
    }

    BIO *bio = BIO_new(method);
    if (bio == NULL)
        return NULL;
    tls_buffer_bio_t *state = OPENSSL_zalloc(sizeof(*state));
    if (state == NULL)
    {
        BIO_free(bio);
        return NULL;
    }
    state->pool       = pool;
    state->eof_return = -1;
    BIO_set_data(bio, state);
    BIO_set_init(bio, 1);
    return bio;
}

bool tlsbufferbioFeed(BIO *bio, sbuf_t *buf)
{
    assert(bio != NULL && buf != NULL && ! sbufIsSplice(buf));
    tls_buffer_bio_t *state  = BIO_get_data(bio);
    const size_t      length = sbufGetLength(buf);
    if (length == 0)
    {
        bufferpoolReuseBuffer(state->pool, buf);
        return true;
    }
    if (length > kTlsBufferBioMaxBytes - state->pending ||
        ww_sbuffer_queue_t_size(&state->buffers) >= kTlsBufferBioMaxBuffers ||
        ww_sbuffer_queue_t_push_back(&state->buffers, buf) == NULL)
    {
        bufferpoolReuseBuffer(state->pool, buf);
        return false;
    }
    state->pending += length;
    BIO_clear_retry_flags(bio);
    return true;
}

sbuf_t *tlsbufferbioTake(BIO *bio)
{
    assert(bio != NULL);
    return tlsbufferbioPop(BIO_get_data(bio));
}

size_t tlsbufferbioPeek(BIO *bio, void *out, size_t length)
{
    assert(bio != NULL && (out != NULL || length == 0));
    tls_buffer_bio_t *state  = BIO_get_data(bio);
    size_t            copied = 0;
    c_foreach(entry, ww_sbuffer_queue_t, state->buffers)
    {
        size_t n = min(length - copied, (size_t) sbufGetLength(*entry.ref));
        if (n == 0)
            break;
        memoryCopy((uint8_t *) out + copied, sbufGetRawPtr(*entry.ref), n);
        copied += n;
    }
    return copied;
}
