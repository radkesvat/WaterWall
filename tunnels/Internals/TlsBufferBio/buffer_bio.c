#include "TlsBufferBio/buffer_bio.h"

#include <openssl/crypto.h>

typedef struct tls_buffer_bio_s
{
    buffer_pool_t     *pool;
    ww_sbuffer_queue_t buffers;
    size_t             pending;
    int                eof_return;
#ifdef OPENSSL_IS_BORINGSSL
    sbuf_t *reserved;
    size_t  reserved_capacity;
    bool    reserved_new;
#endif
} tls_buffer_bio_t;

static void tlsbufferbioAssertIdle(const tls_buffer_bio_t *state)
{
    discard state;
#ifdef OPENSSL_IS_BORINGSSL
    assert(state->reserved == NULL);
#endif
}

/* Unlike BufferStream, this FIFO never coalesces admitted input. It exclusively
 * owns every entry, so partial reads can advance the first entry and BIO writes
 * can append to the last without moving unread bytes or invalidating aliases. */
static sbuf_t *tlsbufferbioPop(tls_buffer_bio_t *state)
{
    tlsbufferbioAssertIdle(state);
    if (ww_sbuffer_queue_t_is_empty(&state->buffers))
        return NULL;

    sbuf_t *buf = ww_sbuffer_queue_t_pull_front(&state->buffers);
    state->pending -= sbufGetLength(buf);
    return buf;
}

static void tlsbufferbioClear(tls_buffer_bio_t *state)
{
    tlsbufferbioAssertIdle(state);
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
    tlsbufferbioAssertIdle(state);
    BIO_clear_retry_flags(bio);
    if (UNLIKELY(length <= 0))
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
        memoryCopyLarge(out + copied, sbufGetRawPtr(buf), n);
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
    tlsbufferbioAssertIdle(state);
    BIO_clear_retry_flags(bio);
    if (UNLIKELY(length <= 0))
        return 0;
    if (UNLIKELY((size_t) length > kTlsBufferBioMaxBytes - state->pending))
        return -1;

    sbuf_t *buf = ww_sbuffer_queue_t_is_empty(&state->buffers) ? NULL : *ww_sbuffer_queue_t_back(&state->buffers);
    if (buf != NULL && (uint32_t) length <= sbufGetTailCapacity(buf))
    {
        const uint32_t previous = sbufGetLength(buf);
        memoryCopyLarge(sbufGetMutablePtr(buf) + previous, data, (size_t) length);
        sbufSetLength(buf, previous + (uint32_t) length);
        state->pending += (size_t) length;
        return length;
    }

    if (UNLIKELY(ww_sbuffer_queue_t_size(&state->buffers) >= kTlsBufferBioMaxBuffers))
        return -1;

    buf = bufferpoolGetLargeBuffer(state->pool);
    buf = sbufReserveSpace(buf, (uint32_t) length);
    sbufWriteLarge(buf, data, (uint32_t) length);
    sbufSetLength(buf, (uint32_t) length);
    if (UNLIKELY(ww_sbuffer_queue_t_push_back(&state->buffers, buf) == NULL))
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
    if (UNLIKELY(tlsbufferbioMethodIndex < 0))
        return NULL;

    BIO_METHOD *method = SSL_CTX_get_ex_data(ctx, tlsbufferbioMethodIndex);
    if (method == NULL)
    {
        method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "WaterWall owned buffers");
        if (UNLIKELY(method == NULL))
            return NULL;
        if (UNLIKELY(! BIO_meth_set_read(method, tlsbufferbioRead) || ! BIO_meth_set_write(method, tlsbufferbioWrite) ||
                     ! BIO_meth_set_ctrl(method, tlsbufferbioCtrl) ||
                     ! BIO_meth_set_destroy(method, tlsbufferbioDestroy) ||
                     ! SSL_CTX_set_ex_data(ctx, tlsbufferbioMethodIndex, method)))
        {
            BIO_meth_free(method);
            return NULL;
        }
    }

    BIO *bio = BIO_new(method);
    if (UNLIKELY(bio == NULL))
        return NULL;
    tls_buffer_bio_t *state = OPENSSL_zalloc(sizeof(*state));
    if (UNLIKELY(state == NULL))
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
    tls_buffer_bio_t *state = BIO_get_data(bio);
    tlsbufferbioAssertIdle(state);
    const size_t length = sbufGetLength(buf);
    if (UNLIKELY(length == 0))
    {
        bufferpoolReuseBuffer(state->pool, buf);
        return true;
    }
    if (UNLIKELY(length > kTlsBufferBioMaxBytes - state->pending ||
                 ww_sbuffer_queue_t_size(&state->buffers) >= kTlsBufferBioMaxBuffers ||
                 ww_sbuffer_queue_t_push_back(&state->buffers, buf) == NULL))
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

#ifdef OPENSSL_IS_BORINGSSL
uint8_t *tlsbufferbioReserveWrite(BIO *bio, size_t capacity, size_t alignment, size_t prefix_len)
{
    assert(bio != NULL && capacity > 0 && alignment > 0 && (alignment & (alignment - 1)) == 0);
    tls_buffer_bio_t *state = BIO_get_data(bio);
    tlsbufferbioAssertIdle(state);
    if (UNLIKELY(capacity > kTlsBufferBioMaxBytes - state->pending || alignment - 1 > UINT32_MAX - capacity))
        return NULL;

    sbuf_t *buf = ww_sbuffer_queue_t_is_empty(&state->buffers) ? NULL : *ww_sbuffer_queue_t_back(&state->buffers);
    bool    new_buffer = buf == NULL || capacity > sbufGetTailCapacity(buf);
    if (new_buffer)
    {
        if (UNLIKELY(ww_sbuffer_queue_t_size(&state->buffers) >= kTlsBufferBioMaxBuffers))
            return NULL;

        buf                   = bufferpoolGetLargeBuffer(state->pool);
        buf                   = sbufReserveSpace(buf, (uint32_t) (capacity + alignment - 1));
        const uint32_t offset = (uint32_t) ((0 - (uintptr_t) sbufGetMutablePtr(buf) - prefix_len) & (alignment - 1));
        /* Advance an empty cursor without spending the chain's left padding. */
        sbufSetLength(buf, offset);
        sbufShiftRight(buf, offset);
        /* Allocate the queue slot before encryption; publishing length later
         * must not fail after the TLS record sequence number has advanced. */
        if (UNLIKELY(ww_sbuffer_queue_t_push_back(&state->buffers, buf) == NULL))
        {
            bufferpoolReuseBuffer(state->pool, buf);
            return NULL;
        }
    }

    state->reserved          = buf;
    state->reserved_capacity = capacity;
    state->reserved_new      = new_buffer;
    BIO_clear_retry_flags(bio);
    return (uint8_t *) sbufGetMutablePtr(buf) + sbufGetLength(buf);
}

void tlsbufferbioFinishWrite(BIO *bio, size_t written)
{
    assert(bio != NULL);
    tls_buffer_bio_t *state = BIO_get_data(bio);
    sbuf_t           *buf   = state->reserved;
    assert(buf != NULL && written <= state->reserved_capacity);
    if (written == 0 && state->reserved_new)
    {
        assert(*ww_sbuffer_queue_t_back(&state->buffers) == buf);
        ww_sbuffer_queue_t_pop_back(&state->buffers);
        bufferpoolReuseBuffer(state->pool, buf);
    }
    else
    {
        sbufSetLength(buf, sbufGetLength(buf) + (uint32_t) written);
        state->pending += written;
    }
    state->reserved          = NULL;
    state->reserved_capacity = 0;
    state->reserved_new      = false;
}

static uint8_t *tlsbufferbioSslReserve(SSL *ssl, size_t capacity, size_t alignment, size_t prefix_len, void *arg)
{
    discard arg;
    return tlsbufferbioReserveWrite(SSL_get_wbio(ssl), capacity, alignment, prefix_len);
}

static void tlsbufferbioSslFinish(SSL *ssl, size_t written, void *arg)
{
    discard arg;
    tlsbufferbioFinishWrite(SSL_get_wbio(ssl), written);
}

void tlsbufferbioEnableDirectWrite(SSL *ssl)
{
    assert(ssl != NULL);
    SSL_set_record_write_buffer_callbacks(ssl, tlsbufferbioSslReserve, tlsbufferbioSslFinish, NULL);
}
#endif
