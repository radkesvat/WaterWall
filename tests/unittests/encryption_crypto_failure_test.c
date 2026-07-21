#if defined(TEST_ENCRYPTION_CLIENT)
#include "EncryptionClient/structure.h"
#define encryption_tstate_t           encryptionclient_tstate_t
#define encryption_lstate_t           encryptionclient_lstate_t
#define encryptionLinestateInitialize encryptionclientLinestateInitialize
#define encryptionPayload             encryptionclientTunnelDownStreamPayload
#elif defined(TEST_ENCRYPTION_SERVER)
#include "EncryptionServer/structure.h"
#define encryption_tstate_t           encryptionserver_tstate_t
#define encryption_lstate_t           encryptionserver_lstate_t
#define encryptionLinestateInitialize encryptionserverLinestateInitialize
#define encryptionPayload             encryptionserverTunnelUpStreamPayload
#else
#error "select an Encryption tunnel test role"
#endif

typedef struct encryption_failure_context_s
{
    uint32_t payloads;
    uint32_t upstream_finishes;
    uint32_t downstream_finishes;
} encryption_failure_context_t;

static bool decrypt_wrapper_called;

wcrypto_status_t __wrap_wCryptoChaCha20Poly1305Decrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                       const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);

wcrypto_status_t __wrap_wCryptoChaCha20Poly1305Decrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                       const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    decrypt_wrapper_called = true;
    discard src;
    discard ad;
    discard ad_len;
    discard nonce;
    discard key;
    if (dst != NULL && src_len >= WCRYPTO_AEAD_TAG_SIZE && dst_capacity >= src_len - WCRYPTO_AEAD_TAG_SIZE)
    {
        memoryZero(dst, src_len - WCRYPTO_AEAD_TAG_SIZE);
    }
    return kWCryptoBackendFailed;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static encryption_failure_context_t *testContext(tunnel_t *t)
{
    return *(encryption_failure_context_t **) tunnelGetState(t);
}

static void capturePayload(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    ++testContext(t)->payloads;
    lineReuseBuffer(line, buf);
}

static void captureUpstreamFinish(tunnel_t *t, line_t *line)
{
    discard line;
    ++testContext(t)->upstream_finishes;
}

static void captureDownstreamFinish(tunnel_t *t, line_t *line)
{
    discard line;
    ++testContext(t)->downstream_finishes;
}

static bool isAllZero(const void *bytes, size_t len)
{
    const uint8_t *cursor = bytes;
    uint8_t        value  = 0;
    for (size_t i = 0; i < len; ++i)
    {
        value |= cursor[i];
    }
    return value == 0;
}

int main(void)
{
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization failed");

    master_pool_t  *large_master    = masterpoolCreateWithCapacity(8);
    master_pool_t  *small_master    = masterpoolCreateWithCapacity(8);
    buffer_pool_t  *pool            = bufferpoolCreate(large_master, small_master, 8, 65536, 1024);
    buffer_pool_t **saved_shortcuts = GSTATE.shortcut_buffer_pools;
    buffer_pool_t  *shortcuts[1]    = {pool};
    GSTATE.shortcut_buffer_pools    = shortcuts;

    encryption_failure_context_t context = {0};
    tunnel_t                    *prev    = tunnelCreate(NULL, sizeof(encryption_failure_context_t *), 0);
    tunnel_t *encryption                 = tunnelCreate(NULL, sizeof(encryption_tstate_t), sizeof(encryption_lstate_t));
    tunnel_t *next                       = tunnelCreate(NULL, sizeof(encryption_failure_context_t *), 0);
    require(prev != NULL && encryption != NULL && next != NULL, "failed to create Encryption failure fixture");
    tunnelBind(prev, encryption);
    tunnelBind(encryption, next);
    *(encryption_failure_context_t **) tunnelGetState(prev) = &context;
    *(encryption_failure_context_t **) tunnelGetState(next) = &context;
    prev->fnPayloadD                                        = capturePayload;
    prev->fnFinD                                            = captureDownstreamFinish;
    next->fnPayloadU                                        = capturePayload;
    next->fnFinU                                            = captureUpstreamFinish;

    encryption_tstate_t *ts = tunnelGetState(encryption);
    ts->algorithm           = kEncryptionAlgorithmChaCha20Poly1305;
    ts->max_frame_payload   = kEncryptionDefaultMaxFramePayload;

    size_t  line_size = sizeof(line_t) + encryption->lstate_size;
    line_t *line      = memoryAllocateCacheAlignedZero(line_size);
    require(line != NULL, "failed to allocate Encryption failure line");
    atomic_init(&line->refc, 1);
    line->alive             = true;
    line->wid               = 0;
    encryption_lstate_t *ls = lineGetState(line, encryption);
    encryptionLinestateInitialize(ls, pool);

    enum
    {
        kBodyLength  = kEncryptionNonceSize + kEncryptionTagSize,
        kFrameLength = kEncryptionTlsHeaderSize + kBodyLength,
    };
    sbuf_t *frame = bufferpoolGetSmallBuffer(pool);
    require(frame != NULL && sbufGetMaximumWriteableSize(frame) >= kFrameLength,
            "failed to allocate Encryption failure frame");
    sbufSetLength(frame, kFrameLength);
    uint8_t *bytes = sbufGetMutablePtr(frame);
    memoryZero(bytes, kFrameLength);
    bytes[0] = kEncryptionTlsApplicationData;
    bytes[1] = kEncryptionTlsVersionMajor;
    bytes[2] = kEncryptionTlsVersionMinor;
    bytes[3] = (uint8_t) (kBodyLength >> 8);
    bytes[4] = (uint8_t) kBodyLength;

    encryptionPayload(encryption, line, frame);

    require(decrypt_wrapper_called, "Encryption failure shim was not exercised");
    require(context.payloads == 0, "Encryption forwarded plaintext after decrypt failure");
    require(context.upstream_finishes == 1 && context.downstream_finishes == 1,
            "Encryption decrypt failure did not close both directions");
    require(line->alive && atomic_load(&line->refc) == 1, "Encryption middle tunnel changed line ownership");
    require(isAllZero(ls, encryption->lstate_size), "Encryption decrypt failure retained line state");

    memoryFreeAligned(line);
    tunnelDestroy(prev);
    tunnelDestroy(encryption);
    tunnelDestroy(next);
    GSTATE.shortcut_buffer_pools = saved_shortcuts;
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
    wCryptoGlobalCleanup();
    return 0;
}
