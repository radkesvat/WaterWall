#pragma once

#include "wwapi.h"

enum encryption_algorithm_e
{
    kEncryptionAlgorithmChaCha20Poly1305 = kDvsFirstOption,
    kEncryptionAlgorithmAes256Gcm        = kDvsSecondOption,
};

enum
{
    kEncryptionTlsHeaderSize          = 5,
    kEncryptionTlsApplicationData     = 0x17,
    kEncryptionTlsVersionMajor        = 0x03,
    kEncryptionTlsVersionMinor        = 0x03,
    kEncryptionNonceSize              = 12,
    kEncryptionTagSize                = 16,
    kEncryptionFramePrefixSize        = kEncryptionTlsHeaderSize + kEncryptionNonceSize,
    kEncryptionMaxTlsRecordBody       = 16384,
    kEncryptionMaxFramePayload        = kEncryptionMaxTlsRecordBody - kEncryptionNonceSize - kEncryptionTagSize,
    kEncryptionDefaultKdfIterations   = 12000,
    kEncryptionDefaultMaxFramePayload = kEncryptionMaxFramePayload,
    kEncryptionHardMaxFramePayload    = kEncryptionMaxFramePayload,
};

typedef enum encryption_frame_result_e
{
    kEncryptionFrameNeedMore,
    kEncryptionFrameReady,
    kEncryptionFrameInvalid,
} encryption_frame_result_t;

/* All operations are synchronous, ordinary-buffer-only and have no tunnel or
 * line callbacks. The caller owns chunking, direction, line lifetime and failure
 * cleanup. Pool access requires the owning worker. */

/* Preserve the nodes' small/large/dedicated frame allocation policy. The pool
 * must advertise at least kEncryptionFramePrefixSize bytes of left padding. */
sbuf_t *encryptionAllocFrameBuffer(buffer_pool_t *pool, uint32_t frame_length);

/* Encode the entire owned plaintext in place, growing tail storage if needed.
 * Requires plaintext length <= kEncryptionHardMaxFramePayload and the advertised
 * left padding. Generates a fresh nonce and authenticates the five-byte header.
 * On every result *buffer is the sole caller-owned allocation; on failure its
 * contents may have changed and must be discarded. Zero plaintext is supported;
 * nodes retain their policy of dropping empty application input before encoding. */
WCRYPTO_MUST_USE wcrypto_status_t encryptionEncodeFrame(uint32_t algorithm, const uint8_t key[32], sbuf_t **buffer);

/* Ready consumes exactly one complete, validated record and transfers it through
 * frame. NeedMore/Invalid consume nothing and leave *frame unchanged. A complete
 * header whose body exceeds the configured limit is Invalid immediately.
 * max_payload must be in [1, kEncryptionHardMaxFramePayload]. */
encryption_frame_result_t encryptionReadFrame(buffer_stream_t *stream, uint32_t max_payload, sbuf_t **frame);

/* Requires one complete validated record, as returned by ReadFrame. On success
 * buffer exposes only plaintext (which can be empty). Ownership never changes;
 * on failure contents may have changed and the caller must discard the buffer. */
WCRYPTO_MUST_USE wcrypto_status_t encryptionDecodeFrame(uint32_t algorithm, const uint8_t key[32], sbuf_t *buffer);
