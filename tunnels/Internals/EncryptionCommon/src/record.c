#include "EncryptionCommon/record.h"

static wcrypto_status_t encryptAead(uint32_t algorithm, unsigned char *dst, size_t dst_capacity,
                                    const unsigned char *src, size_t src_len, const unsigned char *ad, size_t ad_len,
                                    const unsigned char *nonce, const unsigned char *key)
{
    if (algorithm == kEncryptionAlgorithmChaCha20Poly1305)
        return wCryptoChaCha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    if (algorithm == kEncryptionAlgorithmAes256Gcm)
        return wCryptoAes256GcmEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    return kWCryptoUnavailable;
}

static wcrypto_status_t decryptAead(uint32_t algorithm, unsigned char *dst, size_t dst_capacity,
                                    const unsigned char *src, size_t src_len, const unsigned char *ad, size_t ad_len,
                                    const unsigned char *nonce, const unsigned char *key)
{
    if (algorithm == kEncryptionAlgorithmChaCha20Poly1305)
        return wCryptoChaCha20Poly1305Decrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    if (algorithm == kEncryptionAlgorithmAes256Gcm)
        return wCryptoAes256GcmDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    return kWCryptoUnavailable;
}

sbuf_t *encryptionAllocFrameBuffer(buffer_pool_t *pool, uint32_t frame_length)
{
    if (frame_length <= bufferpoolGetSmallBufferSize(pool))
        return bufferpoolGetSmallBuffer(pool);
    if (frame_length <= bufferpoolGetLargeBufferSize(pool))
        return bufferpoolGetLargeBuffer(pool);
    return sbufCreateWithPadding(frame_length, bufferpoolGetLargeBufferPadding(pool));
}

wcrypto_status_t encryptionEncodeFrame(uint32_t algorithm, const uint8_t key[32], sbuf_t **buffer)
{
    assert(buffer != NULL && *buffer != NULL && ! sbufIsSplice(*buffer));
    uint32_t plaintext_length = sbufGetLength(*buffer);
    assert(plaintext_length <= kEncryptionHardMaxFramePayload);
    assert(sbufGetLeftCapacity(*buffer) >= kEncryptionFramePrefixSize);
    uint32_t ciphertext_length = plaintext_length + kEncryptionTagSize;
    uint32_t body_length       = kEncryptionNonceSize + ciphertext_length;

    if (sbufGetMaximumWriteableSize(*buffer) < ciphertext_length)
        *buffer = sbufReserveSpace(*buffer, ciphertext_length);

    sbufShiftLeft(*buffer, kEncryptionFramePrefixSize);
    uint8_t *frame = sbufGetMutablePtr(*buffer);
    frame[0]       = kEncryptionTlsApplicationData;
    frame[1]       = kEncryptionTlsVersionMajor;
    frame[2]       = kEncryptionTlsVersionMinor;
    frame[3]       = (uint8_t) (body_length >> 8);
    frame[4]       = (uint8_t) body_length;
    uint8_t *nonce = frame + kEncryptionTlsHeaderSize;
    getRandomBytes(nonce, kEncryptionNonceSize);

    uint8_t         *ciphertext = frame + kEncryptionFramePrefixSize;
    size_t           capacity   = sbufGetMaximumWriteableSize(*buffer) - kEncryptionFramePrefixSize;
    wcrypto_status_t status     = encryptAead(
        algorithm, ciphertext, capacity, ciphertext, plaintext_length, frame, kEncryptionTlsHeaderSize, nonce, key);
    if (status == kWCryptoOk)
        sbufSetLength(*buffer, kEncryptionTlsHeaderSize + body_length);
    return status;
}

encryption_frame_result_t encryptionReadFrame(buffer_stream_t *stream, uint32_t max_payload, sbuf_t **frame)
{
    assert(max_payload > 0 && max_payload <= kEncryptionHardMaxFramePayload);
    assert(frame != NULL);
    if (bufferstreamGetBufLen(stream) < kEncryptionTlsHeaderSize)
        return kEncryptionFrameNeedMore;

    uint8_t header[kEncryptionTlsHeaderSize];
    bufferstreamViewBytesAt(stream, 0, header, sizeof(header));
    if (header[0] != kEncryptionTlsApplicationData || header[1] != kEncryptionTlsVersionMajor ||
        header[2] != kEncryptionTlsVersionMinor)
        return kEncryptionFrameInvalid;

    uint32_t body_length = ((uint32_t) header[3] << 8) | header[4];
    if (body_length < kEncryptionNonceSize + kEncryptionTagSize ||
        body_length > max_payload + kEncryptionNonceSize + kEncryptionTagSize)
        return kEncryptionFrameInvalid;

    uint32_t frame_length = kEncryptionTlsHeaderSize + body_length;
    if (bufferstreamGetBufLen(stream) < frame_length)
        return kEncryptionFrameNeedMore;

    *frame = bufferstreamReadExact(stream, frame_length);
    return kEncryptionFrameReady;
}

wcrypto_status_t encryptionDecodeFrame(uint32_t algorithm, const uint8_t key[32], sbuf_t *buffer)
{
    assert(buffer != NULL && ! sbufIsSplice(buffer));
    assert(sbufGetLength(buffer) >= kEncryptionFramePrefixSize + kEncryptionTagSize);
    uint8_t *frame       = sbufGetMutablePtr(buffer);
    uint32_t body_length = ((uint32_t) frame[3] << 8) | frame[4];
    assert(frame[0] == kEncryptionTlsApplicationData && frame[1] == kEncryptionTlsVersionMajor &&
           frame[2] == kEncryptionTlsVersionMinor);
    assert(body_length >= kEncryptionNonceSize + kEncryptionTagSize && body_length <= kEncryptionMaxTlsRecordBody);
    assert(sbufGetLength(buffer) == kEncryptionTlsHeaderSize + body_length);
    uint32_t         ciphertext_length = body_length - kEncryptionNonceSize;
    uint8_t         *nonce             = frame + kEncryptionTlsHeaderSize;
    uint8_t         *ciphertext        = frame + kEncryptionFramePrefixSize;
    size_t           capacity          = sbufGetMaximumWriteableSize(buffer) - kEncryptionFramePrefixSize;
    wcrypto_status_t status            = decryptAead(
        algorithm, ciphertext, capacity, ciphertext, ciphertext_length, frame, kEncryptionTlsHeaderSize, nonce, key);
    if (status == kWCryptoOk)
    {
        sbufShiftRight(buffer, kEncryptionFramePrefixSize);
        sbufSetLength(buffer, ciphertext_length - kEncryptionTagSize);
    }
    return status;
}
