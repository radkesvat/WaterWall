#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelstateDestroy(encryptionclient_tstate_t *ts)
{
    memoryZero(ts->key, sizeof(ts->key));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

wcrypto_status_t encryptionclientEncryptAead(uint32_t algorithm, unsigned char *dst, size_t dst_capacity,
                                             const unsigned char *src, size_t src_len, const unsigned char *ad,
                                             size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
    if (algorithm == kEncryptionAlgorithmChaCha20Poly1305)
    {
        return wCryptoChaCha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kEncryptionAlgorithmAes256Gcm)
    {
        return wCryptoAes256GcmEncrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    }

    return kWCryptoUnavailable;
}

wcrypto_status_t encryptionclientDecryptAead(uint32_t algorithm, unsigned char *dst, size_t dst_capacity,
                                             const unsigned char *src, size_t src_len, const unsigned char *ad,
                                             size_t ad_len, const unsigned char *nonce, const unsigned char *key)
{
    if (algorithm == kEncryptionAlgorithmChaCha20Poly1305)
    {
        return wCryptoChaCha20Poly1305Decrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kEncryptionAlgorithmAes256Gcm)
    {
        return wCryptoAes256GcmDecrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
    }

    return kWCryptoUnavailable;
}

void encryptionclientCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    encryptionclient_lstate_t *ls = lineGetState(l, t);
    encryptionclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
