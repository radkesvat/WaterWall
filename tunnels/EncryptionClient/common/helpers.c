#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelstateDestroy(encryptionclient_tstate_t *ts)
{
    memoryZero(ts->key, sizeof(ts->key));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

int encryptionclientEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                                const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                const unsigned char *key)
{
    if (algorithm == kEncryptionAlgorithmChaCha20Poly1305)
    {
        return chacha20poly1305Encrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kEncryptionAlgorithmAes256Gcm)
    {
        return aes256gcmEncrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    return -1;
}

int encryptionclientDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
                                const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                const unsigned char *key)
{
    if (algorithm == kEncryptionAlgorithmChaCha20Poly1305)
    {
        return chacha20poly1305Decrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    if (algorithm == kEncryptionAlgorithmAes256Gcm)
    {
        return aes256gcmDecrypt(dst, src, src_len, ad, ad_len, nonce, key);
    }

    return -1;
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
