#include "structure.h"

#include "loggers/network_logger.h"


void encryptionserverTunnelstateDestroy(encryptionserver_tstate_t *ts)
{
    wCryptoZero(ts->key, sizeof(ts->key));
    memoryZeroAligned32(ts, sizeof(*ts));
}

int encryptionserverEncryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
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

int encryptionserverDecryptAead(uint32_t algorithm, unsigned char *dst, const unsigned char *src, size_t src_len,
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

void encryptionserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    if (! lineIsAlive(l))
    {
        return;
    }

    lineLock(l);

    encryptionserver_lstate_t *ls = lineGetState(l, t);
    bool send_next = ! ls->next_finished;
    bool send_prev = ! ls->prev_finished;

    ls->next_finished = true;
    ls->prev_finished = true;
    encryptionserverLinestateDestroy(ls);

    if (send_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (send_prev && lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}
