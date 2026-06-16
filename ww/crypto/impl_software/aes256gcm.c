#include "private/crypto_backends.h"

int wCryptoSoftwareAES256GCMIsAvailable(void)
{
    return 0;
}

int wCryptoSoftwareAES256GCMEncrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                    const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                    const unsigned char *key)
{
    discard dst;
    discard src;
    discard src_len;
    discard ad;
    discard ad_len;
    discard nonce;
    discard key;
    return -1;
}

int wCryptoSoftwareAES256GCMDecrypt(unsigned char *dst, const unsigned char *src, size_t src_len,
                                    const unsigned char *ad, size_t ad_len, const unsigned char *nonce,
                                    const unsigned char *key)
{
    discard dst;
    discard src;
    discard src_len;
    discard ad;
    discard ad_len;
    discard nonce;
    discard key;
    return -1;
}
