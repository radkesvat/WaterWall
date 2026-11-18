#include "EncryptionCommon/kdf.h"

wcrypto_status_t encryptionDeriveBaseKey(const char *password, size_t password_len, const char *salt, size_t salt_len,
                                         uint32_t iterations, bool packet_mode, uint8_t out_key[32])
{
    assert(password_len > 0 && iterations > 0);
    const unsigned char *password_bytes      = (const unsigned char *) password;
    sha256_hash_t        packet_password_key = {0};
    wcrypto_status_t     status;
    if (packet_mode)
    {
        status = wCryptoSHA256(&packet_password_key, password_bytes, password_len);
        if (status != kWCryptoOk)
            goto cleanup;
    }

    const unsigned char *iteration_key     = packet_mode ? packet_password_key.bytes : password_bytes;
    const size_t         iteration_key_len = packet_mode ? sizeof(packet_password_key.bytes) : password_len;
    status = wCryptoBlake2s(out_key, 32, (const unsigned char *) salt, salt_len, password_bytes, password_len);

    for (uint32_t i = 1; status == kWCryptoOk && i < iterations; ++i)
    {
        uint8_t  iter_block[36];
        uint32_t iter_be = htobe32(i);

        memoryCopy(iter_block, out_key, 32);
        memoryCopy(iter_block + 32, &iter_be, sizeof(iter_be));
        status = wCryptoBlake2s(out_key, 32, iteration_key, iteration_key_len, iter_block, sizeof(iter_block));
        wCryptoZero(iter_block, sizeof(iter_block));
    }

cleanup:
    wCryptoZero(&packet_password_key, sizeof(packet_password_key));
    if (status != kWCryptoOk)
        wCryptoZero(out_key, 32);
    return status;
}
