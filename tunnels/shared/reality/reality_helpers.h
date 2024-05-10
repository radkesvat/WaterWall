#pragma once
#include "buffer_pool.h"
#include "frand.h"
#include "openssl_globals.h" /* These helpers depened on openssl */
#include "shiftbuffer.h"
#include <assert.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

enum reality_consts
{
    kEncryptionBlockSize  = 16,
    kSignPasswordLen      = kEncryptionBlockSize,
    kIVlen                = 16, // iv size for *most* modes is the same as the block size. For AES this is 128 bits
    kSignLen              = (224 / 8),
    kTLSVersion12         = 0x0303,
    kTLS12ApplicationData = 0x17,
    kTLSHeaderlen         = 1 + 2 + 2,
};

static bool verifyMessage(shift_buffer_t *buf, EVP_MD *msg_digest, EVP_MD_CTX *sign_context, EVP_PKEY *sign_key)
{
    int     rc = EVP_DigestSignInit(sign_context, NULL, msg_digest, NULL, sign_key);
    uint8_t expect[EVP_MAX_MD_SIZE];
    memcpy(expect, rawBuf(buf), kSignLen);
    shiftr(buf, kSignLen);
    assert(rc == 1);
    rc = EVP_DigestSignUpdate(sign_context, rawBuf(buf), bufLen(buf));
    assert(rc == 1);
    uint8_t buff[EVP_MAX_MD_SIZE];
    size_t  size = sizeof(buff);
    rc           = EVP_DigestSignFinal(sign_context, buff, &size);
    assert(rc == 1);
    assert(size == kSignLen);
    return ! ! CRYPTO_memcmp(expect, buff, size);
}

static void signMessage(shift_buffer_t *buf, EVP_MD *msg_digest, EVP_MD_CTX *sign_context, EVP_PKEY *sign_key)
{
    int rc = EVP_DigestSignInit(sign_context, NULL, msg_digest, NULL, sign_key);
    assert(rc == 1);
    rc = EVP_DigestSignUpdate(sign_context, rawBuf(buf), bufLen(buf));
    assert(rc == 1);
    size_t req = 0;
    rc         = EVP_DigestSignFinal(sign_context, NULL, &req);
    assert(rc == 1);
    shiftl(buf, req);
    size_t slen = 0;
    rc          = EVP_DigestSignFinal(sign_context, rawBufMut(buf), &slen);
    assert(rc == 1);
    assert((req == slen) && (req == kSignLen));
}

static shift_buffer_t *genericDecrypt(shift_buffer_t *in, EVP_CIPHER_CTX *decryption_context, char *password,
                                      buffer_pool_t *pool)
{
    shift_buffer_t *out          = popBuffer(pool);
    uint16_t        input_length = bufLen(in);

    uint8_t iv[kIVlen];
    memcpy(iv, rawBuf(in), kIVlen);
    shiftr(in, kIVlen);

    EVP_DecryptInit_ex(decryption_context, EVP_aes_128_cbc(), NULL, (const uint8_t *) password, (const uint8_t *) iv);

    reserveBufSpace(out, input_length + (2 * kEncryptionBlockSize));
    int out_len = 0;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(decryption_context, rawBufMut(out), &out_len, rawBuf(in), input_length))
    {
        printSSLErrorAndAbort();
    }
    setLen(out, out_len);

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(decryption_context, rawBufMut(out) + out_len, &out_len))
    {
        printSSLErrorAndAbort();
    }
    reuseBuffer(pool, in);

    setLen(out, bufLen(out) + out_len);
    return out;
}
static shift_buffer_t *genericEncrypt(shift_buffer_t *in, EVP_CIPHER_CTX *encryption_context, char *password,
                                      buffer_pool_t *pool)
{
    shift_buffer_t *out          = popBuffer(pool);
    int             input_length = (int) bufLen(in);

    uint8_t iv[kIVlen];
    for (int i; i < kIVlen / sizeof(uint32_t); i++)
    {
        ((uint32_t *) iv)[i] = fastRand();
    }

    EVP_EncryptInit_ex(encryption_context, EVP_aes_128_cbc(), NULL, (const uint8_t *) password, (const uint8_t *) iv);

    reserveBufSpace(out, input_length + (input_length % kEncryptionBlockSize));
    int out_len = 0;

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(encryption_context, rawBufMut(out), &out_len, rawBuf(in), input_length))
    {
        printSSLErrorAndAbort();
    }

    setLen(out, bufLen(out) + out_len);

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(encryption_context, rawBufMut(out) + out_len, &out_len))
    {
        printSSLErrorAndAbort();
    }
    reuseBuffer(pool, in);
    setLen(out, bufLen(out) + out_len);

    shiftl(out, kIVlen);
    memcpy(rawBufMut(out), iv, kIVlen);
    return out;
}

static void appendTlsHeader(shift_buffer_t *buf)
{
    unsigned int data_length = bufLen(buf);
    assert(data_length < (1U << 16));

    shiftl(buf, sizeof(uint16_t));
    writeUI16(buf, (uint16_t) data_length);

    shiftl(buf, sizeof(uint16_t));
    writeUI16(buf, kTLSVersion12);

    shiftl(buf, sizeof(uint8_t));
    writeUI8(buf, kTLS12ApplicationData);
}

static bool isTlsData(shift_buffer_t *buf)
{
    return bufLen(buf) >= kTLSHeaderlen && ((uint8_t *) rawBuf(buf))[0] == kTLS12ApplicationData &&
           *((uint16_t *) (rawBuf(buf) + 1)) == kTLSVersion12 && *((uint16_t *) (rawBuf(buf) + 1)) > 0x0;
}