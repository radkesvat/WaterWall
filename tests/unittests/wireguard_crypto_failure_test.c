#include "structure.h"

typedef enum crypto_failure_injection_e
{
    kCryptoFailureNone,
    kCryptoFailureBlake2sInit,
    kCryptoFailureX25519,
    kCryptoFailureChaChaEncrypt,
} crypto_failure_injection_t;

static crypto_failure_injection_t crypto_failure_injection;

wcrypto_status_t __real_wCryptoBlake2sInit(wcrypto_blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key,
                                           size_t keylen);
wcrypto_status_t __real_wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE]);
wcrypto_status_t __real_wCryptoChaCha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                       const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);
wcrypto_status_t __wrap_wCryptoBlake2sInit(wcrypto_blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key,
                                           size_t keylen);
wcrypto_status_t __wrap_wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE]);
wcrypto_status_t __wrap_wCryptoChaCha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                       const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE]);

wcrypto_status_t __wrap_wCryptoBlake2sInit(wcrypto_blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key,
                                           size_t keylen)
{
    if (crypto_failure_injection == kCryptoFailureBlake2sInit)
    {
        if (ctx != NULL)
        {
            wCryptoBlake2sDestroy(ctx);
        }
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoBlake2sInit(ctx, outlen, key, keylen);
}

wcrypto_status_t __wrap_wCryptoX25519(unsigned char       out[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char scalar[WCRYPTO_X25519_KEY_SIZE],
                                      const unsigned char point[WCRYPTO_X25519_KEY_SIZE])
{
    if (crypto_failure_injection == kCryptoFailureX25519)
    {
        if (out != NULL)
        {
            memoryZero(out, WCRYPTO_X25519_KEY_SIZE);
        }
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoX25519(out, scalar, point);
}

wcrypto_status_t __wrap_wCryptoChaCha20Poly1305Encrypt(unsigned char *dst, size_t dst_capacity,
                                                       const unsigned char *src, size_t src_len,
                                                       const unsigned char *ad, size_t ad_len,
                                                       const unsigned char nonce[WCRYPTO_CHACHA20POLY1305_NONCE_SIZE],
                                                       const unsigned char key[WCRYPTO_CHACHA20POLY1305_KEY_SIZE])
{
    if (crypto_failure_injection == kCryptoFailureChaChaEncrypt)
    {
        if (dst != NULL && src_len <= SIZE_MAX - WCRYPTO_AEAD_TAG_SIZE &&
            dst_capacity >= src_len + WCRYPTO_AEAD_TAG_SIZE)
        {
            memoryZero(dst, src_len + WCRYPTO_AEAD_TAG_SIZE);
        }
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoChaCha20Poly1305Encrypt(dst, dst_capacity, src, src_len, ad, ad_len, nonce, key);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
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

static void testConstructionHashFailure(void)
{
    crypto_failure_injection = kCryptoFailureBlake2sInit;
    require(wireguardInit() == kWCryptoBackendFailed, "WireGuard construction-hash failure was not propagated");
    crypto_failure_injection = kCryptoFailureNone;
    require(wireguardInit() == kWCryptoOk, "WireGuard construction hashes could not be initialized after failure");
}

static void testSessionKdfFailureInvalidatesHandshake(void)
{
    wireguard_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    memset(&peer.handshake, 0xa5, sizeof(peer.handshake));
    peer.handshake.valid        = true;
    peer.handshake.initiator    = true;
    peer.handshake.local_index  = 0x11223344U;
    peer.handshake.remote_index = 0x55667788U;

    crypto_failure_injection = kCryptoFailureBlake2sInit;
    require(! wireguardStartSession(&peer, true), "WireGuard accepted a failed session KDF");
    crypto_failure_injection = kCryptoFailureNone;

    require(isAllZero(&peer.handshake, sizeof(peer.handshake)), "failed session KDF retained handshake secrets");
    require(isAllZero(&peer.curr_keypair, sizeof(peer.curr_keypair)) &&
                isAllZero(&peer.prev_keypair, sizeof(peer.prev_keypair)) &&
                isAllZero(&peer.next_keypair, sizeof(peer.next_keypair)),
            "failed session KDF published a transport keypair");
}

static void prepareResponderHandshake(wireguard_peer_t *peer)
{
    static const uint8_t basepoint[WCRYPTO_X25519_KEY_SIZE] = {9};
    uint8_t              remote_private[WCRYPTO_X25519_KEY_SIZE];
    uint8_t              peer_private[WCRYPTO_X25519_KEY_SIZE];

    memset(peer, 0, sizeof(*peer));
    for (size_t i = 0; i < sizeof(remote_private); ++i)
    {
        remote_private[i] = (uint8_t) (i + 1U);
        peer_private[i]   = (uint8_t) (0x80U + i);
    }
    require(wCryptoX25519(peer->handshake.remote_ephemeral, remote_private, basepoint) == kWCryptoOk &&
                wCryptoX25519(peer->public_key, peer_private, basepoint) == kWCryptoOk,
            "failed to prepare responder public keys");
    memset(peer->handshake.hash, 0x36, sizeof(peer->handshake.hash));
    memset(peer->handshake.chaining_key, 0x5c, sizeof(peer->handshake.chaining_key));
    memset(peer->preshared_key, 0x42, sizeof(peer->preshared_key));
    peer->handshake.valid        = true;
    peer->handshake.initiator    = false;
    peer->handshake.remote_index = 0x10203040U;
    wCryptoZero(remote_private, sizeof(remote_private));
    wCryptoZero(peer_private, sizeof(peer_private));
}

static void testResponseConstructionFailureInvalidatesHandshake(void)
{
    const crypto_failure_injection_t failures[] = {
        kCryptoFailureX25519,
        kCryptoFailureChaChaEncrypt,
    };

    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i)
    {
        wireguard_device_t           device;
        wireguard_peer_t             peer;
        message_handshake_response_t response;
        memset(&device, 0, sizeof(device));
        prepareResponderHandshake(&peer);
        memset(&response, 0xa5, sizeof(response));

        crypto_failure_injection = failures[i];
        require(! wireguardCreateHandshakeResponse(&device, &peer, &response),
                "WireGuard published a failed handshake response");
        crypto_failure_injection = kCryptoFailureNone;

        require(isAllZero(&peer.handshake, sizeof(peer.handshake)),
                "failed response construction retained handshake secrets");
        require(isAllZero(&response, sizeof(response)), "failed response construction retained partial wire output");
    }
}

static void testDeviceDestroyErasesSecrets(void)
{
    wireguard_device_t device;
    memset(&device, 0xa5, sizeof(device));
    wireguardDeviceDestroy(&device);
    require(isAllZero(&device, sizeof(device)), "WireGuard device destruction retained secret state");
}

int main(void)
{
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization failed");
    require(globalstateInitializeSecureRandom(), "secure random initialization failed");

    testConstructionHashFailure();
    testSessionKdfFailureInvalidatesHandshake();
    testResponseConstructionFailureInvalidatesHandshake();
    testDeviceDestroyErasesSecrets();

    globalstateDestroySecureRandom();
    wCryptoGlobalCleanup();
    return 0;
}
