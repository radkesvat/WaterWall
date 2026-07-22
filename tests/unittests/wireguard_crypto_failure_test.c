#include "structure.h"

typedef enum crypto_failure_injection_e
{
    kCryptoFailureNone,
    kCryptoFailureBlake2sInit,
    kCryptoFailureBlake2sOneShot,
    kCryptoFailureX25519,
    kCryptoFailureChaChaEncrypt,
} crypto_failure_injection_t;

static crypto_failure_injection_t crypto_failure_injection;

wcrypto_status_t __real_wCryptoBlake2sInit(wcrypto_blake2s_ctx_t *ctx, size_t outlen, const unsigned char *key,
                                           size_t keylen);
wcrypto_status_t __real_wCryptoBlake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen,
                                      const unsigned char *in, size_t inlen);
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
wcrypto_status_t __wrap_wCryptoBlake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen,
                                      const unsigned char *in, size_t inlen);
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

wcrypto_status_t __wrap_wCryptoBlake2s(unsigned char *out, size_t outlen, const unsigned char *key, size_t keylen,
                                      const unsigned char *in, size_t inlen)
{
    if (crypto_failure_injection == kCryptoFailureBlake2sOneShot)
    {
        if (out != NULL)
        {
            memoryZero(out, outlen);
        }
        return kWCryptoBackendFailed;
    }
    return __real_wCryptoBlake2s(out, outlen, key, keylen, in, inlen);
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
    const bool roles[] = {true, false};

    for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); ++i)
    {
        wireguard_peer_t peer;
        memset(&peer, 0, sizeof(peer));
        memset(&peer.handshake, 0xa5, sizeof(peer.handshake));
        memset(&peer.pending_handshake, 0x5a, sizeof(peer.pending_handshake));
        peer.handshake.valid        = true;
        peer.handshake.initiator    = roles[i];
        peer.handshake.local_index  = 0x11223344U;
        peer.handshake.remote_index = 0x55667788U;

        crypto_failure_injection = kCryptoFailureBlake2sInit;
        require(! wireguardStartSession(&peer, roles[i]), "WireGuard accepted a failed session KDF");
        crypto_failure_injection = kCryptoFailureNone;

        require(isAllZero(&peer.handshake, sizeof(peer.handshake)),
                "failed session KDF retained handshake secrets");
        require(isAllZero(&peer.pending_handshake, sizeof(peer.pending_handshake)),
                "failed session KDF retained pending handshake packet");
        require(isAllZero(&peer.curr_keypair, sizeof(peer.curr_keypair)) &&
                    isAllZero(&peer.prev_keypair, sizeof(peer.prev_keypair)) &&
                    isAllZero(&peer.next_keypair, sizeof(peer.next_keypair)),
                "failed session KDF published a transport keypair");
    }
}

static void testHandshakeResponseFailureClearsPendingState(void)
{
    wireguard_device_t             device;
    wireguard_peer_t               peer;
    message_handshake_response_t   response;

    memset(&device, 0, sizeof(device));
    memset(&peer, 0, sizeof(peer));
    memset(&response, 0, sizeof(response));
    memset(&peer.handshake, 0xa5, sizeof(peer.handshake));
    memset(&peer.pending_handshake, 0x5a, sizeof(peer.pending_handshake));
    peer.handshake.valid     = true;
    peer.handshake.initiator = true;

    crypto_failure_injection = kCryptoFailureX25519;
    require(! wireguardProcessHandshakeResponse(&device, &peer, &response),
            "WireGuard accepted a failed handshake response");
    crypto_failure_injection = kCryptoFailureNone;

    require(isAllZero(&peer.handshake, sizeof(peer.handshake)),
            "failed handshake response retained handshake secrets");
    require(isAllZero(&peer.pending_handshake, sizeof(peer.pending_handshake)),
            "failed handshake response retained pending handshake packet");
}

static void testInitiationConstructionFailureClearsPendingState(void)
{
    wireguard_device_t               device;
    wireguard_peer_t                 peer;
    message_handshake_initiation_t   initiation;

    memset(&device, 0, sizeof(device));
    memset(&peer, 0, sizeof(peer));
    memset(&initiation, 0xa5, sizeof(initiation));
    memset(&peer.pending_handshake, 0x5a, sizeof(peer.pending_handshake));

    crypto_failure_injection = kCryptoFailureBlake2sInit;
    require(! wireguardCreateHandshakeInitiation(&device, &peer, &initiation),
            "WireGuard published a failed handshake initiation");
    crypto_failure_injection = kCryptoFailureNone;

    require(isAllZero(&peer.handshake, sizeof(peer.handshake)),
            "failed initiation construction retained handshake secrets");
    require(isAllZero(&peer.pending_handshake, sizeof(peer.pending_handshake)),
            "failed initiation construction retained pending handshake packet");
    require(isAllZero(&initiation, sizeof(initiation)),
            "failed initiation construction retained partial wire output");
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
        memset(&peer.pending_handshake, 0x5a, sizeof(peer.pending_handshake));
        memset(&response, 0xa5, sizeof(response));

        crypto_failure_injection = failures[i];
        require(! wireguardCreateHandshakeResponse(&device, &peer, &response),
                "WireGuard published a failed handshake response");
        crypto_failure_injection = kCryptoFailureNone;

        require(isAllZero(&peer.handshake, sizeof(peer.handshake)),
                "failed response construction retained handshake secrets");
        require(isAllZero(&peer.pending_handshake, sizeof(peer.pending_handshake)),
                "failed response construction retained pending handshake packet");
        require(isAllZero(&response, sizeof(response)), "failed response construction retained partial wire output");
    }
}

static void testCookieMacFailureDoesNotPublishState(void)
{
    wireguard_device_t               device;
    wireguard_peer_t                 peer;
    message_handshake_initiation_t   initiation;
    message_cookie_reply_t           reply;
    wireguard_pending_handshake_t    pending_before;
    uint8_t                          cookie_before[WIREGUARD_COOKIE_LEN];
    const uint8_t                    source[] = {127, 0, 0, 1, 0x69, 0x46};
    const uint32_t                   cookie_millis_before = 0x12345678U;

    memset(&device, 0, sizeof(device));
    memset(&peer, 0, sizeof(peer));
    memset(&initiation, 0, sizeof(initiation));
    memset(device.label_cookie_key, 0x31, sizeof(device.label_cookie_key));
    memcpy(peer.label_cookie_key, device.label_cookie_key, sizeof(peer.label_cookie_key));

    initiation.type   = MESSAGE_HANDSHAKE_INITIATION;
    initiation.sender = 0x10203040U;
    memset(initiation.mac1, 0x52, sizeof(initiation.mac1));
    require(wireguardStorePendingHandshake(&peer, &initiation, sizeof(initiation)),
            "failed to retain cookie test handshake");
    require(wireguardCreateCookieReply(
                &device, &reply, initiation.mac1, initiation.sender, (uint8_t *) source, sizeof(source)),
            "failed to create cookie test reply");

    memset(peer.cookie, 0x73, sizeof(peer.cookie));
    peer.cookie_millis = cookie_millis_before;
    memcpy(cookie_before, peer.cookie, sizeof(cookie_before));
    pending_before = peer.pending_handshake;

    crypto_failure_injection = kCryptoFailureBlake2sOneShot;
    require(! wireguardProcessCookieMessage(&device, &peer, &reply), "WireGuard accepted a failed cookie mac2");
    crypto_failure_injection = kCryptoFailureNone;

    require(memcmp(peer.cookie, cookie_before, sizeof(cookie_before)) == 0 &&
                peer.cookie_millis == cookie_millis_before,
            "failed cookie mac2 published cookie state");
    require(memcmp(&peer.pending_handshake, &pending_before, sizeof(pending_before)) == 0,
            "failed cookie mac2 modified the pending handshake packet");
}

static void testClearHandshakeStateErasesActiveAndPendingState(void)
{
    wireguard_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    memset(&peer.handshake, 0xa5, sizeof(peer.handshake));
    memset(&peer.pending_handshake, 0x5a, sizeof(peer.pending_handshake));

    wireguardClearHandshakeState(&peer);

    require(isAllZero(&peer.handshake, sizeof(peer.handshake)), "handshake reset retained active handshake state");
    require(isAllZero(&peer.pending_handshake, sizeof(peer.pending_handshake)),
            "handshake reset retained pending packet state");
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
    testHandshakeResponseFailureClearsPendingState();
    testInitiationConstructionFailureClearsPendingState();
    testResponseConstructionFailureInvalidatesHandshake();
    testCookieMacFailureDoesNotPublishState();
    testClearHandshakeStateErasesActiveAndPendingState();
    testDeviceDestroyErasesSecrets();

    globalstateDestroySecureRandom();
    wCryptoGlobalCleanup();
    return 0;
}
