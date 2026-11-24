/*
 * Covers: wireguard crypto failure; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Cases: testConstructionHashFailure, testSessionKdfFailureInvalidatesHandshake,
 * testHandshakeResponseFailureClearsPendingState, testInitiationConstructionFailureClearsPendingState,
 * testResponseConstructionFailureInvalidatesHandshake, testCookieMacFailureDoesNotPublishState,
 * testClearHandshakeStateErasesActiveAndPendingState, testDeviceDestroyErasesSecrets,
 * testRawDeviceInitialization, testAllowedRangeErrors, testConfiguredKeysRejectMalformedBase64,
 * testConfiguredKeysAcceptCanonicalBase64
 * Checks: Assertion labels include: WireGuard construction-hash failure was not propagated; WireGuard
 * accepted a failed session KDF; failed session KDF retained handshake secrets; failed session KDF
 * retained pending handshake packet
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.wireguard_crypto_failure_unit
 */
#include "WireGuardCommon/engine.h"

#include "loggers/network_logger.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

typedef enum crypto_failure_injection_e
{
    kCryptoFailureNone,
    kCryptoFailureBlake2sInit,
    kCryptoFailureBlake2sOneShot,
    kCryptoFailureX25519,
    kCryptoFailureChaChaEncrypt,
} crypto_failure_injection_t;

static crypto_failure_injection_t crypto_failure_injection;
static bool                       checking_key_decode;

int __real_wwBase64Decode(const char *in, unsigned int inlen, unsigned char *out);
int __wrap_wwBase64Decode(const char *in, unsigned int inlen, unsigned char *out);

int __wrap_wwBase64Decode(const char *in, unsigned int inlen, unsigned char *out)
{
    if (! checking_key_decode)
    {
        return __real_wwBase64Decode(in, inlen, out);
    }

    /* Run an unbounded decode into enough storage to observe its actual output
     * length without corrupting the caller's 32-byte key. The fixed, bounded
     * decoder rejects oversized output before it reaches this legacy helper. */
    unsigned char decoded[BASE64_DECODE_OUT_SIZE(BASE64_ENCODE_OUT_SIZE(WIREGUARD_PRIVATE_KEY_LEN))];
    require(inlen <= BASE64_ENCODE_OUT_SIZE(WIREGUARD_PRIVATE_KEY_LEN), "unexpected key input length");
    const int length = __real_wwBase64Decode(in, inlen, decoded);
    require(length <= WIREGUARD_PRIVATE_KEY_LEN, "WireGuard key decoding writes beyond its 32-byte destination");
    if (length > 0)
    {
        memcpy(out, decoded, (size_t) length);
    }
    wCryptoZero(decoded, sizeof(decoded));
    return length;
}

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

        require(isAllZero(&peer.handshake, sizeof(peer.handshake)), "failed session KDF retained handshake secrets");
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
    wireguard_device_t           device;
    wireguard_peer_t             peer;
    message_handshake_response_t response;

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

    require(isAllZero(&peer.handshake, sizeof(peer.handshake)), "failed handshake response retained handshake secrets");
    require(isAllZero(&peer.pending_handshake, sizeof(peer.pending_handshake)),
            "failed handshake response retained pending handshake packet");
}

static void testInitiationConstructionFailureClearsPendingState(void)
{
    wireguard_device_t             device;
    wireguard_peer_t               peer;
    message_handshake_initiation_t initiation;

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
    require(isAllZero(&initiation, sizeof(initiation)), "failed initiation construction retained partial wire output");
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
        wireguard_peer_t expected = peer;
        memset(&expected.handshake, 0, sizeof(expected.handshake));
        memset(&expected.pending_handshake, 0, sizeof(expected.pending_handshake));

        crypto_failure_injection = failures[i];
        require(! wireguardCreateHandshakeResponse(&device, &peer, &response),
                "WireGuard published a failed handshake response");
        crypto_failure_injection = kCryptoFailureNone;

        require(isAllZero(&peer.handshake, sizeof(peer.handshake)),
                "failed response construction retained handshake secrets");
        require(isAllZero(&peer.pending_handshake, sizeof(peer.pending_handshake)),
                "failed response construction retained pending handshake packet");
        require(isAllZero(&response, sizeof(response)), "failed response construction retained partial wire output");
        require(memcmp(&peer, &expected, sizeof(peer)) == 0,
                "failed response erasure changed bytes outside the handshake and pending state");
    }
}

static void testCookieMacFailureDoesNotPublishState(void)
{
    wireguard_device_t             device;
    wireguard_peer_t               peer;
    message_handshake_initiation_t initiation;
    message_cookie_reply_t         reply;
    wireguard_pending_handshake_t  pending_before;
    uint8_t                        cookie_before[WIREGUARD_COOKIE_LEN];
    const uint8_t                  source[]             = {127, 0, 0, 1, 0x69, 0x46};
    const uint32_t                 cookie_millis_before = 0x12345678U;

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
    wireguard_device_t device = {0};
    memset(device.private_key, 0xa5, sizeof(device.private_key));
    memset(device.cookie_secret, 0xa5, sizeof(device.cookie_secret));
    memset(device.label_cookie_key, 0xa5, sizeof(device.label_cookie_key));
    memset(device.label_mac1_key, 0xa5, sizeof(device.label_mac1_key));
    wireguardDeviceDestroy(&device);
    require(isAllZero(&device, sizeof(device)), "WireGuard device destruction retained secret state");
}

static const char private_key_base64[] = "0MHoX6RogAEFxKF7c5E84tA1Qy3l9u8IzJfgcVt4B2Y=";
static const char public_key_base64[]  = "GnRcOavdc180YrXak138cZxWlMoEUZL0Mg/ZyWhLBgo=";

static void testRawDeviceInitialization(void)
{
    /* Alice's X25519 key pair from RFC 7748, section 6.1. */
    const uint8_t key[WIREGUARD_PRIVATE_KEY_LEN] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const uint8_t expected_public[WIREGUARD_PUBLIC_KEY_LEN] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    };
    wireguard_device_t device;
    memset(&device, 0xa5, sizeof(device));
    require(wireguardDeviceInit(&device, key) && device.valid && device.store == NULL && device.peer_count == 0 &&
                device.processing_depth == 0,
            "raw device initialization did not start with an empty peer store");
    require(memcmp(device.public_key, expected_public, sizeof(expected_public)) == 0,
            "raw device initialization produced the wrong public key for separate input");
    wireguardDeviceDestroy(&device);

    memcpy(device.private_key, key, sizeof(key));
    require(wireguardDeviceInit(&device, device.private_key) &&
                memcmp(device.public_key, expected_public, sizeof(expected_public)) == 0,
            "raw device initialization produced the wrong public key for in-device input");
    wireguardDeviceDestroy(&device);

    memset(&device, 0xa5, sizeof(device));
    crypto_failure_injection = kCryptoFailureBlake2sInit;
    require(! wireguardDeviceInit(&device, key) && isAllZero(&device, sizeof(device)),
            "failed raw device initialization retained partial state");
    crypto_failure_injection = kCryptoFailureNone;
    wireguardDeviceDestroy(&device);
}

static void testAllowedRangeErrors(void)
{
    wireguard_device_t device;
    require(wireguardCommonInit(&device, private_key_base64, NULL, (wireguard_callbacks_t) {0}),
            "range test device initialization failed");
    wireguard_peer_init_data_t peer;
    wireguardifPeerInit(&peer);
    peer.public_key = (const uint8_t *) public_key_base64;
    IP_ADDR4(&peer.allowed_ip, 192, 0, 2, 0);
    ip_addr_t invalid_masks[2];
    IP_ADDR4(&invalid_masks[0], 255, 0, 255, 0);
    ipAddrSetAny(true, &invalid_masks[1]);
    size_t id;
    for (size_t i = 0; i < ARRAY_SIZE(invalid_masks); ++i)
    {
        peer.allowed_mask = invalid_masks[i];
        require(wireguardifAddPeer(&device, &peer, &id) == ERR_ARG && id == WIREGUARDIF_INVALID_INDEX &&
                    device.peer_count == 0 && wireguardCommonPeerForIp(&device, &peer.allowed_ip) == NULL,
                "invalid first range did not reject and roll back peer creation");
    }
    IP_ADDR4(&peer.allowed_mask, 255, 255, 255, 255);
    require(wireguardifAddPeer(&device, &peer, &id) == ERR_OK, "valid first range failed");
    for (size_t i = 0; i < ARRAY_SIZE(invalid_masks); ++i)
        require(wireguardifAddAllowedIp(&device, id, &peer.allowed_ip, &invalid_masks[i]) == ERR_ARG,
                "invalid additional range reported capacity exhaustion");
    ip_addr_t address;
    for (unsigned i = 1; i < WIREGUARD_MAX_SRC_IPS; ++i)
    {
        IP_ADDR4(&address, 192, 0, 2, i);
        require(wireguardifAddAllowedIp(&device, id, &address, &peer.allowed_mask) == ERR_OK,
                "valid range failed before per-peer capacity");
    }
    IP_ADDR4(&address, 192, 0, 2, WIREGUARD_MAX_SRC_IPS);
    require(wireguardifAddAllowedIp(&device, id, &address, &peer.allowed_mask) == ERR_MEM &&
                wireguardifAddAllowedIp(&device, id, &address, &invalid_masks[0]) == ERR_ARG &&
                wireguardifAddAllowedIp(&device, id, &peer.allowed_ip, &peer.allowed_mask) == ERR_OK &&
                wireguardCommonPeerForIp(&device, &address) == NULL,
            "full range table lost error or duplicate semantics");
    wireguardDeviceDestroy(&device);
}

static cJSON *configuredPeer(const char *public_key, const char *preshared_key)
{
    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL && cJSON_AddStringToObject(settings, "publickey", public_key) != NULL &&
                cJSON_AddStringToObject(settings, "allowedips", "10.1.0.1/32") != NULL &&
                (preshared_key == NULL || cJSON_AddStringToObject(settings, "presharedkey", preshared_key) != NULL),
            "key configuration fixture failed");
    return settings;
}

static void testConfiguredKeysRejectMalformedBase64(void)
{
    char invalid[4][sizeof(public_key_base64)];
    memset(invalid[0], 'A', sizeof(invalid[0]) - 1);
    invalid[0][sizeof(invalid[0]) - 1] = '\0'; // 44 alphabet characters decode to 33 bytes.
    for (size_t i = 1; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        memcpy(invalid[i], public_key_base64, sizeof(public_key_base64));
    }
    invalid[1][42] = 'p'; // Same decoded key as the valid 'o', but with nonzero padding bits.
    memset(invalid[2] + 41, '=', 3);
    invalid[3][42] = '!';

    checking_key_decode = true;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        wireguard_device_t device;
        memset(&device, 0xa5, sizeof(device));
        require(! wireguardCommonInit(&device, invalid[i], NULL, (wireguard_callbacks_t) {0}) && ! device.valid &&
                    device.store == NULL && device.processing_depth == 0,
                "WireGuard accepted a malformed private key");
        wireguardDeviceDestroy(&device);
        require(wireguardCommonInit(&device, private_key_base64, NULL, (wireguard_callbacks_t) {0}),
                "valid private key failed after malformed key rejection");

        size_t index    = WIREGUARDIF_INVALID_INDEX;
        cJSON *settings = configuredPeer(invalid[i], NULL);
        require(! wireguardCommonAddConfiguredPeer(&device, settings, &index),
                "WireGuard accepted a malformed configured public key");
        cJSON_Delete(settings);

        settings = configuredPeer(public_key_base64, invalid[i]);
        require(! wireguardCommonAddConfiguredPeer(&device, settings, &index),
                "WireGuard accepted a malformed preshared key");
        cJSON_Delete(settings);

        wireguard_peer_init_data_t peer;
        wireguardifPeerInit(&peer);
        peer.public_key = (const uint8_t *) invalid[i];
        require(wireguardifAddPeer(&device, &peer, &index) == ERR_ARG,
                "WireGuard peer helper accepted a malformed public key");
        require(device.peer_count == 0 && device.first_peer == NULL, "malformed key published a peer");
        wireguardDeviceDestroy(&device);
    }
    checking_key_decode = false;
}

static void testConfiguredKeysAcceptCanonicalBase64(void)
{
    wireguard_device_t device = {0};
    uint8_t            preshared[WIREGUARD_SESSION_KEY_LEN];
    char               encoded[BASE64_ENCODE_OUT_SIZE(sizeof(preshared)) + 1] = {0};
    for (size_t i = 0; i < sizeof(preshared); ++i)
    {
        preshared[i] = (uint8_t) (i + 1);
    }
    require(wwBase64Encode(preshared, sizeof(preshared), encoded) == sizeof(encoded) - 1,
            "preshared key encoding failed");

    checking_key_decode = true;
    require(wireguardCommonInit(&device, private_key_base64, NULL, (wireguard_callbacks_t) {0}),
            "WireGuard rejected a canonical private key");
    size_t  index    = WIREGUARDIF_INVALID_INDEX;
    cJSON  *settings = configuredPeer(public_key_base64, encoded);
    require(wireguardCommonAddConfiguredPeer(&device, settings, &index) &&
                peerLookupByPeerIndex(&device, index) != NULL &&
                memcmp(peerLookupByPeerIndex(&device, index)->preshared_key, preshared, sizeof(preshared)) == 0,
            "WireGuard rejected or changed canonical configured keys");
    cJSON_Delete(settings);
    require(wireguardifRemovePeer(&device, index) == ERR_OK, "configured peer removal failed");

    wireguard_peer_init_data_t peer;
    wireguardifPeerInit(&peer);
    peer.public_key    = (const uint8_t *) public_key_base64;
    peer.preshared_key = preshared;
    require(wireguardifAddPeer(&device, &peer, &index) == ERR_OK && peerLookupByPeerIndex(&device, index) != NULL,
            "WireGuard peer helper rejected a canonical public key");
    wireguardDeviceDestroy(&device);
    checking_key_decode = false;
    wCryptoZero(preshared, sizeof(preshared));
    wCryptoZero(encoded, sizeof(encoded));
}

int main(void)
{
    testCaseSet("wireguard_crypto_failure_test");
    require(globalstateInitializeSecureRandom(), "secure random initialization failed");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();
    require(wCryptoGlobalInit() == kWCryptoOk, "crypto global initialization failed");
    require(createNetworkLogger(NULL, false) != NULL, "logger setup failed");

    testConstructionHashFailure();
    testSessionKdfFailureInvalidatesHandshake();
    testHandshakeResponseFailureClearsPendingState();
    testInitiationConstructionFailureClearsPendingState();
    testResponseConstructionFailureInvalidatesHandshake();
    testCookieMacFailureDoesNotPublishState();
    testClearHandshakeStateErasesActiveAndPendingState();
    testDeviceDestroyErasesSecrets();
    testRawDeviceInitialization();
    testAllowedRangeErrors();
    testConfiguredKeysRejectMalformedBase64();
    testConfiguredKeysAcceptCanonicalBase64();

    networkloggerDestroy();
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
