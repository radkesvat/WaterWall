#include "structure.h"

#ifdef COMPILER_MSVC

#pragma warning(disable : 4295) // array is too small to include a terminating null character (IT IS OK)
#pragma warning(disable : 4703) // potentially uninitialized local pointer variable (IT IS OK)
#pragma warning(disable : 4701) // potentially uninitialized local variable (IT IS OK)

#endif

// For HMAC calculation
#define WIREGUARD_BLAKE2S_BLOCK_SIZE (64)

// 5.4 Messages
// Constants
static const uint8_t CONSTRUCTION[37] = {
    'N', 'o', 'i', 's', 'e', '_', 'I', 'K', 'p', 's', 'k', '2', '_', '2', '5', '5', '1', '9', '_',
    'C', 'h', 'a', 'C', 'h', 'a', 'P', 'o', 'l', 'y', '_', 'B', 'L', 'A', 'K', 'E', '2', 's'}; // The UTF-8 string
                                                                                               // literal
                                                                                               // "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s",
                                                                                               // 37 bytes of output

static const uint8_t IDENTIFIER[34] = {'W', 'i', 'r', 'e', 'G', 'u', 'a', 'r', 'd', ' ', 'v', '1',
                                       ' ', 'z', 'x', '2', 'c', '4', ' ', 'J', 'a', 's', 'o', 'n',
                                       '@', 'z', 'x', '2', 'c', '4', '.', 'c', 'o', 'm'}; // The UTF-8 string literal
                                                                                          // "WireGuard v1 zx2c4
                                                                                          // Jason@zx2c4.com", 34 bytes
                                                                                          // of output

static const uint8_t LABEL_MAC1[8] = {
    'm', 'a', 'c', '1', '-', '-', '-', '-'}; // Label-Mac1 The UTF-8 string literal "mac1----", 8 bytes of output.

static const uint8_t LABEL_COOKIE[8] = {
    'c', 'o', 'o', 'k', 'i', 'e', '-', '-'}; // Label-Cookie The UTF-8 string literal "cookie--", 8 bytes of output

// Calculated in wireguardInit
static uint8_t construction_hash[WIREGUARD_HASH_LEN];
static uint8_t identifier_hash[WIREGUARD_HASH_LEN];

static void wireguard12byteTai64(uint8_t *output)
{
    // See https://cr.yp.to/libtai/tai64.html
    // 64 bit seconds from 1970 = 8 bytes
    // 32 bit nano seconds from current second

    const unsigned long long now_us = getTimeOfDayUS();

    // Split into seconds offset + nanos
    uint64_t seconds = 0x400000000000000aULL + (uint64_t) (now_us / 1000000ULL);
    uint32_t nanos   = (uint32_t) ((now_us % 1000000ULL) * 1000ULL);
    U64TO8_BIG(output + 0, seconds);
    U32TO8_BIG(output + 8, nanos);
}

static WCRYPTO_MUST_USE wcrypto_status_t chacha20poly1305EncryptWrapper(unsigned char *dst, size_t dst_capacity,
                                                                        const unsigned char *src, size_t srclen,
                                                                        const unsigned char *ad, size_t adlen,
                                                                        uint64_t nonce, const unsigned char *key)
{
    uint8_t wireguard_nonce[12] = {0};
    U64TO8_LITTLE(wireguard_nonce + 4, nonce);
    wcrypto_status_t status =
        wCryptoChaCha20Poly1305Encrypt(dst, dst_capacity, src, srclen, ad, adlen, wireguard_nonce, key);
    return status;
}

static WCRYPTO_MUST_USE wcrypto_status_t chacha20poly1305DecryptWrapper(unsigned char *dst, size_t dst_capacity,
                                                                        const unsigned char *src, size_t srclen,
                                                                        const unsigned char *ad, size_t adlen,
                                                                        uint64_t nonce, const unsigned char *key)
{
    uint8_t wireguard_nonce[12] = {0};
    U64TO8_LITTLE(wireguard_nonce + 4, nonce);
    wcrypto_status_t status =
        wCryptoChaCha20Poly1305Decrypt(dst, dst_capacity, src, srclen, ad, adlen, wireguard_nonce, key);
    return status;
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardBlake2sTwo(uint8_t *dst, size_t dst_len, const uint8_t *key,
                                                             size_t key_len, const void *first, size_t first_len,
                                                             const void *second, size_t second_len)
{
    wcrypto_blake2s_ctx_t ctx    = WCRYPTO_BLAKE2S_CONTEXT_INITIALIZER;
    wcrypto_status_t      status = wCryptoBlake2sInit(&ctx, dst_len, key, key_len);
    if (status == kWCryptoOk && first_len != 0)
    {
        status = wCryptoBlake2sUpdate(&ctx, first, first_len);
    }
    if (status == kWCryptoOk && second_len != 0)
    {
        status = wCryptoBlake2sUpdate(&ctx, second, second_len);
    }
    if (status == kWCryptoOk)
    {
        status = wCryptoBlake2sFinal(&ctx, dst, dst_len);
    }
    else
    {
        wCryptoBlake2sDestroy(&ctx);
    }
    if (status != kWCryptoOk)
    {
        wCryptoZero(dst, dst_len);
    }
    return status;
}

wcrypto_status_t wireguardInit(void)
{
    wcrypto_status_t status = wireguardBlake2sTwo(
        construction_hash, WIREGUARD_HASH_LEN, NULL, 0, CONSTRUCTION, sizeof(CONSTRUCTION), NULL, 0);
    if (status == kWCryptoOk)
    {
        status = wireguardBlake2sTwo(identifier_hash,
                                     WIREGUARD_HASH_LEN,
                                     NULL,
                                     0,
                                     construction_hash,
                                     sizeof(construction_hash),
                                     IDENTIFIER,
                                     sizeof(IDENTIFIER));
    }
    if (status != kWCryptoOk)
    {
        memoryZero(construction_hash, sizeof(construction_hash));
        memoryZero(identifier_hash, sizeof(identifier_hash));
    }
    return status;
}

wireguard_peer_t *peerAlloc(wireguard_device_t *device)
{
    wireguard_peer_t *result = NULL;
    wireguard_peer_t *tmp;
    int               x;
    for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
    {
        tmp = &device->peers[x];
        if (! tmp->valid)
        {
            result = tmp;
            break;
        }
    }
    return result;
}

wireguard_peer_t *peerLookupByPubkey(wireguard_device_t *device, uint8_t *public_key)
{
    wireguard_peer_t *result = NULL;
    wireguard_peer_t *tmp;
    int               x;
    for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
    {
        tmp = &device->peers[x];
        if (tmp->valid)
        {
            if (memcmp(tmp->public_key, public_key, WIREGUARD_PUBLIC_KEY_LEN) == 0)
            {
                result = tmp;
                break;
            }
        }
    }
    return result;
}

uint8_t wireguardPeerIndex(wireguard_device_t *device, wireguard_peer_t *peer)
{
    uint8_t result = 0xFF;
    uint8_t x;
    for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
    {
        if (peer == &device->peers[x])
        {
            result = x;
            break;
        }
    }
    return result;
}

wireguard_peer_t *peerLookupByPeerIndex(wireguard_device_t *device, uint8_t peer_index)
{
    wireguard_peer_t *result = NULL;
    if (peer_index < WIREGUARD_MAX_PEERS)
    {
        if (device->peers[peer_index].valid)
        {
            result = &device->peers[peer_index];
        }
    }
    return result;
}

wireguard_peer_t *peerLookupByReceiver(wireguard_device_t *device, uint32_t receiver)
{
    wireguard_peer_t *result = NULL;
    wireguard_peer_t *tmp;
    int               x;
    for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
    {
        tmp = &device->peers[x];
        if (tmp->valid)
        {
            if ((tmp->curr_keypair.valid && (tmp->curr_keypair.local_index == receiver)) ||
                (tmp->next_keypair.valid && (tmp->next_keypair.local_index == receiver)) ||
                (tmp->prev_keypair.valid && (tmp->prev_keypair.local_index == receiver)))
            {
                result = tmp;
                break;
            }
        }
    }
    return result;
}

wireguard_peer_t *peerLookupByHandshake(wireguard_device_t *device, uint32_t receiver)
{
    wireguard_peer_t *result = NULL;
    wireguard_peer_t *tmp;
    int               x;
    for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
    {
        tmp = &device->peers[x];
        if (tmp->valid)
        {
            if (tmp->handshake.valid && tmp->handshake.initiator && (tmp->handshake.local_index == receiver))
            {
                result = tmp;
                break;
            }
        }
    }
    return result;
}

bool wireguardExpired(uint32_t created_millis, uint32_t valid_seconds)
{
    uint32_t diff = getTickMS() - created_millis;
    return (diff >= (valid_seconds * 1000));
}

static bool generateCookieSecret(wireguard_device_t *device)
{
    uint8_t secret[WIREGUARD_HASH_LEN];
    if (UNLIKELY(! secureRandomBytes(secret, sizeof(secret))))
    {
        wCryptoZero(secret, sizeof(secret));
        return false;
    }

    memoryCopy(device->cookie_secret, secret, sizeof(secret));
    wCryptoZero(secret, sizeof(secret));
    device->cookie_secret_millis = getTickMS();
    return true;
}

static bool generatePeerCookie(wireguard_device_t *device, uint8_t *cookie, uint8_t *source_addr_port,
                               size_t source_length)
{
    if (wireguardExpired(device->cookie_secret_millis, COOKIE_SECRET_MAX_AGE))
    {
        // Generate new random bytes
        if (UNLIKELY(! generateCookieSecret(device)))
        {
            return false;
        }
    }

    // Mac(key, input) Keyed-Blake2s(key, input, 16), the keyed MAC variant of the BLAKE2s hash function, returning 16
    // bytes of output
    // Mix in the IP address and port as a byte array to avoid coupling this module to the IP stack.
    return wireguardBlake2sTwo(cookie,
                               WIREGUARD_COOKIE_LEN,
                               device->cookie_secret,
                               WIREGUARD_HASH_LEN,
                               source_addr_port,
                               source_length,
                               NULL,
                               0) == kWCryptoOk;
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardMac(uint8_t *dst, const void *message, size_t len, const uint8_t *key,
                                                      size_t keylen)
{
    return wCryptoBlake2s(dst, WIREGUARD_COOKIE_LEN, key, keylen, message, len);
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardMacKey(uint8_t *key, const uint8_t *public_key, const uint8_t *label,
                                                         size_t label_len)
{
    return wireguardBlake2sTwo(
        key, WIREGUARD_SESSION_KEY_LEN, NULL, 0, label, label_len, public_key, WIREGUARD_PUBLIC_KEY_LEN);
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardMixHash(uint8_t *hash, const uint8_t *src, size_t src_len)
{
    return wireguardBlake2sTwo(hash, WIREGUARD_HASH_LEN, NULL, 0, hash, WIREGUARD_HASH_LEN, src, src_len);
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardHmac(uint8_t *digest, const uint8_t *key, size_t key_len,
                                                       const uint8_t *text, size_t text_len)
{
    // Adapted from appendix example in RFC2104 to use BLAKE2S instead of MD5 - https://tools.ietf.org/html/rfc2104
    uint8_t          k_ipad[WIREGUARD_BLAKE2S_BLOCK_SIZE] = {0};
    uint8_t          k_opad[WIREGUARD_BLAKE2S_BLOCK_SIZE] = {0};
    uint8_t          tk[WIREGUARD_HASH_LEN]               = {0};
    uint8_t          inner[WIREGUARD_HASH_LEN]            = {0};
    wcrypto_status_t status                               = kWCryptoOk;
    // if key is longer than BLAKE2S_BLOCK_SIZE bytes reset it to key=BLAKE2S(key)
    if (key_len > WIREGUARD_BLAKE2S_BLOCK_SIZE)
    {
        status = wCryptoBlake2s(tk, sizeof(tk), NULL, 0, key, key_len);
        if (status != kWCryptoOk)
        {
            goto cleanup;
        }
        key     = tk;
        key_len = WIREGUARD_HASH_LEN;
    }

    // the HMAC transform looks like:
    // HASH(K XOR opad, HASH(K XOR ipad, text))
    // where K is an n byte key
    // ipad is the byte 0x36 repeated BLAKE2S_BLOCK_SIZE times
    // opad is the byte 0x5c repeated BLAKE2S_BLOCK_SIZE times
    // and text is the data being protected
    memoryCopy(k_ipad, key, key_len);
    memoryCopy(k_opad, key, key_len);

    // XOR key with ipad and opad values
    for (size_t i = 0; i < WIREGUARD_BLAKE2S_BLOCK_SIZE; i++)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    status = wireguardBlake2sTwo(inner, sizeof(inner), NULL, 0, k_ipad, sizeof(k_ipad), text, text_len);
    if (status == kWCryptoOk)
    {
        status = wireguardBlake2sTwo(digest, WIREGUARD_HASH_LEN, NULL, 0, k_opad, sizeof(k_opad), inner, sizeof(inner));
    }

cleanup:
    if (status != kWCryptoOk)
    {
        wCryptoZero(digest, WIREGUARD_HASH_LEN);
    }
    wCryptoZero(k_ipad, sizeof(k_ipad));
    wCryptoZero(k_opad, sizeof(k_opad));
    wCryptoZero(tk, sizeof(tk));
    wCryptoZero(inner, sizeof(inner));
    return status;
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardKdf1(uint8_t *tau1, const uint8_t *chaining_key, const uint8_t *data,
                                                       size_t data_len)
{
    uint8_t tau0[WIREGUARD_HASH_LEN]       = {0};
    uint8_t output[WIREGUARD_HASH_LEN + 1] = {0};

    wcrypto_status_t status = wireguardHmac(tau0, chaining_key, WIREGUARD_HASH_LEN, data, data_len);
    if (status == kWCryptoOk)
    {
        output[0] = 1;
        status    = wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, 1);
    }
    if (status == kWCryptoOk)
    {
        memoryCopy(tau1, output, WIREGUARD_HASH_LEN);
    }
    else
    {
        wCryptoZero(tau1, WIREGUARD_HASH_LEN);
    }

    // Wipe intermediates
    wCryptoZero(tau0, sizeof(tau0));
    wCryptoZero(output, sizeof(output));
    return status;
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardKdf2(uint8_t *tau1, uint8_t *tau2, const uint8_t *chaining_key,
                                                       const uint8_t *data, size_t data_len)
{
    uint8_t tau0[WIREGUARD_HASH_LEN]       = {0};
    uint8_t output[WIREGUARD_HASH_LEN + 1] = {0};
    uint8_t first[WIREGUARD_HASH_LEN]      = {0};

    wcrypto_status_t status = wireguardHmac(tau0, chaining_key, WIREGUARD_HASH_LEN, data, data_len);
    if (status == kWCryptoOk)
    {
        output[0] = 1;
        status    = wireguardHmac(first, tau0, WIREGUARD_HASH_LEN, output, 1);
    }
    if (status == kWCryptoOk)
    {
        memoryCopy(output, first, sizeof(first));
        output[WIREGUARD_HASH_LEN] = 2;
        status                     = wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, WIREGUARD_HASH_LEN + 1);
    }
    if (status == kWCryptoOk)
    {
        memoryCopy(tau1, first, WIREGUARD_HASH_LEN);
        memoryCopy(tau2, output, WIREGUARD_HASH_LEN);
    }
    else
    {
        wCryptoZero(tau1, WIREGUARD_HASH_LEN);
        wCryptoZero(tau2, WIREGUARD_HASH_LEN);
    }

    // Wipe intermediates
    wCryptoZero(tau0, sizeof(tau0));
    wCryptoZero(output, sizeof(output));
    wCryptoZero(first, sizeof(first));
    return status;
}

static WCRYPTO_MUST_USE wcrypto_status_t wireguardKdf3(uint8_t *tau1, uint8_t *tau2, uint8_t *tau3,
                                                       const uint8_t *chaining_key, const uint8_t *data,
                                                       size_t data_len)
{
    uint8_t tau0[WIREGUARD_HASH_LEN]       = {0};
    uint8_t output[WIREGUARD_HASH_LEN + 1] = {0};
    uint8_t first[WIREGUARD_HASH_LEN]      = {0};
    uint8_t second[WIREGUARD_HASH_LEN]     = {0};

    wcrypto_status_t status = wireguardHmac(tau0, chaining_key, WIREGUARD_HASH_LEN, data, data_len);
    if (status == kWCryptoOk)
    {
        output[0] = 1;
        status    = wireguardHmac(first, tau0, WIREGUARD_HASH_LEN, output, 1);
    }
    if (status == kWCryptoOk)
    {
        memoryCopy(output, first, sizeof(first));
        output[WIREGUARD_HASH_LEN] = 2;
        status                     = wireguardHmac(second, tau0, WIREGUARD_HASH_LEN, output, WIREGUARD_HASH_LEN + 1);
    }
    if (status == kWCryptoOk)
    {
        memoryCopy(output, second, sizeof(second));
        output[WIREGUARD_HASH_LEN] = 3;
        status                     = wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, WIREGUARD_HASH_LEN + 1);
    }
    if (status == kWCryptoOk)
    {
        memoryCopy(tau1, first, WIREGUARD_HASH_LEN);
        memoryCopy(tau2, second, WIREGUARD_HASH_LEN);
        memoryCopy(tau3, output, WIREGUARD_HASH_LEN);
    }
    else
    {
        wCryptoZero(tau1, WIREGUARD_HASH_LEN);
        wCryptoZero(tau2, WIREGUARD_HASH_LEN);
        wCryptoZero(tau3, WIREGUARD_HASH_LEN);
    }

    // Wipe intermediates
    wCryptoZero(tau0, sizeof(tau0));
    wCryptoZero(output, sizeof(output));
    wCryptoZero(first, sizeof(first));
    wCryptoZero(second, sizeof(second));
    return status;
}

bool wireguardCheckReplay(wireguard_keypair_t *keypair, uint64_t seq)
{
    // Implementation of packet replay window - as per RFC2401
    // Adapted from code in Appendix C at https://tools.ietf.org/html/rfc2401
    uint32_t diff;
    bool     result           = false;
    size_t   ReplayWindowSize = sizeof(keypair->replay_bitmap) * CHAR_BIT; // 32 bits

    // WireGuard data packet counter starts from 0 but algorithm expects packet numbers to start from 1
    seq++;

    if (seq != 0)
    {
        if (seq > keypair->replay_counter)
        {
            // new larger sequence number
            diff = (uint32_t) (seq - keypair->replay_counter);
            if (diff < ReplayWindowSize)
            {
                // In window
                keypair->replay_bitmap <<= diff;
                // set bit for this packet
                keypair->replay_bitmap |= 1;
            }
            else
            {
                // This packet has a "way larger"
                keypair->replay_bitmap = 1;
            }
            keypair->replay_counter = seq;
            // larger is good
            result = true;
        }
        else
        {
            diff = (uint32_t) (keypair->replay_counter - seq);
            if (diff < ReplayWindowSize)
            {
                if (keypair->replay_bitmap & ((uint32_t) 1 << diff))
                {
                    // already seen
                }
                else
                {
                    // mark as seen
                    keypair->replay_bitmap |= ((uint32_t) 1 << diff);
                    // out of order but good
                    result = true;
                }
            }
            else
            {
                // too old or wrapped
            }
        }
    }
    else
    {
        // first == 0 or wrapped
    }
    return result;
}

wireguard_keypair_t *getPeerKeypairForIdx(wireguard_peer_t *peer, uint32_t idx)
{
    if (peer->curr_keypair.valid && peer->curr_keypair.local_index == idx)
    {
        return &peer->curr_keypair;
    }
    else if (peer->next_keypair.valid && peer->next_keypair.local_index == idx)
    {
        return &peer->next_keypair;
    }
    else if (peer->prev_keypair.valid && peer->prev_keypair.local_index == idx)
    {
        return &peer->prev_keypair;
    }
    return NULL;
}

static uint32_t wireguardGenerateUniqueIndex(wireguard_device_t *device)
{
    // We need a random 32-bit number but make sure it's not already been used in the context of this device
    uint32_t          result = 0;
    uint8_t           buf[4];
    int               x;
    wireguard_peer_t *peer;
    bool              existing;
    do
    {
        do
        {
            if (UNLIKELY(! secureRandomBytes(buf, sizeof(buf))))
            {
                wCryptoZero(buf, sizeof(buf));
                return 0;
            }
            result = U8TO32_LITTLE(buf);
        } while ((result == 0) || (result == 0xFFFFFFFF)); // Don't allow 0 or 0xFFFFFFFF as valid values

        existing = false;
        for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
        {
            peer = &device->peers[x];
            if ((result == peer->curr_keypair.local_index) || (result == peer->prev_keypair.local_index) ||
                (result == peer->next_keypair.local_index) || (result == peer->handshake.local_index))
            {
                existing = true;
                break;
            }
        }
    } while (existing);

    wCryptoZero(buf, sizeof(buf));
    return result;
}

static void wireguardClampPrivateKey(uint8_t *key)
{
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
}

static bool wireguardGeneratePrivateKey(uint8_t *key)
{
    if (UNLIKELY(! secureRandomBytes(key, WIREGUARD_PRIVATE_KEY_LEN)))
    {
        wCryptoZero(key, WIREGUARD_PRIVATE_KEY_LEN);
        return false;
    }

    wireguardClampPrivateKey(key);
    return true;
}

static bool wireguardGeneratePublicKey(uint8_t *public_key, const uint8_t *private_key)
{
    static const uint8_t basepoint[WIREGUARD_PUBLIC_KEY_LEN] = {9};

    return wCryptoX25519(public_key, private_key, basepoint) == kWCryptoOk;
}

bool wireguardCheckMac1(wireguard_device_t *device, const uint8_t *data, size_t len, const uint8_t *mac1)
{
    bool    result = false;
    uint8_t calculated[WIREGUARD_COOKIE_LEN];
    if (wireguardMac(calculated, data, len, device->label_mac1_key, WIREGUARD_SESSION_KEY_LEN) == kWCryptoOk &&
        wCryptoEqual(calculated, mac1, WIREGUARD_COOKIE_LEN))
    {
        result = true;
    }
    wCryptoZero(calculated, sizeof(calculated));
    return result;
}

bool wireguardCheckMac2(wireguard_device_t *device, const uint8_t *data, size_t len, uint8_t *source_addr_port,
                        size_t source_length, const uint8_t *mac2)
{
    bool    result = false;
    uint8_t cookie[WIREGUARD_COOKIE_LEN];
    uint8_t calculated[WIREGUARD_COOKIE_LEN];

    if (UNLIKELY(! generatePeerCookie(device, cookie, source_addr_port, source_length)))
    {
        goto cleanup;
    }

    if (wireguardMac(calculated, data, len, cookie, WIREGUARD_COOKIE_LEN) == kWCryptoOk &&
        wCryptoEqual(calculated, mac2, WIREGUARD_COOKIE_LEN))
    {
        result = true;
    }

cleanup:
    wCryptoZero(cookie, sizeof(cookie));
    wCryptoZero(calculated, sizeof(calculated));
    return result;
}

void keypairDestroy(wireguard_keypair_t *keypair)
{
    wCryptoZero(keypair, sizeof(wireguard_keypair_t));
    keypair->valid = false;
}

static void wireguardHandshakeDestroy(wireguard_handshake_t *handshake)
{
    wCryptoZero(handshake, sizeof(*handshake));
}

void keypairUpdate(wireguard_peer_t *peer, wireguard_keypair_t *received_keypair)
{
    bool key_is_next = (received_keypair == &peer->next_keypair);
    if (key_is_next)
    {
        peer->prev_keypair = peer->curr_keypair;
        peer->curr_keypair = peer->next_keypair;
        keypairDestroy(&peer->next_keypair);
    }
}

static void addNewKeypair(wireguard_peer_t *peer, wireguard_keypair_t new_keypair)
{
    if (new_keypair.initiator)
    {
        if (peer->next_keypair.valid)
        {
            peer->prev_keypair = peer->next_keypair;
            keypairDestroy(&peer->next_keypair);
        }
        else
        {
            peer->prev_keypair = peer->curr_keypair;
        }
        peer->curr_keypair = new_keypair;
    }
    else
    {
        peer->next_keypair = new_keypair;
        keypairDestroy(&peer->prev_keypair);
    }
}

bool wireguardStartSession(wireguard_peer_t *peer, bool initiator)
{
    wireguard_handshake_t *handshake = &peer->handshake;
    wireguard_keypair_t    new_keypair;

    wCryptoZero(&new_keypair, sizeof(wireguard_keypair_t));
    new_keypair.initiator    = initiator;
    new_keypair.local_index  = handshake->local_index;
    new_keypair.remote_index = handshake->remote_index;

    new_keypair.keypair_millis  = getTickMS();
    new_keypair.sending_valid   = true;
    new_keypair.receiving_valid = true;

    // 5.4.5 Transport Data Key Derivation
    // (Tsendi = Trecvr, Trecvi = Tsendr) := Kdf2(Ci = Cr,E)
    if (new_keypair.initiator)
    {
        if (wireguardKdf2(new_keypair.sending_key, new_keypair.receiving_key, handshake->chaining_key, NULL, 0) !=
            kWCryptoOk)
        {
            wCryptoZero(&new_keypair, sizeof(new_keypair));
            wireguardHandshakeDestroy(handshake);
            return false;
        }
    }
    else
    {
        if (wireguardKdf2(new_keypair.receiving_key, new_keypair.sending_key, handshake->chaining_key, NULL, 0) !=
            kWCryptoOk)
        {
            wCryptoZero(&new_keypair, sizeof(new_keypair));
            wireguardHandshakeDestroy(handshake);
            return false;
        }
    }

    new_keypair.replay_bitmap  = 0;
    new_keypair.replay_counter = 0;

    new_keypair.last_tx = 0;
    new_keypair.last_rx = 0; // No packets received yet

    new_keypair.valid = true;

    // Eprivi = Epubi = Eprivr = Epubr = Ci = Cr := E
    wireguardHandshakeDestroy(handshake);

    addNewKeypair(peer, new_keypair);
    wCryptoZero(&new_keypair, sizeof(new_keypair));
    return true;
}

uint8_t wireguardGetMessageType(const uint8_t *data, size_t len)
{
    uint8_t result = MESSAGE_INVALID;
    if (len >= 4)
    {
        if ((data[1] == 0) && (data[2] == 0) && (data[3] == 0))
        {
            switch (data[0])
            {
            case MESSAGE_HANDSHAKE_INITIATION:
                if (len == sizeof(message_handshake_initiation_t))
                {
                    result = MESSAGE_HANDSHAKE_INITIATION;
                }
                break;
            case MESSAGE_HANDSHAKE_RESPONSE:
                if (len == sizeof(message_handshake_response_t))
                {
                    result = MESSAGE_HANDSHAKE_RESPONSE;
                }
                break;
            case MESSAGE_COOKIE_REPLY:
                if (len == sizeof(message_cookie_reply_t))
                {
                    result = MESSAGE_COOKIE_REPLY;
                }
                break;
            case MESSAGE_TRANSPORT_DATA:
                if (len >= sizeof(message_transport_data_t) + WIREGUARD_AUTHTAG_LEN)
                {
                    result = MESSAGE_TRANSPORT_DATA;
                }
                break;
            default:
                break;
            }
        }
    }
    return result;
}

wireguard_peer_t *wireguardProcessInitiationMessage(wireguard_device_t *device, message_handshake_initiation_t *msg)
{
    wireguard_peer_t *ret_peer                                 = NULL;
    uint8_t           key[WIREGUARD_SESSION_KEY_LEN]           = {0};
    uint8_t           chaining_key[WIREGUARD_HASH_LEN]         = {0};
    uint8_t           hash[WIREGUARD_HASH_LEN]                 = {0};
    uint8_t           s[WIREGUARD_PUBLIC_KEY_LEN]              = {0};
    uint8_t           e[WIREGUARD_PUBLIC_KEY_LEN]              = {0};
    uint8_t           timestamp[WIREGUARD_TAI64N_LEN]          = {0};
    uint8_t           dh_calculation[WIREGUARD_PUBLIC_KEY_LEN] = {0};

    // We are the responder, other end is the initiator

    // Ci := Hash(Construction) (precalculated hash)
    memoryCopy(chaining_key, construction_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Ci || Identifier
    memoryCopy(hash, identifier_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Hi || Spubr)
    if (wireguardMixHash(hash, device->public_key, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    // Ci := Kdf1(Ci, Epubi)
    if (wireguardKdf1(chaining_key, chaining_key, msg->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    // msg.ephemeral := Epubi
    memoryCopy(e, msg->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

    // Hi := Hash(Hi || msg.ephemeral)
    if (wireguardMixHash(hash, msg->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    // Calculate DH(Eprivi,Spubr)
    if (wCryptoX25519(dh_calculation, device->private_key, e) != kWCryptoOk)
    {
        goto cleanup;
    }

    // (Ci,k) := Kdf2(Ci,DH(Eprivi,Spubr))
    if (wireguardKdf2(chaining_key, key, chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    // msg.static := AEAD(k, 0, Spubi, Hi)
    if (chacha20poly1305DecryptWrapper(
            s, sizeof(s), msg->enc_static, sizeof(msg->enc_static), hash, WIREGUARD_HASH_LEN, 0, key) != kWCryptoOk ||
        wireguardMixHash(hash, msg->enc_static, sizeof(msg->enc_static)) != kWCryptoOk)
    {
        goto cleanup;
    }

    wireguard_peer_t *peer = peerLookupByPubkey(device, s);
    if (peer == NULL)
    {
        goto cleanup;
    }

    // (Ci,k) := Kdf2(Ci,DH(Sprivi,Spubr))
    if (wireguardKdf2(chaining_key, key, chaining_key, peer->public_key_dh, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk ||
        chacha20poly1305DecryptWrapper(timestamp,
                                       sizeof(timestamp),
                                       msg->enc_timestamp,
                                       sizeof(msg->enc_timestamp),
                                       hash,
                                       WIREGUARD_HASH_LEN,
                                       0,
                                       key) != kWCryptoOk ||
        wireguardMixHash(hash, msg->enc_timestamp, sizeof(msg->enc_timestamp)) != kWCryptoOk)
    {
        goto cleanup;
    }

    uint32_t now    = getTickMS();
    bool     replay = memcmp(timestamp, peer->greatest_timestamp, WIREGUARD_TAI64N_LEN) <= 0;
    bool     rate_limit =
        peer->last_initiation_rx != 0 && (now - peer->last_initiation_rx) < (1000 / MAX_INITIATIONS_PER_SECOND);
    if (replay || rate_limit)
    {
        goto cleanup;
    }

    wireguard_handshake_t *handshake = &peer->handshake;
    peer->last_initiation_rx         = now;
    memoryCopy(peer->greatest_timestamp, timestamp, WIREGUARD_TAI64N_LEN);
    memoryCopy(handshake->remote_ephemeral, e, WIREGUARD_PUBLIC_KEY_LEN);
    memoryCopy(handshake->hash, hash, WIREGUARD_HASH_LEN);
    memoryCopy(handshake->chaining_key, chaining_key, WIREGUARD_HASH_LEN);
    handshake->remote_index = msg->sender;
    handshake->valid        = true;
    handshake->initiator    = false;
    ret_peer                = peer;

cleanup:
    wCryptoZero(key, sizeof(key));
    wCryptoZero(hash, sizeof(hash));
    wCryptoZero(chaining_key, sizeof(chaining_key));
    wCryptoZero(dh_calculation, sizeof(dh_calculation));
    wCryptoZero(s, sizeof(s));
    wCryptoZero(e, sizeof(e));
    wCryptoZero(timestamp, sizeof(timestamp));

    return ret_peer;
}

bool wireguardProcessHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                       message_handshake_response_t *src)
{
    wireguard_handshake_t *handshake                                   = &peer->handshake;
    bool                   result                                      = false;
    uint8_t                key[WIREGUARD_SESSION_KEY_LEN]              = {0};
    uint8_t                hash[WIREGUARD_HASH_LEN]                    = {0};
    uint8_t                chaining_key[WIREGUARD_HASH_LEN]            = {0};
    uint8_t                e[WIREGUARD_PUBLIC_KEY_LEN]                 = {0};
    uint8_t                ephemeral_private[WIREGUARD_PUBLIC_KEY_LEN] = {0};
    uint8_t                dh_calculation[WIREGUARD_PUBLIC_KEY_LEN]    = {0};
    uint8_t                tau[WIREGUARD_PUBLIC_KEY_LEN]               = {0};

    if (! handshake->valid || ! handshake->initiator)
    {
        goto cleanup;
    }

    memoryCopy(hash, handshake->hash, WIREGUARD_HASH_LEN);
    memoryCopy(chaining_key, handshake->chaining_key, WIREGUARD_HASH_LEN);
    memoryCopy(ephemeral_private, handshake->ephemeral_private, WIREGUARD_PUBLIC_KEY_LEN);

    if (wireguardKdf1(chaining_key, chaining_key, src->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }
    memoryCopy(e, src->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);
    if (wireguardMixHash(hash, src->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    if (wCryptoX25519(dh_calculation, ephemeral_private, e) != kWCryptoOk ||
        wireguardKdf1(chaining_key, chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    if (wCryptoX25519(dh_calculation, device->private_key, e) != kWCryptoOk ||
        wireguardKdf1(chaining_key, chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    if (wireguardKdf3(chaining_key, tau, key, chaining_key, peer->preshared_key, WIREGUARD_SESSION_KEY_LEN) !=
            kWCryptoOk ||
        wireguardMixHash(hash, tau, WIREGUARD_HASH_LEN) != kWCryptoOk ||
        chacha20poly1305DecryptWrapper(
            NULL, 0, src->enc_empty, sizeof(src->enc_empty), hash, WIREGUARD_HASH_LEN, 0, key) != kWCryptoOk)
    {
        goto cleanup;
    }

    memoryCopy(handshake->remote_ephemeral, e, WIREGUARD_HASH_LEN);
    memoryCopy(handshake->hash, hash, WIREGUARD_HASH_LEN);
    memoryCopy(handshake->chaining_key, chaining_key, WIREGUARD_HASH_LEN);
    handshake->remote_index = src->sender;
    result                  = true;

cleanup:
    if (! result)
    {
        wireguardHandshakeDestroy(handshake);
    }
    wCryptoZero(key, sizeof(key));
    wCryptoZero(hash, sizeof(hash));
    wCryptoZero(chaining_key, sizeof(chaining_key));
    wCryptoZero(ephemeral_private, sizeof(ephemeral_private));
    wCryptoZero(dh_calculation, sizeof(dh_calculation));
    wCryptoZero(e, sizeof(e));
    wCryptoZero(tau, sizeof(tau));

    return result;
}

bool wireguardProcessCookieMessage(wireguard_device_t *device, wireguard_peer_t *peer, message_cookie_reply_t *src)
{
    discard device;
    uint8_t cookie[WIREGUARD_COOKIE_LEN];
    bool    result = false;

    if (peer->handshake_mac1_valid)
    {

        result = wCryptoXChaCha20Poly1305Decrypt(cookie,
                                                 sizeof(cookie),
                                                 src->enc_cookie,
                                                 sizeof(src->enc_cookie),
                                                 peer->handshake_mac1,
                                                 WIREGUARD_COOKIE_LEN,
                                                 src->nonce,
                                                 peer->label_cookie_key) == kWCryptoOk;

        if (result)
        {
            // 5.4.7 Under Load: Cookie Reply Message
            // Upon receiving this message, if it is valid, the only thing the recipient of this message should do is
            // store the cookie along with the time at which it was received
            memoryCopy(peer->cookie, cookie, WIREGUARD_COOKIE_LEN);
            peer->cookie_millis        = getTickMS();
            peer->handshake_mac1_valid = false;
        }
    }
    else
    {
        // We didn't send any initiation packet so we shouldn't be getting a cookie reply!
    }
    wCryptoZero(cookie, sizeof(cookie));
    return result;
}

bool wireguardCreateHandshakeInitiation(wireguard_device_t *device, wireguard_peer_t *peer,
                                        message_handshake_initiation_t *dst)
{
    uint8_t timestamp[WIREGUARD_TAI64N_LEN]          = {0};
    uint8_t key[WIREGUARD_SESSION_KEY_LEN]           = {0};
    uint8_t dh_calculation[WIREGUARD_PUBLIC_KEY_LEN] = {0};
    bool    result                                   = false;

    wireguard_handshake_t *handshake = &peer->handshake;

    memoryZero(dst, sizeof(message_handshake_initiation_t));

    // Ci := Hash(Construction) (precalculated hash)
    memoryCopy(handshake->chaining_key, construction_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Ci || Identifier)
    memoryCopy(handshake->hash, identifier_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Hi || Spubr)
    if (wireguardMixHash(handshake->hash, peer->public_key, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    // (Eprivi, Epubi) := DH-Generate()
    if (! wireguardGeneratePrivateKey(handshake->ephemeral_private) ||
        ! wireguardGeneratePublicKey(dst->ephemeral, handshake->ephemeral_private))
    {
        goto cleanup;
    }

    if (wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) !=
            kWCryptoOk ||
        wireguardMixHash(handshake->hash, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    if (wCryptoX25519(dh_calculation, handshake->ephemeral_private, peer->public_key) != kWCryptoOk ||
        wireguardKdf2(
            handshake->chaining_key, key, handshake->chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN) !=
            kWCryptoOk ||
        chacha20poly1305EncryptWrapper(dst->enc_static,
                                       sizeof(dst->enc_static),
                                       device->public_key,
                                       WIREGUARD_PUBLIC_KEY_LEN,
                                       handshake->hash,
                                       WIREGUARD_HASH_LEN,
                                       0,
                                       key) != kWCryptoOk ||
        wireguardMixHash(handshake->hash, dst->enc_static, sizeof(dst->enc_static)) != kWCryptoOk ||
        wireguardKdf2(
            handshake->chaining_key, key, handshake->chaining_key, peer->public_key_dh, WIREGUARD_PUBLIC_KEY_LEN) !=
            kWCryptoOk)
    {
        goto cleanup;
    }

    wireguard12byteTai64(timestamp);
    if (chacha20poly1305EncryptWrapper(dst->enc_timestamp,
                                       sizeof(dst->enc_timestamp),
                                       timestamp,
                                       WIREGUARD_TAI64N_LEN,
                                       handshake->hash,
                                       WIREGUARD_HASH_LEN,
                                       0,
                                       key) != kWCryptoOk ||
        wireguardMixHash(handshake->hash, dst->enc_timestamp, sizeof(dst->enc_timestamp)) != kWCryptoOk)
    {
        goto cleanup;
    }

    dst->type   = MESSAGE_HANDSHAKE_INITIATION;
    dst->sender = wireguardGenerateUniqueIndex(device);
    if (dst->sender == 0 || wireguardMac(dst->mac1,
                                         dst,
                                         sizeof(message_handshake_initiation_t) - (2 * WIREGUARD_COOKIE_LEN),
                                         peer->label_mac1_key,
                                         WIREGUARD_SESSION_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    if ((peer->cookie_millis == 0) || wireguardExpired(peer->cookie_millis, COOKIE_SECRET_MAX_AGE))
    {
        wCryptoZero(dst->mac2, WIREGUARD_COOKIE_LEN);
    }
    else if (wireguardMac(dst->mac2,
                          dst,
                          sizeof(message_handshake_initiation_t) - WIREGUARD_COOKIE_LEN,
                          peer->cookie,
                          WIREGUARD_COOKIE_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    handshake->valid       = true;
    handshake->initiator   = true;
    handshake->local_index = dst->sender;
    result                 = true;

cleanup:
    if (! result)
    {
        wCryptoZero(dst, sizeof(*dst));
        wireguardHandshakeDestroy(handshake);
    }
    wCryptoZero(timestamp, sizeof(timestamp));
    wCryptoZero(key, sizeof(key));
    wCryptoZero(dh_calculation, sizeof(dh_calculation));
    return result;
}

bool wireguardCreateHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                      message_handshake_response_t *dst)
{
    wireguard_handshake_t *handshake                                = &peer->handshake;
    uint8_t                key[WIREGUARD_SESSION_KEY_LEN]           = {0};
    uint8_t                dh_calculation[WIREGUARD_PUBLIC_KEY_LEN] = {0};
    uint8_t                tau[WIREGUARD_HASH_LEN]                  = {0};
    bool                   result                                   = false;

    memoryZero(dst, sizeof(message_handshake_response_t));

    if (! handshake->valid || handshake->initiator)
    {
        goto cleanup;
    }

    if (! wireguardGeneratePrivateKey(handshake->ephemeral_private) ||
        ! wireguardGeneratePublicKey(dst->ephemeral, handshake->ephemeral_private) ||
        wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) !=
            kWCryptoOk ||
        wireguardMixHash(handshake->hash, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    if (wCryptoX25519(dh_calculation, handshake->ephemeral_private, handshake->remote_ephemeral) != kWCryptoOk ||
        wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN) !=
            kWCryptoOk ||
        wCryptoX25519(dh_calculation, handshake->ephemeral_private, peer->public_key) != kWCryptoOk ||
        wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN) !=
            kWCryptoOk ||
        wireguardKdf3(handshake->chaining_key,
                      tau,
                      key,
                      handshake->chaining_key,
                      peer->preshared_key,
                      WIREGUARD_SESSION_KEY_LEN) != kWCryptoOk ||
        wireguardMixHash(handshake->hash, tau, WIREGUARD_HASH_LEN) != kWCryptoOk ||
        chacha20poly1305EncryptWrapper(
            dst->enc_empty, sizeof(dst->enc_empty), NULL, 0, handshake->hash, WIREGUARD_HASH_LEN, 0, key) !=
            kWCryptoOk ||
        wireguardMixHash(handshake->hash, dst->enc_empty, sizeof(dst->enc_empty)) != kWCryptoOk)
    {
        goto cleanup;
    }

    dst->type     = MESSAGE_HANDSHAKE_RESPONSE;
    dst->receiver = handshake->remote_index;
    dst->sender   = wireguardGenerateUniqueIndex(device);
    if (dst->sender == 0 || wireguardMac(dst->mac1,
                                         dst,
                                         sizeof(message_handshake_response_t) - (2 * WIREGUARD_COOKIE_LEN),
                                         peer->label_mac1_key,
                                         WIREGUARD_SESSION_KEY_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    if ((peer->cookie_millis == 0) || wireguardExpired(peer->cookie_millis, COOKIE_SECRET_MAX_AGE))
    {
        wCryptoZero(dst->mac2, WIREGUARD_COOKIE_LEN);
    }
    else if (wireguardMac(dst->mac2,
                          dst,
                          sizeof(message_handshake_response_t) - WIREGUARD_COOKIE_LEN,
                          peer->cookie,
                          WIREGUARD_COOKIE_LEN) != kWCryptoOk)
    {
        goto cleanup;
    }

    handshake->local_index = dst->sender;
    result                 = true;

cleanup:
    if (! result)
    {
        wCryptoZero(dst, sizeof(*dst));
        wireguardHandshakeDestroy(handshake);
    }
    wCryptoZero(key, sizeof(key));
    wCryptoZero(dh_calculation, sizeof(dh_calculation));
    wCryptoZero(tau, sizeof(tau));
    return result;
}

bool wireguardCreateCookieReply(wireguard_device_t *device, message_cookie_reply_t *dst, const uint8_t *mac1,
                                uint32_t index, uint8_t *source_addr_port, size_t source_length)
{
    uint8_t cookie[WIREGUARD_COOKIE_LEN];
    wCryptoZero(dst, sizeof(message_cookie_reply_t));

    if (UNLIKELY(! generatePeerCookie(device, cookie, source_addr_port, source_length)) ||
        UNLIKELY(! secureRandomBytes(dst->nonce, COOKIE_NONCE_LEN)))
    {
        wCryptoZero(cookie, sizeof(cookie));
        wCryptoZero(dst, sizeof(message_cookie_reply_t));
        return false;
    }

    dst->type      = MESSAGE_COOKIE_REPLY;
    dst->receiver  = index;
    bool encrypted = wCryptoXChaCha20Poly1305Encrypt(dst->enc_cookie,
                                                     sizeof(dst->enc_cookie),
                                                     cookie,
                                                     WIREGUARD_COOKIE_LEN,
                                                     mac1,
                                                     WIREGUARD_COOKIE_LEN,
                                                     dst->nonce,
                                                     device->label_cookie_key) == kWCryptoOk;
    wCryptoZero(cookie, sizeof(cookie));
    if (UNLIKELY(! encrypted))
    {
        wCryptoZero(dst, sizeof(message_cookie_reply_t));
        return false;
    }
    return true;
}

bool wireguardPeerInit(wireguard_device_t *device, wireguard_peer_t *peer, const uint8_t *public_key,
                       const uint8_t *preshared_key)
{
    // Clear out structure
    memoryZero(peer, sizeof(wireguard_peer_t));

    if (device->valid)
    {
        // Copy across the public key into our peer structure
        memoryCopy(peer->public_key, public_key, WIREGUARD_PUBLIC_KEY_LEN);
        if (preshared_key)
        {
            memoryCopy(peer->preshared_key, preshared_key, WIREGUARD_SESSION_KEY_LEN);
        }
        else
        {
            wCryptoZero(peer->preshared_key, WIREGUARD_SESSION_KEY_LEN);
        }

        if (wCryptoX25519(peer->public_key_dh, device->private_key, peer->public_key) == kWCryptoOk)
        {
            // Zero out handshake
            memoryZero(&peer->handshake, sizeof(wireguard_handshake_t));
            peer->handshake.valid = false;

            // Zero out any cookie info - we haven't received one yet
            peer->cookie_millis = 0;
            memoryZero(&peer->cookie, WIREGUARD_COOKIE_LEN);

            // Precompute keys to deal with mac1/2 calculation
            peer->valid =
                wireguardMacKey(peer->label_mac1_key, peer->public_key, LABEL_MAC1, sizeof(LABEL_MAC1)) == kWCryptoOk &&
                wireguardMacKey(peer->label_cookie_key, peer->public_key, LABEL_COOKIE, sizeof(LABEL_COOKIE)) ==
                    kWCryptoOk;
        }
        else
        {
            wCryptoZero(peer->public_key_dh, WIREGUARD_PUBLIC_KEY_LEN);
        }
    }
    if (! peer->valid)
    {
        wCryptoZero(peer, sizeof(*peer));
    }
    return peer->valid;
}

bool wireguardDeviceInit(wireguard_device_t *device, const uint8_t *private_key)
{
    // Set the private key and calculate public key from it
    memoryCopy(device->private_key, private_key, WIREGUARD_PRIVATE_KEY_LEN);
    // Ensure private key is correctly "clamped"
    wireguardClampPrivateKey(device->private_key);
    device->valid = wireguardGeneratePublicKey(device->public_key, device->private_key);
    if (device->valid)
    {
        device->valid = generateCookieSecret(device);
        if (device->valid)
        {
            // 5.4.4 Cookie MACs - The value Hash(Label-Mac1 || Spubm' ) above can be pre-computed.
            device->valid =
                wireguardMacKey(device->label_mac1_key, device->public_key, LABEL_MAC1, sizeof(LABEL_MAC1)) ==
                kWCryptoOk;
            // 5.4.7 Under Load: Cookie Reply Message - The value Hash(Label-Cookie || Spubm) above can be pre-computed.
            if (device->valid)
            {
                device->valid =
                    wireguardMacKey(device->label_cookie_key, device->public_key, LABEL_COOKIE, sizeof(LABEL_COOKIE)) ==
                    kWCryptoOk;
            }
        }
    }
    if (! device->valid)
    {
        wCryptoZero(device->private_key, WIREGUARD_PRIVATE_KEY_LEN);
        wCryptoZero(device->public_key, WIREGUARD_PUBLIC_KEY_LEN);
        wCryptoZero(device->cookie_secret, WIREGUARD_HASH_LEN);
        wCryptoZero(device->label_mac1_key, WIREGUARD_SESSION_KEY_LEN);
        wCryptoZero(device->label_cookie_key, WIREGUARD_SESSION_KEY_LEN);
    }
    return device->valid;
}

void wireguardDeviceDestroy(wireguard_device_t *device)
{
    if (device != NULL)
    {
        wCryptoZero(device, sizeof(*device));
    }
}

// Modify packet functions to use the wrappers:
bool wireguardEncryptPacket(uint8_t *dst, size_t dst_capacity, const uint8_t *src, size_t src_len,
                            wireguard_keypair_t *keypair)
{
    if (chacha20poly1305EncryptWrapper(
            dst, dst_capacity, src, src_len, NULL, 0, keypair->sending_counter, keypair->sending_key) != kWCryptoOk)
    {
        return false;
    }
    keypair->sending_counter++;
    return true;
}

bool wireguardDecryptPacket(uint8_t *dst, size_t dst_capacity, const uint8_t *src, size_t src_len, uint64_t counter,
                            wireguard_keypair_t *keypair)
{
    return chacha20poly1305DecryptWrapper(dst, dst_capacity, src, src_len, NULL, 0, counter, keypair->receiving_key) ==
           kWCryptoOk;
}
