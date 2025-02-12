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
static const uint8_t CONSTRUCTION[37] =
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"; // The UTF-8 string literal "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", 37
                                             // bytes of output
static const uint8_t IDENTIFIER[34] =
    "WireGuard v1 zx2c4 Jason@zx2c4.com"; // The UTF-8 string literal "WireGuard v1 zx2c4 Jason@zx2c4.com", 34 bytes of
                                          // output
static const uint8_t LABEL_MAC1[8] = "mac1----"; // Label-Mac1 The UTF-8 string literal "mac1----", 8 bytes of output.
static const uint8_t LABEL_COOKIE[8] =
    "cookie--"; // Label-Cookie The UTF-8 string literal "cookie--", 8 bytes of output

static const uint8_t zero_key[WIREGUARD_PUBLIC_KEY_LEN] = {0};

// Calculated in wireguardInit
static uint8_t construction_hash[WIREGUARD_HASH_LEN];
static uint8_t identifier_hash[WIREGUARD_HASH_LEN];

static void wireguard12byteTai64(uint8_t *output)
{
    // See https://cr.yp.to/libtai/tai64.html
    // 64 bit seconds from 1970 = 8 bytes
    // 32 bit nano seconds from current second

    uint64_t millis = getTickMS();

    // Split into seconds offset + nanos
    uint64_t seconds = 0x400000000000000aULL + (millis / 1000);
    uint32_t nanos   = (uint32_t)((millis % 1000) * 1000);
    U64TO8_BIG(output + 0, seconds);
    U32TO8_BIG(output + 8, nanos);
}

static bool chacha20poly1305EncryptWrapper(unsigned char *dst, const unsigned char *src, size_t srclen,
                                           const unsigned char *ad, size_t adlen, uint64_t nonce,
                                           const unsigned char *key)
{
    uint32_t wireguard_way_of_nonce[4] = {(uint32_t)(nonce >> 32), (uint32_t)(nonce & 0xFFFFFFFF), 0, 0 };
    return 0 == chacha20poly1305Encrypt(dst, src, srclen, ad, adlen, (unsigned char *) &wireguard_way_of_nonce, key);
}

static bool chacha20poly1305DecryptWrapper(unsigned char *dst, const unsigned char *src, size_t srclen,
                                           const unsigned char *ad, size_t adlen, uint64_t nonce,
                                           const unsigned char *key)
{
    uint32_t wireguard_way_of_nonce[4] = {(uint32_t)(nonce >> 32), (uint32_t)(nonce & 0xFFFFFFFFULL), 0, 0 };
    return 0 == chacha20poly1305Decrypt(dst, src, srclen, ad, adlen, (unsigned char *) &wireguard_way_of_nonce[0], key);
}

void wireguardInit(void)
{
#ifdef DEBUG
    testWireGuardImpl();
#endif

    blake2s_ctx_t ctx;
    // Pre-calculate chaining key hash
    blake2sInit(&ctx, WIREGUARD_HASH_LEN, NULL, 0);
    blake2sUpdate(&ctx, CONSTRUCTION, sizeof(CONSTRUCTION)); // 96 226
    blake2sFinal(&ctx, construction_hash);
    // Pre-calculate initial handshake hash - uses construction_hash calculated above
    blake2sInit(&ctx, WIREGUARD_HASH_LEN, NULL, 0);
    blake2sUpdate(&ctx, construction_hash, sizeof(construction_hash));
    blake2sUpdate(&ctx, IDENTIFIER, sizeof(IDENTIFIER));
    blake2sFinal(&ctx, identifier_hash);
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

static void generateCookieSecret(wireguard_device_t *device)
{
    getRandomBytes(device->cookie_secret, WIREGUARD_HASH_LEN);
    device->cookie_secret_millis = getTickMS();
}

static void generatePeerCookie(wireguard_device_t *device, uint8_t *cookie, uint8_t *source_addr_port,
                               size_t source_length)
{
    blake2s_ctx_t ctx;

    if (wireguardExpired(device->cookie_secret_millis, COOKIE_SECRET_MAX_AGE))
    {
        // Generate new random bytes
        generateCookieSecret(device);
    }

    // Mac(key, input) Keyed-Blake2s(key, input, 16), the keyed MAC variant of the BLAKE2s hash function, returning 16
    // bytes of output
    blake2sInit(&ctx, WIREGUARD_COOKIE_LEN, device->cookie_secret, WIREGUARD_HASH_LEN);
    // 5.4.7 Under Load: Cookie Reply Message
    // Mix in the IP address and port - have the IP layer pass this in as byte array to avoid using Lwip specific APIs
    // in this module
    if ((source_addr_port) && (source_length > 0))
    {
        blake2sUpdate(&ctx, source_addr_port, source_length);
    }
    blake2sFinal(&ctx, cookie);
}

static void wireguardMac(uint8_t *dst, const void *message, size_t len, const uint8_t *key, size_t keylen)
{
    blake2s(dst, WIREGUARD_COOKIE_LEN, key, keylen, message, len);
}

static void wireguardMacKey(uint8_t *key, const uint8_t *public_key, const uint8_t *label, size_t label_len)
{
    blake2s_ctx_t ctx;
    blake2sInit(&ctx, WIREGUARD_SESSION_KEY_LEN, NULL, 0);
    blake2sUpdate(&ctx, label, label_len);
    blake2sUpdate(&ctx, public_key, WIREGUARD_PUBLIC_KEY_LEN);
    blake2sFinal(&ctx, key);
}

static void wireguardMixHash(uint8_t *hash, const uint8_t *src, size_t src_len)
{
    blake2s_ctx_t ctx;
    blake2sInit(&ctx, WIREGUARD_HASH_LEN, NULL, 0);
    blake2sUpdate(&ctx, hash, WIREGUARD_HASH_LEN);
    blake2sUpdate(&ctx, src, src_len);
    blake2sFinal(&ctx, hash);
}

static void wireguardHmac(uint8_t *digest, const uint8_t *key, size_t key_len, const uint8_t *text, size_t text_len)
{
    // Adapted from appendix example in RFC2104 to use BLAKE2S instead of MD5 - https://tools.ietf.org/html/rfc2104
    blake2s_ctx_t ctx;
    uint8_t       k_ipad[WIREGUARD_BLAKE2S_BLOCK_SIZE]; // inner padding - key XORd with ipad
    uint8_t       k_opad[WIREGUARD_BLAKE2S_BLOCK_SIZE]; // outer padding - key XORd with opad

    uint8_t tk[WIREGUARD_HASH_LEN];
    int     i;
    // if key is longer than BLAKE2S_BLOCK_SIZE bytes reset it to key=BLAKE2S(key)
    if (key_len > WIREGUARD_BLAKE2S_BLOCK_SIZE)
    {
        blake2s_ctx_t tctx;
        blake2sInit(&tctx, WIREGUARD_HASH_LEN, NULL, 0);
        blake2sUpdate(&tctx, key, key_len);
        blake2sFinal(&tctx, tk);
        key     = tk;
        key_len = WIREGUARD_HASH_LEN;
    }

    // the HMAC transform looks like:
    // HASH(K XOR opad, HASH(K XOR ipad, text))
    // where K is an n byte key
    // ipad is the byte 0x36 repeated BLAKE2S_BLOCK_SIZE times
    // opad is the byte 0x5c repeated BLAKE2S_BLOCK_SIZE times
    // and text is the data being protected
    memorySet(k_ipad, 0, sizeof(k_ipad));
    memorySet(k_opad, 0, sizeof(k_opad));
    memoryCopy(k_ipad, key, key_len);
    memoryCopy(k_opad, key, key_len);

    // XOR key with ipad and opad values
    for (i = 0; i < WIREGUARD_BLAKE2S_BLOCK_SIZE; i++)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    // perform inner HASH
    blake2sInit(&ctx, WIREGUARD_HASH_LEN, NULL, 0);            // init context for 1st pass
    blake2sUpdate(&ctx, k_ipad, WIREGUARD_BLAKE2S_BLOCK_SIZE); // start with inner pad
    blake2sUpdate(&ctx, text, text_len);                       // then text of datagram
    blake2sFinal(&ctx, digest);                                // finish up 1st pass

    // perform outer HASH
    blake2sInit(&ctx, WIREGUARD_HASH_LEN, NULL, 0);            // init context for 2nd pass
    blake2sUpdate(&ctx, k_opad, WIREGUARD_BLAKE2S_BLOCK_SIZE); // start with outer pad
    blake2sUpdate(&ctx, digest, WIREGUARD_HASH_LEN);           // then results of 1st hash
    blake2sFinal(&ctx, digest);                                // finish up 2nd pass
}

static void wireguardKdf1(uint8_t *tau1, const uint8_t *chaining_key, const uint8_t *data, size_t data_len)
{
    uint8_t tau0[WIREGUARD_HASH_LEN];
    uint8_t output[WIREGUARD_HASH_LEN + 1];

    // tau0 = Hmac(key, input)
    wireguardHmac(tau0, chaining_key, WIREGUARD_HASH_LEN, data, data_len);
    // tau1 := Hmac(tau0, 0x1)
    output[0] = 1;
    wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, 1);
    memoryCopy(tau1, output, WIREGUARD_HASH_LEN);

    // Wipe intermediates
    wCryptoZero(tau0, sizeof(tau0));
    wCryptoZero(output, sizeof(output));
}

static void wireguardKdf2(uint8_t *tau1, uint8_t *tau2, const uint8_t *chaining_key, const uint8_t *data,
                          size_t data_len)
{
    uint8_t tau0[WIREGUARD_HASH_LEN];
    uint8_t output[WIREGUARD_HASH_LEN + 1];

    // tau0 = Hmac(key, input)
    wireguardHmac(tau0, chaining_key, WIREGUARD_HASH_LEN, data, data_len);
    // tau1 := Hmac(tau0, 0x1)
    output[0] = 1;
    wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, 1);
    memoryCopy(tau1, output, WIREGUARD_HASH_LEN);

    // tau2 := Hmac(tau0,tau1 || 0x2)
    output[WIREGUARD_HASH_LEN] = 2;
    wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, WIREGUARD_HASH_LEN + 1);
    memoryCopy(tau2, output, WIREGUARD_HASH_LEN);

    // Wipe intermediates
    wCryptoZero(tau0, sizeof(tau0));
    wCryptoZero(output, sizeof(output));
}

static void wireguardKdf3(uint8_t *tau1, uint8_t *tau2, uint8_t *tau3, const uint8_t *chaining_key, const uint8_t *data,
                          size_t data_len)
{
    uint8_t tau0[WIREGUARD_HASH_LEN];
    uint8_t output[WIREGUARD_HASH_LEN + 1];

    // tau0 = Hmac(key, input)
    wireguardHmac(tau0, chaining_key, WIREGUARD_HASH_LEN, data, data_len);
    // tau1 := Hmac(tau0, 0x1)
    output[0] = 1;
    wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, 1);
    memoryCopy(tau1, output, WIREGUARD_HASH_LEN);

    // tau2 := Hmac(tau0,tau1 || 0x2)
    output[WIREGUARD_HASH_LEN] = 2;
    wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, WIREGUARD_HASH_LEN + 1);
    memoryCopy(tau2, output, WIREGUARD_HASH_LEN);

    // tau3 := Hmac(tau0,tau1,tau2 || 0x3)
    output[WIREGUARD_HASH_LEN] = 3;
    wireguardHmac(output, tau0, WIREGUARD_HASH_LEN, output, WIREGUARD_HASH_LEN + 1);
    memoryCopy(tau3, output, WIREGUARD_HASH_LEN);

    // Wipe intermediates
    wCryptoZero(tau0, sizeof(tau0));
    wCryptoZero(output, sizeof(output));
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
    uint32_t          result;
    uint8_t           buf[4];
    int               x;
    wireguard_peer_t *peer;
    bool              existing;
    do
    {
        do
        {
            getRandomBytes(buf, 4);
            result = U8TO32_LITTLE(buf);
        } while ((result == 0) || (result == 0xFFFFFFFF)); // Don't allow 0 or 0xFFFFFFFF as valid values

        existing = false;
        for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
        {
            peer     = &device->peers[x];
            existing = (result == peer->curr_keypair.local_index) || (result == peer->prev_keypair.local_index) ||
                       (result == peer->next_keypair.local_index) || (result == peer->handshake.local_index);
        }
    } while (existing);

    return result;
}

static void wireguardClampPrivateKey(uint8_t *key)
{
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
}

static void wireguardGeneratePrivateKey(uint8_t *key)
{
    getRandomBytes(key, WIREGUARD_PRIVATE_KEY_LEN);
    wireguardClampPrivateKey(key);
}

static bool wireguardGeneratePublicKey(uint8_t *public_key, const uint8_t *private_key)
{
    static const uint8_t basepoint[WIREGUARD_PUBLIC_KEY_LEN] = {9};
    bool                 result                              = false;
    if (! wCryptoEqual(private_key, zero_key, WIREGUARD_PUBLIC_KEY_LEN))
    {
        result = (performX25519(public_key, private_key, basepoint) == 0);
    }
    return result;
}

bool wireguardCheckMac1(wireguard_device_t *device, const uint8_t *data, size_t len, const uint8_t *mac1)
{
    bool    result = false;
    uint8_t calculated[WIREGUARD_COOKIE_LEN];
    wireguardMac(calculated, data, len, device->label_mac1_key, WIREGUARD_SESSION_KEY_LEN);
    if (wCryptoEqual(calculated, mac1, WIREGUARD_COOKIE_LEN))
    {
        result = true;
    }
    return result;
}

bool wireguardCheckMac2(wireguard_device_t *device, const uint8_t *data, size_t len, uint8_t *source_addr_port,
                        size_t source_length, const uint8_t *mac2)
{
    bool    result = false;
    uint8_t cookie[WIREGUARD_COOKIE_LEN];
    uint8_t calculated[WIREGUARD_COOKIE_LEN];

    generatePeerCookie(device, cookie, source_addr_port, source_length);

    wireguardMac(calculated, data, len, cookie, WIREGUARD_COOKIE_LEN);
    if (wCryptoEqual(calculated, mac2, WIREGUARD_COOKIE_LEN))
    {
        result = true;
    }
    return result;
}

void keypairDestroy(wireguard_keypair_t *keypair)
{
    wCryptoZero(keypair, sizeof(wireguard_keypair_t));
    keypair->valid = false;
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

void wireguardStartSession(wireguard_peer_t *peer, bool initiator)
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
        wireguardKdf2(new_keypair.sending_key, new_keypair.receiving_key, handshake->chaining_key, NULL, 0);
    }
    else
    {
        wireguardKdf2(new_keypair.receiving_key, new_keypair.sending_key, handshake->chaining_key, NULL, 0);
    }

    new_keypair.replay_bitmap  = 0;
    new_keypair.replay_counter = 0;

    new_keypair.last_tx = 0;
    new_keypair.last_rx = 0; // No packets received yet

    new_keypair.valid = true;

    // Eprivi = Epubi = Eprivr = Epubr = Ci = Cr := E
    wCryptoZero(handshake->ephemeral_private, WIREGUARD_PUBLIC_KEY_LEN);
    wCryptoZero(handshake->remote_ephemeral, WIREGUARD_PUBLIC_KEY_LEN);
    wCryptoZero(handshake->hash, WIREGUARD_HASH_LEN);
    wCryptoZero(handshake->chaining_key, WIREGUARD_HASH_LEN);
    handshake->remote_index = 0;
    handshake->local_index  = 0;
    handshake->valid        = false;

    addNewKeypair(peer, new_keypair);
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
    wireguard_peer_t      *ret_peer = NULL;
    wireguard_peer_t      *peer     = NULL;
    wireguard_handshake_t *handshake;
    uint8_t                key[WIREGUARD_SESSION_KEY_LEN];
    uint8_t                chaining_key[WIREGUARD_HASH_LEN];
    uint8_t                hash[WIREGUARD_HASH_LEN];
    uint8_t                s[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t                e[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t                t[WIREGUARD_TAI64N_LEN];
    uint8_t                dh_calculation[WIREGUARD_PUBLIC_KEY_LEN];
    uint32_t               now;
    bool                   rate_limit;
    bool                   replay;

    // We are the responder, other end is the initiator

    // Ci := Hash(Construction) (precalculated hash)
    memoryCopy(chaining_key, construction_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Ci || Identifier
    memoryCopy(hash, identifier_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Hi || Spubr)
    wireguardMixHash(hash, device->public_key, WIREGUARD_PUBLIC_KEY_LEN);

    // Ci := Kdf1(Ci, Epubi)
    wireguardKdf1(chaining_key, chaining_key, msg->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

    // msg.ephemeral := Epubi
    memoryCopy(e, msg->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

    // Hi := Hash(Hi || msg.ephemeral)
    wireguardMixHash(hash, msg->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

    // Calculate DH(Eprivi,Spubr)
    performX25519(dh_calculation, device->private_key, e);
    if (! wCryptoEqual(dh_calculation, zero_key, WIREGUARD_PUBLIC_KEY_LEN))
    {

        // (Ci,k) := Kdf2(Ci,DH(Eprivi,Spubr))
        wireguardKdf2(chaining_key, key, chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN);

        // msg.static := AEAD(k, 0, Spubi, Hi)
        if (chacha20poly1305DecryptWrapper(s, msg->enc_static, sizeof(msg->enc_static), hash, WIREGUARD_HASH_LEN, 0,
                                           key))
        {
            // Hi := Hash(Hi || msg.static)
            wireguardMixHash(hash, msg->enc_static, sizeof(msg->enc_static));

            peer = peerLookupByPubkey(device, s);
            if (peer)
            {
                handshake = &peer->handshake;

                // (Ci,k) := Kdf2(Ci,DH(Sprivi,Spubr))
                wireguardKdf2(chaining_key, key, chaining_key, peer->public_key_dh, WIREGUARD_PUBLIC_KEY_LEN);

                // msg.timestamp := AEAD(k, 0, Timestamp(), Hi)
                if (chacha20poly1305DecryptWrapper(t, msg->enc_timestamp, sizeof(msg->enc_timestamp), hash,
                                                   WIREGUARD_HASH_LEN, 0, key))
                {
                    // Hi := Hash(Hi || msg.timestamp)
                    wireguardMixHash(hash, msg->enc_timestamp, sizeof(msg->enc_timestamp));

                    now = getTickMS();

                    // Check that timestamp is increasing and we haven't had too many initiations (should only get one
                    // per peer every 5 seconds max?)
                    replay     = (memcmp(t, peer->greatest_timestamp, WIREGUARD_TAI64N_LEN) <=
                              0); // tai64n is big endian so we can use memcmp to compare
                    rate_limit = (peer->last_initiation_rx - now) < (1000 / MAX_INITIATIONS_PER_SECOND);

                    if (! replay && ! rate_limit)
                    {
                        // Success! Copy everything to peer
                        peer->last_initiation_rx = now;
                        if (memcmp(t, peer->greatest_timestamp, WIREGUARD_TAI64N_LEN) > 0)
                        {
                            memoryCopy(peer->greatest_timestamp, t, WIREGUARD_TAI64N_LEN);
                            // TODO: Need to notify if the higher layers want to persist latest timestamp/nonce
                            // somewhere
                        }
                        memoryCopy(handshake->remote_ephemeral, e, WIREGUARD_PUBLIC_KEY_LEN);
                        memoryCopy(handshake->hash, hash, WIREGUARD_HASH_LEN);
                        memoryCopy(handshake->chaining_key, chaining_key, WIREGUARD_HASH_LEN);
                        handshake->remote_index = msg->sender;
                        handshake->valid        = true;
                        handshake->initiator    = false;
                        ret_peer                = peer;
                    }
                    else
                    {
                        // Ignore
                    }
                }
                else
                {
                    // Failed to decrypt
                }
            }
            else
            {
                // peer not found
            }
        }
        else
        {
            // Failed to decrypt
        }
    }
    else
    {
        // Bad X25519
    }

    wCryptoZero(key, sizeof(key));
    wCryptoZero(hash, sizeof(hash));
    wCryptoZero(chaining_key, sizeof(chaining_key));
    wCryptoZero(dh_calculation, sizeof(dh_calculation));

    return ret_peer;
}

bool wireguardProcessHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                       message_handshake_response_t *src)
{
    wireguard_handshake_t *handshake = &peer->handshake;

    bool    result = false;
    uint8_t key[WIREGUARD_SESSION_KEY_LEN];
    uint8_t hash[WIREGUARD_HASH_LEN];
    uint8_t chaining_key[WIREGUARD_HASH_LEN];
    uint8_t e[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t ephemeral_private[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t static_private[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t preshared_key[WIREGUARD_SESSION_KEY_LEN];
    uint8_t dh_calculation[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t tau[WIREGUARD_PUBLIC_KEY_LEN];

    if (handshake->valid && handshake->initiator)
    {

        memoryCopy(hash, handshake->hash, WIREGUARD_HASH_LEN);
        memoryCopy(chaining_key, handshake->chaining_key, WIREGUARD_HASH_LEN);
        memoryCopy(ephemeral_private, handshake->ephemeral_private, WIREGUARD_PUBLIC_KEY_LEN);
        memoryCopy(preshared_key, peer->preshared_key, WIREGUARD_SESSION_KEY_LEN);

        // (Eprivr, Epubr) := DH-Generate()
        // Not required

        // Cr := Kdf1(Cr,Epubr)
        wireguardKdf1(chaining_key, chaining_key, src->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

        // msg.ephemeral := Epubr
        memoryCopy(e, src->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

        // Hr := Hash(Hr || msg.ephemeral)
        wireguardMixHash(hash, src->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

        // Cr := Kdf1(Cr, DH(Eprivr, Epubi))
        // Calculate DH(Eprivr, Epubi)
        performX25519(dh_calculation, ephemeral_private, e);
        if (! wCryptoEqual(dh_calculation, zero_key, WIREGUARD_PUBLIC_KEY_LEN))
        {
            wireguardKdf1(chaining_key, chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN);

            // Cr := Kdf1(Cr, DH(Eprivr, Spubi))
            // CalculateDH(Eprivr, Spubi)
            performX25519(dh_calculation, device->private_key, e);
            if (! wCryptoEqual(dh_calculation, zero_key, WIREGUARD_PUBLIC_KEY_LEN))
            {
                wireguardKdf1(chaining_key, chaining_key, dh_calculation, WIREGUARD_PUBLIC_KEY_LEN);

                // (Cr, t, k) := Kdf3(Cr, Q)
                wireguardKdf3(chaining_key, tau, key, chaining_key, peer->preshared_key, WIREGUARD_SESSION_KEY_LEN);

                // Hr := Hash(Hr | t)
                wireguardMixHash(hash, tau, WIREGUARD_HASH_LEN);

                // msg.empty := AEAD(k, 0, E, Hr)
                if (chacha20poly1305DecryptWrapper(NULL, src->enc_empty, sizeof(src->enc_empty), hash,
                                                   WIREGUARD_HASH_LEN, 0, key))
                {
                    // Hr := Hash(Hr | msg.empty)
                    // Not required as discarded

                    // Copy details to handshake
                    memoryCopy(handshake->remote_ephemeral, e, WIREGUARD_HASH_LEN);
                    memoryCopy(handshake->hash, hash, WIREGUARD_HASH_LEN);
                    memoryCopy(handshake->chaining_key, chaining_key, WIREGUARD_HASH_LEN);
                    handshake->remote_index = src->sender;

                    result = true;
                }
                else
                {
                    // Decrypt failed
                }
            }
            else
            {
                // X25519 fail
            }
        }
        else
        {
            // X25519 fail
        }
    }
    wCryptoZero(key, sizeof(key));
    wCryptoZero(hash, sizeof(hash));
    wCryptoZero(chaining_key, sizeof(chaining_key));
    wCryptoZero(ephemeral_private, sizeof(ephemeral_private));
    wCryptoZero(static_private, sizeof(static_private));
    wCryptoZero(preshared_key, sizeof(preshared_key));
    wCryptoZero(tau, sizeof(tau));

    return result;
}

bool wireguardProcessCookieMessage(wireguard_device_t *device, wireguard_peer_t *peer, message_cookie_reply_t *src)
{
    (void) device;
    uint8_t cookie[WIREGUARD_COOKIE_LEN];
    bool    result = false;

    if (peer->handshake_mac1_valid)
    {

        result = 0 == xchacha20poly1305Decrypt(cookie, src->enc_cookie, sizeof(src->enc_cookie), peer->handshake_mac1,
                                               WIREGUARD_COOKIE_LEN, src->nonce, peer->label_cookie_key);

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
    return result;
}

bool wireguardCreateHandshakeInitiation(wireguard_device_t *device, wireguard_peer_t *peer,
                                        message_handshake_initiation_t *dst)
{
    uint8_t timestamp[WIREGUARD_TAI64N_LEN];
    uint8_t key[WIREGUARD_SESSION_KEY_LEN];
    uint8_t dh_calculation[WIREGUARD_PUBLIC_KEY_LEN];
    bool    result = false;

    wireguard_handshake_t *handshake = &peer->handshake;

    memorySet(dst, 0, sizeof(message_handshake_initiation_t));

    // Ci := Hash(Construction) (precalculated hash)
    memoryCopy(handshake->chaining_key, construction_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Ci || Identifier)
    memoryCopy(handshake->hash, identifier_hash, WIREGUARD_HASH_LEN);

    // Hi := Hash(Hi || Spubr)
    wireguardMixHash(handshake->hash, peer->public_key, WIREGUARD_PUBLIC_KEY_LEN);

    // (Eprivi, Epubi) := DH-Generate()
    wireguardGeneratePrivateKey(handshake->ephemeral_private);
    if (wireguardGeneratePublicKey(dst->ephemeral, handshake->ephemeral_private))
    {

        // Ci := Kdf1(Ci, Epubi)
        wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

        // msg.ephemeral := Epubi
        // Done above - public keys is calculated into dst->ephemeral

        // Hi := Hash(Hi || msg.ephemeral)
        wireguardMixHash(handshake->hash, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

        // Calculate DH(Eprivi,Spubr)
        performX25519(dh_calculation, handshake->ephemeral_private, peer->public_key);
        if (! wCryptoEqual(dh_calculation, zero_key, WIREGUARD_PUBLIC_KEY_LEN))
        {

            // (Ci,k) := Kdf2(Ci,DH(Eprivi,Spubr))
            wireguardKdf2(handshake->chaining_key, key, handshake->chaining_key, dh_calculation,
                          WIREGUARD_PUBLIC_KEY_LEN);

            // msg.static := AEAD(k,0,Spubi, Hi)
            chacha20poly1305EncryptWrapper(dst->enc_static, device->public_key, WIREGUARD_PUBLIC_KEY_LEN,
                                           handshake->hash, WIREGUARD_HASH_LEN, 0, key);

            // Hi := Hash(Hi || msg.static)
            wireguardMixHash(handshake->hash, dst->enc_static, sizeof(dst->enc_static));

            // (Ci,k) := Kdf2(Ci,DH(Sprivi,Spubr))
            // note DH(Sprivi,Spubr) is precomputed per peer
            wireguardKdf2(handshake->chaining_key, key, handshake->chaining_key, peer->public_key_dh,
                          WIREGUARD_PUBLIC_KEY_LEN);

            // msg.timestamp := AEAD(k, 0, Timestamp(), Hi)
            wireguard12byteTai64(timestamp);
            chacha20poly1305EncryptWrapper(dst->enc_timestamp, timestamp, WIREGUARD_TAI64N_LEN, handshake->hash,
                                           WIREGUARD_HASH_LEN, 0, key);

            // Hi := Hash(Hi || msg.timestamp)
            wireguardMixHash(handshake->hash, dst->enc_timestamp, sizeof(dst->enc_timestamp));

            dst->type   = MESSAGE_HANDSHAKE_INITIATION;
            dst->sender = wireguardGenerateUniqueIndex(device);

            handshake->valid       = true;
            handshake->initiator   = true;
            handshake->local_index = dst->sender;

            result = true;
        }
    }

    if (result)
    {
        // 5.4.4 Cookie MACs
        // msg.mac1 := Mac(Hash(Label-Mac1 || Spubm' ), msgA)
        // The value Hash(Label-Mac1 || Spubm' ) above can be pre-computed
        wireguardMac(dst->mac1, dst, (sizeof(message_handshake_initiation_t) - (2 * WIREGUARD_COOKIE_LEN)),
                     peer->label_mac1_key, WIREGUARD_SESSION_KEY_LEN);

        // if Lm = E or Lm ≥ 120:
        if ((peer->cookie_millis == 0) || wireguardExpired(peer->cookie_millis, COOKIE_SECRET_MAX_AGE))
        {
            // msg.mac2 := 0
            wCryptoZero(dst->mac2, WIREGUARD_COOKIE_LEN);
        }
        else
        {
            // msg.mac2 := Mac(Lm, msgB)
            wireguardMac(dst->mac2, dst, (sizeof(message_handshake_initiation_t) - (WIREGUARD_COOKIE_LEN)),
                         peer->cookie, WIREGUARD_COOKIE_LEN);
        }
    }

    wCryptoZero(key, sizeof(key));
    wCryptoZero(dh_calculation, sizeof(dh_calculation));
    return result;
}

bool wireguardCreateHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                      message_handshake_response_t *dst)
{
    wireguard_handshake_t *handshake = &peer->handshake;
    uint8_t                key[WIREGUARD_SESSION_KEY_LEN];
    uint8_t                dh_calculation[WIREGUARD_PUBLIC_KEY_LEN];
    uint8_t                tau[WIREGUARD_HASH_LEN];
    bool                   result = false;

    memorySet(dst, 0, sizeof(message_handshake_response_t));

    if (handshake->valid && ! handshake->initiator)
    {

        // (Eprivr, Epubr) := DH-Generate()
        wireguardGeneratePrivateKey(handshake->ephemeral_private);
        if (wireguardGeneratePublicKey(dst->ephemeral, handshake->ephemeral_private))
        {

            // Cr := Kdf1(Cr,Epubr)
            wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

            // msg.ephemeral := Epubr
            // Copied above when generated

            // Hr := Hash(Hr || msg.ephemeral)
            wireguardMixHash(handshake->hash, dst->ephemeral, WIREGUARD_PUBLIC_KEY_LEN);

            // Cr := Kdf1(Cr, DH(Eprivr, Epubi))
            // Calculate DH(Eprivi,Spubr)
            performX25519(dh_calculation, handshake->ephemeral_private, handshake->remote_ephemeral);
            if (! wCryptoEqual(dh_calculation, zero_key, WIREGUARD_PUBLIC_KEY_LEN))
            {
                wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dh_calculation,
                              WIREGUARD_PUBLIC_KEY_LEN);

                // Cr := Kdf1(Cr, DH(Eprivr, Spubi))
                // Calculate DH(Eprivi,Spubr)
                performX25519(dh_calculation, handshake->ephemeral_private, peer->public_key);
                if (! wCryptoEqual(dh_calculation, zero_key, WIREGUARD_PUBLIC_KEY_LEN))
                {
                    wireguardKdf1(handshake->chaining_key, handshake->chaining_key, dh_calculation,
                                  WIREGUARD_PUBLIC_KEY_LEN);

                    // (Cr, t, k) := Kdf3(Cr, Q)
                    wireguardKdf3(handshake->chaining_key, tau, key, handshake->chaining_key, peer->preshared_key,
                                  WIREGUARD_SESSION_KEY_LEN);

                    // Hr := Hash(Hr | t)
                    wireguardMixHash(handshake->hash, tau, WIREGUARD_HASH_LEN);

                    // msg.empty := AEAD(k, 0, E, Hr)
                    chacha20poly1305EncryptWrapper(dst->enc_empty, NULL, 0, handshake->hash, WIREGUARD_HASH_LEN, 0,
                                                   key);

                    // Hr := Hash(Hr | msg.empty)
                    wireguardMixHash(handshake->hash, dst->enc_empty, sizeof(dst->enc_empty));

                    dst->type     = MESSAGE_HANDSHAKE_RESPONSE;
                    dst->receiver = handshake->remote_index;
                    dst->sender   = wireguardGenerateUniqueIndex(device);
                    // Update handshake object too
                    handshake->local_index = dst->sender;

                    result = true;
                }
                else
                {
                    // Bad x25519
                }
            }
            else
            {
                // Bad x25519
            }
        }
        else
        {
            // Failed to generate DH
        }
    }

    if (result)
    {
        // 5.4.4 Cookie MACs
        // msg.mac1 := Mac(Hash(Label-Mac1 || Spubm' ), msgA)
        // The value Hash(Label-Mac1 || Spubm' ) above can be pre-computed
        wireguardMac(dst->mac1, dst, (sizeof(message_handshake_response_t) - (2 * WIREGUARD_COOKIE_LEN)),
                     peer->label_mac1_key, WIREGUARD_SESSION_KEY_LEN);

        // if Lm = E or Lm ≥ 120:
        if ((peer->cookie_millis == 0) || wireguardExpired(peer->cookie_millis, COOKIE_SECRET_MAX_AGE))
        {
            // msg.mac2 := 0
            wCryptoZero(dst->mac2, WIREGUARD_COOKIE_LEN);
        }
        else
        {
            // msg.mac2 := Mac(Lm, msgB)
            wireguardMac(dst->mac2, dst, (sizeof(message_handshake_response_t) - (WIREGUARD_COOKIE_LEN)), peer->cookie,
                         WIREGUARD_COOKIE_LEN);
        }
    }

    wCryptoZero(key, sizeof(key));
    wCryptoZero(dh_calculation, sizeof(dh_calculation));
    wCryptoZero(tau, sizeof(tau));
    return result;
}

void wireguardCreateCookieReply(wireguard_device_t *device, message_cookie_reply_t *dst, const uint8_t *mac1,
                                uint32_t index, uint8_t *source_addr_port, size_t source_length)
{
    uint8_t cookie[WIREGUARD_COOKIE_LEN];
    wCryptoZero(dst, sizeof(message_cookie_reply_t));
    dst->type     = MESSAGE_COOKIE_REPLY;
    dst->receiver = index;
    getRandomBytes(dst->nonce, COOKIE_NONCE_LEN);
    generatePeerCookie(device, cookie, source_addr_port, source_length);
    xchacha20poly1305Encrypt(dst->enc_cookie, cookie, WIREGUARD_COOKIE_LEN, mac1, WIREGUARD_COOKIE_LEN, dst->nonce,
                             device->label_cookie_key);
}

bool wireguardPeerInit(wireguard_device_t *device, wireguard_peer_t *peer, const uint8_t *public_key,
                       const uint8_t *preshared_key)
{
    // Clear out structure
    memorySet(peer, 0, sizeof(wireguard_peer_t));

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

        if (performX25519(peer->public_key_dh, device->private_key, peer->public_key) == 0)
        {
            // Zero out handshake
            memorySet(&peer->handshake, 0, sizeof(wireguard_handshake_t));
            peer->handshake.valid = false;

            // Zero out any cookie info - we haven't received one yet
            peer->cookie_millis = 0;
            memorySet(&peer->cookie, 0, WIREGUARD_COOKIE_LEN);

            // Precompute keys to deal with mac1/2 calculation
            wireguardMacKey(peer->label_mac1_key, peer->public_key, LABEL_MAC1, sizeof(LABEL_MAC1));
            wireguardMacKey(peer->label_cookie_key, peer->public_key, LABEL_COOKIE, sizeof(LABEL_COOKIE));

            peer->valid = true;
        }
        else
        {
            wCryptoZero(peer->public_key_dh, WIREGUARD_PUBLIC_KEY_LEN);
        }
    }
    return peer->valid;
}

bool wireguardDeviceInit(wireguard_device_t *device, const uint8_t *private_key)
{
    // Set the private key and calculate public key from it
    memoryCopy(device->private_key, private_key, WIREGUARD_PRIVATE_KEY_LEN);
    // Ensure private key is correctly "clamped"
    wireguardClampPrivateKey(device->private_key);
    device->valid = wireguardGeneratePublicKey(device->public_key, private_key);
    if (device->valid)
    {
        generateCookieSecret(device);
        // 5.4.4 Cookie MACs - The value Hash(Label-Mac1 || Spubm' ) above can be pre-computed.
        wireguardMacKey(device->label_mac1_key, device->public_key, LABEL_MAC1, sizeof(LABEL_MAC1));
        // 5.4.7 Under Load: Cookie Reply Message - The value Hash(Label-Cookie || Spubm) above can be pre-computed.
        wireguardMacKey(device->label_cookie_key, device->public_key, LABEL_COOKIE, sizeof(LABEL_COOKIE));
    }
    else
    {
        wCryptoZero(device->private_key, WIREGUARD_PRIVATE_KEY_LEN);
    }
    return device->valid;
}

// Modify packet functions to use the wrappers:
void wireguardEncryptPacket(uint8_t *dst, const uint8_t *src, size_t src_len, wireguard_keypair_t *keypair)
{
    // Use the wrapper with keypair->sending_counter passed by value.
    chacha20poly1305EncryptWrapper(dst, src, src_len, NULL, 0, keypair->sending_counter, keypair->sending_key);
    keypair->sending_counter++;
}

bool wireguardDecryptPacket(uint8_t *dst, const uint8_t *src, size_t src_len, uint64_t counter,
                            wireguard_keypair_t *keypair)
{
    return chacha20poly1305DecryptWrapper(dst, src, src_len, NULL, 0, counter, keypair->receiving_key);
}
