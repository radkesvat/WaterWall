#include "stun_turn_ice.h"

enum
{
    kStunHeaderLen           = 20,
    kStunTransactionIdLen    = 12,
    kStunMessageIntegrityLen = 20,
    kStunMagicCookie         = 0x2112A442U,

    kStunMethodBindingRequest          = 0x0001,
    kTurnMethodAllocateRequest         = 0x0003,
    kTurnMethodCreatePermissionRequest = 0x0008,
    kTurnMethodChannelBindRequest      = 0x0009,
    kTurnMethodSendIndication          = 0x0016,

    kStunAttrUsername           = 0x0006,
    kStunAttrMessageIntegrity   = 0x0008,
    kStunAttrChannelNumber      = 0x000C,
    kStunAttrLifetime           = 0x000D,
    kStunAttrXorPeerAddress     = 0x0012,
    kStunAttrData               = 0x0013,
    kStunAttrRealm              = 0x0014,
    kStunAttrNonce              = 0x0015,
    kStunAttrRequestedTransport = 0x0019,
    kStunAttrPriority           = 0x0024,
    kStunAttrUseCandidate       = 0x0025,
    kStunAttrSoftware           = 0x8022,
    kStunAttrFingerprint        = 0x8028,
    kStunAttrIceControlled      = 0x8029,
    kStunAttrIceControlling     = 0x802A,

    kStunTransportUdp = 17,
    kTurnChannelMin   = 0x4000,
    kTurnChannelMax   = 0x7FFF,
};

typedef struct junkdatagramsender_stun_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_stun_writer_t;

typedef struct junkdatagramsender_stun_peer_s
{
    uint8_t  ip[4];
    uint16_t port;
} junkdatagramsender_stun_peer_t;

static uint32_t junkdatagramsenderStunWriteLimit(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < limit)
    {
        limit = args->max_packet_size;
    }
    return limit;
}

static bool junkdatagramsenderStunCanWrite(const junkdatagramsender_stun_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderStunPutBytes(junkdatagramsender_stun_writer_t *writer, const void *src, uint32_t len)
{
    if (! junkdatagramsenderStunCanWrite(writer, len))
    {
        return false;
    }

    if (len > 0 && src != NULL)
    {
        memoryCopy(sbufGetMutablePtr(writer->buf) + writer->pos, src, len);
    }
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderStunPutU8(junkdatagramsender_stun_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderStunPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderStunPutU16(junkdatagramsender_stun_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderStunPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderStunPutU32(junkdatagramsender_stun_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderStunPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderStunPatchU16(junkdatagramsender_stun_writer_t *writer, uint32_t offset, uint16_t value)
{
    uint16_t network_value = htobe16(value);

    if (offset > writer->pos || sizeof(network_value) > writer->pos - offset)
    {
        return false;
    }

    memoryCopy(sbufGetMutablePtr(writer->buf) + offset, &network_value, sizeof(network_value));
    return true;
}

static uint32_t junkdatagramsenderStunCrc32Ieee(const uint8_t *data, uint32_t len)
{
    uint32_t crc = UINT32_C(0xFFFFFFFF);

    for (uint32_t i = 0; i < len; ++i)
    {
        crc ^= data[i];

        for (uint8_t bit = 0; bit < 8; ++bit)
        {
            if ((crc & 1U) != 0)
            {
                crc = (crc >> 1U) ^ UINT32_C(0xEDB88320);
            }
            else
            {
                crc >>= 1U;
            }
        }
    }

    return crc ^ UINT32_C(0xFFFFFFFF);
}

static bool junkdatagramsenderStunBeginMessage(junkdatagramsender_stun_writer_t *writer, uint16_t message_type,
                                               const uint8_t transaction_id[12])
{
    if (transaction_id == NULL)
    {
        return false;
    }

    writer->pos = 0;
    return junkdatagramsenderStunPutU16(writer, message_type) && junkdatagramsenderStunPutU16(writer, 0) &&
           junkdatagramsenderStunPutU32(writer, kStunMagicCookie) &&
           junkdatagramsenderStunPutBytes(writer, transaction_id, kStunTransactionIdLen);
}

static bool junkdatagramsenderStunPutAttrRaw(junkdatagramsender_stun_writer_t *writer, uint16_t attr_type,
                                             const void *data, uint16_t data_len)
{
    uint32_t padded_len  = ((uint32_t) data_len + 3U) & ~UINT32_C(3);
    uint32_t padding_pos = data_len;

    if (data_len > 0 && data == NULL)
    {
        return false;
    }

    if (! junkdatagramsenderStunPutU16(writer, attr_type) || ! junkdatagramsenderStunPutU16(writer, data_len) ||
        ! junkdatagramsenderStunPutBytes(writer, data, data_len))
    {
        return false;
    }

    while (padding_pos < padded_len)
    {
        if (! junkdatagramsenderStunPutU8(writer, 0))
        {
            return false;
        }
        ++padding_pos;
    }

    return true;
}

static bool junkdatagramsenderStunPutAttrString(junkdatagramsender_stun_writer_t *writer, uint16_t attr_type,
                                                const char *value)
{
    if (value == NULL || value[0] == '\0')
    {
        return true;
    }

    size_t len = stringLength(value);
    if (len > UINT16_MAX)
    {
        return false;
    }

    return junkdatagramsenderStunPutAttrRaw(writer, attr_type, value, (uint16_t) len);
}

static bool junkdatagramsenderStunPutAttrU32(junkdatagramsender_stun_writer_t *writer, uint16_t attr_type,
                                             uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderStunPutAttrRaw(writer, attr_type, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderStunPutAttrU64(junkdatagramsender_stun_writer_t *writer, uint16_t attr_type,
                                             uint64_t value)
{
    uint64_t network_value = htobe64(value);
    return junkdatagramsenderStunPutAttrRaw(writer, attr_type, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderStunPutAttrMessageIntegrity(junkdatagramsender_stun_writer_t *writer,
                                                          const uint8_t                     message_integrity[20])
{
    if (message_integrity == NULL)
    {
        return true;
    }

    return junkdatagramsenderStunPutAttrRaw(
        writer, kStunAttrMessageIntegrity, message_integrity, kStunMessageIntegrityLen);
}

static bool junkdatagramsenderStunPutAttrRequestedTransportUdp(junkdatagramsender_stun_writer_t *writer)
{
    uint8_t requested_transport[4] = {kStunTransportUdp, 0, 0, 0};
    return junkdatagramsenderStunPutAttrRaw(
        writer, kStunAttrRequestedTransport, requested_transport, sizeof(requested_transport));
}

static bool junkdatagramsenderStunPutAttrXorIpv4Address(junkdatagramsender_stun_writer_t *writer, uint16_t attr_type,
                                                        const uint8_t ip[4], uint16_t port)
{
    if (ip == NULL)
    {
        return false;
    }

    uint32_t ip_u32 =
        ((uint32_t) ip[0] << 24U) | ((uint32_t) ip[1] << 16U) | ((uint32_t) ip[2] << 8U) | (uint32_t) ip[3];
    uint16_t xport    = (uint16_t) (port ^ (uint16_t) (kStunMagicCookie >> 16U));
    uint32_t xaddr    = ip_u32 ^ kStunMagicCookie;
    uint8_t  value[8] = {
        0,
        0x01,
        (uint8_t) ((xport >> 8U) & 0xFFU),
        (uint8_t) (xport & 0xFFU),
        (uint8_t) ((xaddr >> 24U) & 0xFFU),
        (uint8_t) ((xaddr >> 16U) & 0xFFU),
        (uint8_t) ((xaddr >> 8U) & 0xFFU),
        (uint8_t) (xaddr & 0xFFU),
    };

    return junkdatagramsenderStunPutAttrRaw(writer, attr_type, value, sizeof(value));
}

static bool junkdatagramsenderStunPutAttrChannelNumber(junkdatagramsender_stun_writer_t *writer,
                                                       uint16_t                          channel_number)
{
    if (channel_number < kTurnChannelMin || channel_number > kTurnChannelMax)
    {
        return false;
    }

    uint8_t value[4] = {
        (uint8_t) ((channel_number >> 8U) & 0xFFU),
        (uint8_t) (channel_number & 0xFFU),
        0,
        0,
    };

    return junkdatagramsenderStunPutAttrRaw(writer, kStunAttrChannelNumber, value, sizeof(value));
}

static bool junkdatagramsenderStunFinishMessage(junkdatagramsender_stun_writer_t *writer, bool add_fingerprint)
{
    if (writer->pos < kStunHeaderLen || writer->pos - kStunHeaderLen > UINT16_MAX)
    {
        return false;
    }

    if (! add_fingerprint)
    {
        if (! junkdatagramsenderStunPatchU16(writer, 2, (uint16_t) (writer->pos - kStunHeaderLen)))
        {
            return false;
        }
        sbufSetLength(writer->buf, writer->pos);
        return true;
    }

    if (! junkdatagramsenderStunCanWrite(writer, 8) || writer->pos - kStunHeaderLen + 8U > UINT16_MAX ||
        ! junkdatagramsenderStunPatchU16(writer, 2, (uint16_t) (writer->pos - kStunHeaderLen + 8U)))
    {
        return false;
    }

    uint32_t fingerprint =
        junkdatagramsenderStunCrc32Ieee(sbufGetMutablePtr(writer->buf), writer->pos) ^ UINT32_C(0x5354554E);

    if (! junkdatagramsenderStunPutU16(writer, kStunAttrFingerprint) || ! junkdatagramsenderStunPutU16(writer, 4) ||
        ! junkdatagramsenderStunPutU32(writer, fingerprint))
    {
        return false;
    }

    sbufSetLength(writer->buf, writer->pos);
    return true;
}

static const char *junkdatagramsenderStunRandomSoftware(void)
{
    static const char *software[] = {
        "libwebrtc",
        "Pion TURN client",
        "coturn-4.6.2",
        "ice4j.org",
        "aiortc",
    };

    if ((fastRand32() % 100U) < 18U)
    {
        return NULL;
    }
    return software[fastRand32() % (sizeof(software) / sizeof(software[0]))];
}

static const char *junkdatagramsenderStunRandomRealm(void)
{
    static const char *realms[] = {
        "voice.office.lan",
        "turn.voice.office.lan",
        "realm",
        "local",
    };

    return realms[fastRand32() % (sizeof(realms) / sizeof(realms[0]))];
}

static bool junkdatagramsenderStunRandomToken(char *buf, size_t buf_len, uint32_t min_len, uint32_t max_len)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint32_t          len        = fastRandRange32(min_len, max_len);

    if (buf_len == 0 || len + 1U > buf_len)
    {
        return false;
    }

    for (uint32_t i = 0; i < len; ++i)
    {
        buf[i] = alphabet[fastRand32() % (sizeof(alphabet) - 1U)];
    }
    buf[len] = '\0';
    return true;
}

static const char *junkdatagramsenderStunRandomIceUsername(char *buf, size_t buf_len)
{
    char local[9];
    char remote[9];

    if (junkdatagramsenderStunRandomToken(local, sizeof(local), 4, 8) &&
        junkdatagramsenderStunRandomToken(remote, sizeof(remote), 4, 8) &&
        stringFormatFits(stringNPrintf(buf, buf_len, "%s:%s", remote, local), buf_len))
    {
        return buf;
    }
    return "remote:local";
}

static const char *junkdatagramsenderStunRandomTurnUsername(char *buf, size_t buf_len)
{
    if (stringFormatFits(
            stringNPrintf(buf, buf_len, "user%04x", (unsigned int) (fastRand32() & 0xFFFFU)), buf_len))
    {
        return buf;
    }
    return "user";
}

static const char *junkdatagramsenderStunRandomNonce(char *buf, size_t buf_len)
{
    if (junkdatagramsenderStunRandomToken(buf, buf_len, 16, 32))
    {
        return buf;
    }
    return "nonce";
}

static void junkdatagramsenderStunRandomPeer(junkdatagramsender_stun_peer_t *peer)
{
    switch (fastRand32() % 4U)
    {
    case 0:
        peer->ip[0] = 192;
        peer->ip[1] = 0;
        peer->ip[2] = 2;
        peer->ip[3] = (uint8_t) fastRandRange32(1, 254);
        break;
    case 1:
        peer->ip[0] = 198;
        peer->ip[1] = 51;
        peer->ip[2] = 100;
        peer->ip[3] = (uint8_t) fastRandRange32(1, 254);
        break;
    case 2:
        peer->ip[0] = 203;
        peer->ip[1] = 0;
        peer->ip[2] = 113;
        peer->ip[3] = (uint8_t) fastRandRange32(1, 254);
        break;
    default:
        peer->ip[0] = 10;
        peer->ip[1] = (uint8_t) (fastRand32() % 255U);
        peer->ip[2] = (uint8_t) (fastRand32() % 255U);
        peer->ip[3] = (uint8_t) fastRandRange32(1, 254);
        break;
    }

    peer->port = (uint16_t) fastRandRange32(1024, 65535);
}

static void junkdatagramsenderStunMaybeIntegrity(uint8_t message_integrity[20], const uint8_t **selected)
{
    if ((fastRand32() % 100U) < 72U)
    {
        getRandomBytes(message_integrity, kStunMessageIntegrityLen);
        *selected = message_integrity;
        return;
    }
    *selected = NULL;
}

static bool junkdatagramsenderStunBuildBindingRequest(sbuf_t *buf, uint32_t write_limit,
                                                      const uint8_t transaction_id[12], const char *software,
                                                      bool add_fingerprint)
{
    junkdatagramsender_stun_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};

    if (! junkdatagramsenderStunBeginMessage(&writer, kStunMethodBindingRequest, transaction_id) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrSoftware, software))
    {
        return false;
    }

    return junkdatagramsenderStunFinishMessage(&writer, add_fingerprint);
}

static bool junkdatagramsenderIceBuildConnectivityCheck(sbuf_t *buf, uint32_t write_limit,
                                                        const uint8_t transaction_id[12], const char *username,
                                                        uint32_t priority, bool controlling, uint64_t tiebreaker,
                                                        bool use_candidate, const uint8_t message_integrity[20],
                                                        const char *software, bool add_fingerprint)
{
    junkdatagramsender_stun_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};

    if (username == NULL || username[0] == '\0' ||
        ! junkdatagramsenderStunBeginMessage(&writer, kStunMethodBindingRequest, transaction_id) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrUsername, username) ||
        ! junkdatagramsenderStunPutAttrU32(&writer, kStunAttrPriority, priority) ||
        ! junkdatagramsenderStunPutAttrU64(
            &writer, controlling ? kStunAttrIceControlling : kStunAttrIceControlled, tiebreaker))
    {
        return false;
    }

    if (use_candidate && ! junkdatagramsenderStunPutAttrRaw(&writer, kStunAttrUseCandidate, NULL, 0))
    {
        return false;
    }

    if (! junkdatagramsenderStunPutAttrString(&writer, kStunAttrSoftware, software) ||
        ! junkdatagramsenderStunPutAttrMessageIntegrity(&writer, message_integrity))
    {
        return false;
    }

    return junkdatagramsenderStunFinishMessage(&writer, add_fingerprint);
}

static bool junkdatagramsenderTurnBuildAllocateRequestUdp(sbuf_t *buf, uint32_t write_limit,
                                                          const uint8_t transaction_id[12], const char *username,
                                                          const char *realm, const char *nonce,
                                                          uint32_t      lifetime_seconds,
                                                          const uint8_t message_integrity[20], const char *software,
                                                          bool add_fingerprint)
{
    junkdatagramsender_stun_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};

    if (! junkdatagramsenderStunBeginMessage(&writer, kTurnMethodAllocateRequest, transaction_id) ||
        ! junkdatagramsenderStunPutAttrRequestedTransportUdp(&writer))
    {
        return false;
    }

    if (lifetime_seconds != 0 && ! junkdatagramsenderStunPutAttrU32(&writer, kStunAttrLifetime, lifetime_seconds))
    {
        return false;
    }

    if (! junkdatagramsenderStunPutAttrString(&writer, kStunAttrUsername, username) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrRealm, realm) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrNonce, nonce) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrSoftware, software) ||
        ! junkdatagramsenderStunPutAttrMessageIntegrity(&writer, message_integrity))
    {
        return false;
    }

    return junkdatagramsenderStunFinishMessage(&writer, add_fingerprint);
}

static bool junkdatagramsenderTurnBuildCreatePermissionRequestIpv4(
    sbuf_t *buf, uint32_t write_limit, const uint8_t transaction_id[12], const junkdatagramsender_stun_peer_t *peer,
    const char *username, const char *realm, const char *nonce, const uint8_t message_integrity[20],
    bool add_fingerprint)
{
    junkdatagramsender_stun_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};

    if (peer == NULL ||
        ! junkdatagramsenderStunBeginMessage(&writer, kTurnMethodCreatePermissionRequest, transaction_id) ||
        ! junkdatagramsenderStunPutAttrXorIpv4Address(&writer, kStunAttrXorPeerAddress, peer->ip, peer->port) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrUsername, username) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrRealm, realm) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrNonce, nonce) ||
        ! junkdatagramsenderStunPutAttrMessageIntegrity(&writer, message_integrity))
    {
        return false;
    }

    return junkdatagramsenderStunFinishMessage(&writer, add_fingerprint);
}

static bool junkdatagramsenderTurnBuildChannelBindRequestIpv4(sbuf_t *buf, uint32_t write_limit,
                                                              const uint8_t transaction_id[12], uint16_t channel_number,
                                                              const junkdatagramsender_stun_peer_t *peer,
                                                              const char *username, const char *realm,
                                                              const char *nonce, const uint8_t message_integrity[20],
                                                              bool add_fingerprint)
{
    junkdatagramsender_stun_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};

    if (peer == NULL || ! junkdatagramsenderStunBeginMessage(&writer, kTurnMethodChannelBindRequest, transaction_id) ||
        ! junkdatagramsenderStunPutAttrChannelNumber(&writer, channel_number) ||
        ! junkdatagramsenderStunPutAttrXorIpv4Address(&writer, kStunAttrXorPeerAddress, peer->ip, peer->port) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrUsername, username) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrRealm, realm) ||
        ! junkdatagramsenderStunPutAttrString(&writer, kStunAttrNonce, nonce) ||
        ! junkdatagramsenderStunPutAttrMessageIntegrity(&writer, message_integrity))
    {
        return false;
    }

    return junkdatagramsenderStunFinishMessage(&writer, add_fingerprint);
}

static bool junkdatagramsenderTurnBuildSendIndicationIpv4(sbuf_t *buf, uint32_t write_limit,
                                                          const uint8_t                         transaction_id[12],
                                                          const junkdatagramsender_stun_peer_t *peer,
                                                          const uint8_t *data, uint16_t data_len, bool add_fingerprint)
{
    junkdatagramsender_stun_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};

    if (peer == NULL || (data_len > 0 && data == NULL) ||
        ! junkdatagramsenderStunBeginMessage(&writer, kTurnMethodSendIndication, transaction_id) ||
        ! junkdatagramsenderStunPutAttrXorIpv4Address(&writer, kStunAttrXorPeerAddress, peer->ip, peer->port) ||
        ! junkdatagramsenderStunPutAttrRaw(&writer, kStunAttrData, data, data_len))
    {
        return false;
    }

    return junkdatagramsenderStunFinishMessage(&writer, add_fingerprint);
}

bool junkdatagramsenderStunTurnIceGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint8_t                        transaction_id[kStunTransactionIdLen];
    uint8_t                        message_integrity[kStunMessageIntegrityLen];
    uint8_t                        send_data[128];
    char                           username[32];
    char                           nonce[40];
    const uint8_t                 *selected_integrity = NULL;
    junkdatagramsender_stun_peer_t peer;

    uint32_t write_limit = junkdatagramsenderStunWriteLimit(buf, args);
    if (write_limit < kStunHeaderLen + 8U || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    getRandomBytes(transaction_id, sizeof(transaction_id));
    junkdatagramsenderStunRandomPeer(&peer);
    junkdatagramsenderStunMaybeIntegrity(message_integrity, &selected_integrity);

    sbufSetLength(buf, 0);

    switch (fastRand32() % 6U)
    {
    case 0:
        return junkdatagramsenderStunBuildBindingRequest(
            buf, write_limit, transaction_id, junkdatagramsenderStunRandomSoftware(), (fastRand32() % 100U) < 82U);

    case 1:
        return junkdatagramsenderIceBuildConnectivityCheck(
            buf,
            write_limit,
            transaction_id,
            junkdatagramsenderStunRandomIceUsername(username, sizeof(username)),
            2113929216U + (fastRand32() & 0x00FFFFFFU),
            (fastRand32() % 2U) == 0,
            (((uint64_t) fastRand32()) << 32U) | fastRand32(),
            (fastRand32() % 100U) < 18U,
            selected_integrity,
            junkdatagramsenderStunRandomSoftware(),
            true);

    case 2:
        return junkdatagramsenderTurnBuildAllocateRequestUdp(
            buf,
            write_limit,
            transaction_id,
            junkdatagramsenderStunRandomTurnUsername(username, sizeof(username)),
            junkdatagramsenderStunRandomRealm(),
            junkdatagramsenderStunRandomNonce(nonce, sizeof(nonce)),
            fastRandRange32(300, 3600),
            selected_integrity,
            junkdatagramsenderStunRandomSoftware(),
            true);

    case 3:
        return junkdatagramsenderTurnBuildCreatePermissionRequestIpv4(
            buf,
            write_limit,
            transaction_id,
            &peer,
            junkdatagramsenderStunRandomTurnUsername(username, sizeof(username)),
            junkdatagramsenderStunRandomRealm(),
            junkdatagramsenderStunRandomNonce(nonce, sizeof(nonce)),
            selected_integrity,
            true);

    case 4:
        return junkdatagramsenderTurnBuildChannelBindRequestIpv4(
            buf,
            write_limit,
            transaction_id,
            (uint16_t) fastRandRange32(kTurnChannelMin, kTurnChannelMax),
            &peer,
            junkdatagramsenderStunRandomTurnUsername(username, sizeof(username)),
            junkdatagramsenderStunRandomRealm(),
            junkdatagramsenderStunRandomNonce(nonce, sizeof(nonce)),
            selected_integrity,
            true);

    default: {
        uint16_t data_len = (uint16_t) fastRandRange32(8, 96);
        if (data_len > sizeof(send_data))
        {
            data_len = sizeof(send_data);
        }
        getRandomBytes(send_data, data_len);
        return junkdatagramsenderTurnBuildSendIndicationIpv4(
            buf, write_limit, transaction_id, &peer, send_data, data_len, true);
    }
    }
}
