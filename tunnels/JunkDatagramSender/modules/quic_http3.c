#include "quic_http3.h"

enum
{
    kQuicVersion1              = 0x00000001U,
    kQuicLongHeaderFixedBit    = 0x40U,
    kQuicLongHeaderBit         = 0x80U,
    kQuicPacketTypeInitial     = 0x00U,
    kQuicFramePadding          = 0x00U,
    kQuicFrameCrypto           = 0x06U,
    kQuicMinClientInitialDgram = 1200U,
    kQuicMaxConnectionIdLen    = 20U,
    kQuicMaxTokenLen           = 32U,

    kTlsHandshakeClientHello          = 1,
    kTlsLegacyVersionTls12            = 0x0303U,
    kTlsVersionTls13                  = 0x0304U,
    kTlsCipherAes128GcmSha256         = 0x1301U,
    kTlsCipherAes256GcmSha384         = 0x1302U,
    kTlsCipherChacha20Poly1305Sha256  = 0x1303U,
    kTlsGroupX25519                   = 0x001DU,
    kTlsGroupSecp256r1                = 0x0017U,
    kTlsSignatureEcdsaSecp256r1Sha256 = 0x0403U,
    kTlsSignatureRsaPssRsaeSha256     = 0x0804U,
    kTlsSignatureRsaPssRsaeSha384     = 0x0805U,
    kTlsSignatureRsaPssRsaeSha512     = 0x0806U,

    kTlsExtServerName              = 0x0000U,
    kTlsExtSupportedGroups         = 0x000AU,
    kTlsExtSignatureAlgorithms     = 0x000DU,
    kTlsExtAlpn                    = 0x0010U,
    kTlsExtSupportedVersions       = 0x002BU,
    kTlsExtPskKeyExchangeModes     = 0x002DU,
    kTlsExtKeyShare                = 0x0033U,
    kTlsExtQuicTransportParameters = 0x0039U,

    kQuicTpMaxIdleTimeout                 = 0x01U,
    kQuicTpMaxUdpPayloadSize              = 0x03U,
    kQuicTpInitialMaxData                 = 0x04U,
    kQuicTpInitialMaxStreamDataBidiLocal  = 0x05U,
    kQuicTpInitialMaxStreamDataBidiRemote = 0x06U,
    kQuicTpInitialMaxStreamsBidi          = 0x08U,
    kQuicTpInitialMaxStreamsUni           = 0x09U,
    kQuicTpActiveConnectionIdLimit        = 0x0EU,
};

static const uint64_t kQuicVarintMax             = 4611686018427387903ULL;
static const uint64_t kQuicVarintEightBytePrefix = 0xC000000000000000ULL;

typedef struct junkdatagramsender_quic_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_quic_writer_t;

typedef struct junkdatagramsender_quic_bytes_writer_s
{
    uint8_t *out;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_quic_bytes_writer_t;

static bool junkdatagramsenderQuicFormatFits(int written, size_t buf_len)
{
    return written > 0 && (size_t) written < buf_len;
}

static uint32_t junkdatagramsenderQuicRandomRange(uint32_t min_value, uint32_t max_value)
{
    if (max_value <= min_value)
    {
        return min_value;
    }
    return min_value + (fastRand32() % (max_value - min_value + 1U));
}

static bool junkdatagramsenderQuicCanWrite(const junkdatagramsender_quic_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderQuicPutBytes(junkdatagramsender_quic_writer_t *writer, const void *src, uint32_t len)
{
    if (! junkdatagramsenderQuicCanWrite(writer, len))
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

static bool junkdatagramsenderQuicPutZeros(junkdatagramsender_quic_writer_t *writer, uint32_t len)
{
    if (! junkdatagramsenderQuicCanWrite(writer, len))
    {
        return false;
    }

    if (len > 0)
    {
        memorySet(sbufGetMutablePtr(writer->buf) + writer->pos, kQuicFramePadding, len);
    }
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderQuicPutU8(junkdatagramsender_quic_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderQuicPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderQuicPutU16(junkdatagramsender_quic_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderQuicPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderQuicPutU32(junkdatagramsender_quic_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderQuicPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderQuicPutU64(junkdatagramsender_quic_writer_t *writer, uint64_t value)
{
    uint64_t network_value = htobe64(value);
    return junkdatagramsenderQuicPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderQuicBytesCanWrite(const junkdatagramsender_quic_bytes_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderQuicBytesPutBytes(junkdatagramsender_quic_bytes_writer_t *writer, const void *src,
                                                uint32_t len)
{
    if (! junkdatagramsenderQuicBytesCanWrite(writer, len))
    {
        return false;
    }

    if (len > 0 && src != NULL)
    {
        memoryCopy(writer->out + writer->pos, src, len);
    }
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderQuicBytesPutU8(junkdatagramsender_quic_bytes_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderQuicBytesPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderQuicBytesPutU16(junkdatagramsender_quic_bytes_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderQuicBytesPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderQuicBytesPutU24(junkdatagramsender_quic_bytes_writer_t *writer, uint32_t value)
{
    if (value > 0x00FFFFFFU)
    {
        return false;
    }

    return junkdatagramsenderQuicBytesPutU8(writer, (uint8_t) ((value >> 16) & 0xFFU)) &&
           junkdatagramsenderQuicBytesPutU8(writer, (uint8_t) ((value >> 8) & 0xFFU)) &&
           junkdatagramsenderQuicBytesPutU8(writer, (uint8_t) (value & 0xFFU));
}

static bool junkdatagramsenderQuicBytesPutU32(junkdatagramsender_quic_bytes_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderQuicBytesPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderQuicBytesPutU64(junkdatagramsender_quic_bytes_writer_t *writer, uint64_t value)
{
    uint64_t network_value = htobe64(value);
    return junkdatagramsenderQuicBytesPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderQuicBytesPatchU16(junkdatagramsender_quic_bytes_writer_t *writer, uint32_t offset,
                                                uint16_t value)
{
    uint16_t network_value = htobe16(value);

    if (offset > writer->pos || sizeof(network_value) > writer->pos - offset)
    {
        return false;
    }

    memoryCopy(writer->out + offset, &network_value, sizeof(network_value));
    return true;
}

static bool junkdatagramsenderQuicBytesPatchU24(junkdatagramsender_quic_bytes_writer_t *writer, uint32_t offset,
                                                uint32_t value)
{
    if (value > 0x00FFFFFFU || offset > writer->pos || 3U > writer->pos - offset)
    {
        return false;
    }

    writer->out[offset]      = (uint8_t) ((value >> 16) & 0xFFU);
    writer->out[offset + 1U] = (uint8_t) ((value >> 8) & 0xFFU);
    writer->out[offset + 2U] = (uint8_t) (value & 0xFFU);
    return true;
}

static uint8_t junkdatagramsenderQuicVarintLen(uint64_t value)
{
    if (value <= 63ULL)
    {
        return 1;
    }
    if (value <= 16383ULL)
    {
        return 2;
    }
    if (value <= 1073741823ULL)
    {
        return 4;
    }
    if (value <= kQuicVarintMax)
    {
        return 8;
    }
    return 0;
}

static bool junkdatagramsenderQuicPutVarint(junkdatagramsender_quic_writer_t *writer, uint64_t value)
{
    if (value <= 63ULL)
    {
        return junkdatagramsenderQuicPutU8(writer, (uint8_t) value);
    }
    if (value <= 16383ULL)
    {
        return junkdatagramsenderQuicPutU16(writer, (uint16_t) (0x4000U | value));
    }
    if (value <= 1073741823ULL)
    {
        return junkdatagramsenderQuicPutU32(writer, UINT32_C(0x80000000) | (uint32_t) value);
    }
    if (value <= kQuicVarintMax)
    {
        return junkdatagramsenderQuicPutU64(writer, kQuicVarintEightBytePrefix | value);
    }
    return false;
}

static bool junkdatagramsenderQuicBytesPutVarint(junkdatagramsender_quic_bytes_writer_t *writer, uint64_t value)
{
    if (value <= 63ULL)
    {
        return junkdatagramsenderQuicBytesPutU8(writer, (uint8_t) value);
    }
    if (value <= 16383ULL)
    {
        return junkdatagramsenderQuicBytesPutU16(writer, (uint16_t) (0x4000U | value));
    }
    if (value <= 1073741823ULL)
    {
        return junkdatagramsenderQuicBytesPutU32(writer, UINT32_C(0x80000000) | (uint32_t) value);
    }
    if (value <= kQuicVarintMax)
    {
        return junkdatagramsenderQuicBytesPutU64(writer, kQuicVarintEightBytePrefix | value);
    }
    return false;
}

static bool junkdatagramsenderQuicPutPacketNumber(junkdatagramsender_quic_writer_t *writer, uint32_t packet_number,
                                                  uint8_t packet_number_len)
{
    if (packet_number_len < 1 || packet_number_len > 4)
    {
        return false;
    }

    for (uint8_t i = packet_number_len; i > 0; --i)
    {
        if (! junkdatagramsenderQuicPutU8(writer, (uint8_t) ((packet_number >> (8U * (uint32_t) (i - 1U))) & 0xFFU)))
        {
            return false;
        }
    }
    return true;
}

static bool junkdatagramsenderQuicTlsBeginExtension(junkdatagramsender_quic_bytes_writer_t *writer,
                                                    uint16_t extension_type, uint32_t *length_offset,
                                                    uint32_t *payload_offset)
{
    if (! junkdatagramsenderQuicBytesPutU16(writer, extension_type))
    {
        return false;
    }

    *length_offset = writer->pos;
    if (! junkdatagramsenderQuicBytesPutU16(writer, 0))
    {
        return false;
    }

    *payload_offset = writer->pos;
    return true;
}

static bool junkdatagramsenderQuicTlsEndExtension(junkdatagramsender_quic_bytes_writer_t *writer,
                                                  uint32_t length_offset, uint32_t payload_offset)
{
    uint32_t extension_len = writer->pos - payload_offset;
    if (extension_len > UINT16_MAX)
    {
        return false;
    }

    return junkdatagramsenderQuicBytesPatchU16(writer, length_offset, (uint16_t) extension_len);
}

static bool junkdatagramsenderQuicTlsPutServerNameExtension(junkdatagramsender_quic_bytes_writer_t *writer,
                                                            const char                             *hostname)
{
    uint32_t length_offset  = 0;
    uint32_t payload_offset = 0;

    size_t hostname_len = stringLength(hostname);
    if (hostname_len == 0 || hostname_len > UINT8_MAX)
    {
        return false;
    }

    if (! junkdatagramsenderQuicTlsBeginExtension(writer, kTlsExtServerName, &length_offset, &payload_offset))
    {
        return false;
    }

    if (! junkdatagramsenderQuicBytesPutU16(writer, (uint16_t) (3U + hostname_len)) ||
        ! junkdatagramsenderQuicBytesPutU8(writer, 0) ||
        ! junkdatagramsenderQuicBytesPutU16(writer, (uint16_t) hostname_len) ||
        ! junkdatagramsenderQuicBytesPutBytes(writer, hostname, (uint32_t) hostname_len))
    {
        return false;
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicTlsPutSupportedGroupsExtension(junkdatagramsender_quic_bytes_writer_t *writer)
{
    uint32_t length_offset  = 0;
    uint32_t payload_offset = 0;

    if (! junkdatagramsenderQuicTlsBeginExtension(writer, kTlsExtSupportedGroups, &length_offset, &payload_offset))
    {
        return false;
    }

    if (! junkdatagramsenderQuicBytesPutU16(writer, 4) ||
        ! junkdatagramsenderQuicBytesPutU16(writer, kTlsGroupX25519) ||
        ! junkdatagramsenderQuicBytesPutU16(writer, kTlsGroupSecp256r1))
    {
        return false;
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicTlsPutSignatureAlgorithmsExtension(junkdatagramsender_quic_bytes_writer_t *writer)
{
    static const uint16_t signature_algorithms[] = {
        kTlsSignatureEcdsaSecp256r1Sha256,
        kTlsSignatureRsaPssRsaeSha256,
        kTlsSignatureRsaPssRsaeSha384,
        kTlsSignatureRsaPssRsaeSha512,
    };

    uint32_t length_offset  = 0;
    uint32_t payload_offset = 0;
    uint16_t list_len       = (uint16_t) (sizeof(signature_algorithms) / sizeof(signature_algorithms[0]) * 2U);

    if (! junkdatagramsenderQuicTlsBeginExtension(
            writer, kTlsExtSignatureAlgorithms, &length_offset, &payload_offset) ||
        ! junkdatagramsenderQuicBytesPutU16(writer, list_len))
    {
        return false;
    }

    for (size_t i = 0; i < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]); ++i)
    {
        if (! junkdatagramsenderQuicBytesPutU16(writer, signature_algorithms[i]))
        {
            return false;
        }
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicTlsPutAlpnExtension(junkdatagramsender_quic_bytes_writer_t *writer, const char *alpn)
{
    uint32_t length_offset  = 0;
    uint32_t payload_offset = 0;

    size_t alpn_len = stringLength(alpn);
    if (alpn_len == 0 || alpn_len > UINT8_MAX)
    {
        return false;
    }

    if (! junkdatagramsenderQuicTlsBeginExtension(writer, kTlsExtAlpn, &length_offset, &payload_offset))
    {
        return false;
    }

    if (! junkdatagramsenderQuicBytesPutU16(writer, (uint16_t) (1U + alpn_len)) ||
        ! junkdatagramsenderQuicBytesPutU8(writer, (uint8_t) alpn_len) ||
        ! junkdatagramsenderQuicBytesPutBytes(writer, alpn, (uint32_t) alpn_len))
    {
        return false;
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicTlsPutSupportedVersionsExtension(junkdatagramsender_quic_bytes_writer_t *writer)
{
    uint32_t length_offset  = 0;
    uint32_t payload_offset = 0;

    if (! junkdatagramsenderQuicTlsBeginExtension(writer, kTlsExtSupportedVersions, &length_offset, &payload_offset))
    {
        return false;
    }

    if (! junkdatagramsenderQuicBytesPutU8(writer, 2) || ! junkdatagramsenderQuicBytesPutU16(writer, kTlsVersionTls13))
    {
        return false;
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicTlsPutPskModesExtension(junkdatagramsender_quic_bytes_writer_t *writer)
{
    uint32_t length_offset  = 0;
    uint32_t payload_offset = 0;

    if (! junkdatagramsenderQuicTlsBeginExtension(writer, kTlsExtPskKeyExchangeModes, &length_offset, &payload_offset))
    {
        return false;
    }

    if (! junkdatagramsenderQuicBytesPutU8(writer, 1) || ! junkdatagramsenderQuicBytesPutU8(writer, 1))
    {
        return false;
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicTlsPutKeyShareExtension(junkdatagramsender_quic_bytes_writer_t *writer)
{
    uint8_t  key_share[32];
    uint32_t length_offset  = 0;
    uint32_t payload_offset = 0;

    getRandomBytes(key_share, sizeof(key_share));

    if (! junkdatagramsenderQuicTlsBeginExtension(writer, kTlsExtKeyShare, &length_offset, &payload_offset))
    {
        return false;
    }

    if (! junkdatagramsenderQuicBytesPutU16(writer, 2U + 2U + sizeof(key_share)) ||
        ! junkdatagramsenderQuicBytesPutU16(writer, kTlsGroupX25519) ||
        ! junkdatagramsenderQuicBytesPutU16(writer, sizeof(key_share)) ||
        ! junkdatagramsenderQuicBytesPutBytes(writer, key_share, sizeof(key_share)))
    {
        return false;
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicBytesPutTransportParameterVarint(junkdatagramsender_quic_bytes_writer_t *writer,
                                                                   uint64_t id, uint64_t value)
{
    uint8_t                                value_bytes[8];
    junkdatagramsender_quic_bytes_writer_t value_writer = {
        .out      = value_bytes,
        .pos      = 0,
        .capacity = sizeof(value_bytes),
    };

    if (! junkdatagramsenderQuicBytesPutVarint(&value_writer, value))
    {
        return false;
    }

    return junkdatagramsenderQuicBytesPutVarint(writer, id) &&
           junkdatagramsenderQuicBytesPutVarint(writer, value_writer.pos) &&
           junkdatagramsenderQuicBytesPutBytes(writer, value_bytes, value_writer.pos);
}

static bool junkdatagramsenderQuicBuildTransportParameters(uint8_t *out, uint32_t out_len, uint32_t *written)
{
    static const uint64_t idle_timeouts[] = {15000, 30000, 45000, 60000};
    static const uint64_t max_udp_sizes[] = {1200, 1232, 1350, 1452};

    junkdatagramsender_quic_bytes_writer_t writer = {
        .out      = out,
        .pos      = 0,
        .capacity = out_len,
    };

    if (! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer,
            kQuicTpMaxIdleTimeout,
            idle_timeouts[fastRand32() % (sizeof(idle_timeouts) / sizeof(idle_timeouts[0]))]) ||
        ! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer,
            kQuicTpMaxUdpPayloadSize,
            max_udp_sizes[fastRand32() % (sizeof(max_udp_sizes) / sizeof(max_udp_sizes[0]))]) ||
        ! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer, kQuicTpInitialMaxData, junkdatagramsenderQuicRandomRange(262144, 4194304)) ||
        ! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer, kQuicTpInitialMaxStreamDataBidiLocal, junkdatagramsenderQuicRandomRange(65536, 1048576)) ||
        ! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer, kQuicTpInitialMaxStreamDataBidiRemote, junkdatagramsenderQuicRandomRange(65536, 1048576)) ||
        ! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer, kQuicTpInitialMaxStreamsBidi, junkdatagramsenderQuicRandomRange(16, 128)) ||
        ! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer, kQuicTpInitialMaxStreamsUni, junkdatagramsenderQuicRandomRange(3, 16)) ||
        ! junkdatagramsenderQuicBytesPutTransportParameterVarint(
            &writer, kQuicTpActiveConnectionIdLimit, junkdatagramsenderQuicRandomRange(2, 8)))
    {
        return false;
    }

    *written = writer.pos;
    return true;
}

static bool junkdatagramsenderQuicTlsPutTransportParametersExtension(junkdatagramsender_quic_bytes_writer_t *writer)
{
    uint8_t  transport_parameters[128];
    uint32_t transport_parameters_len = 0;
    uint32_t length_offset            = 0;
    uint32_t payload_offset           = 0;

    if (! junkdatagramsenderQuicBuildTransportParameters(
            transport_parameters, sizeof(transport_parameters), &transport_parameters_len))
    {
        return false;
    }

    if (! junkdatagramsenderQuicTlsBeginExtension(
            writer, kTlsExtQuicTransportParameters, &length_offset, &payload_offset) ||
        ! junkdatagramsenderQuicBytesPutBytes(writer, transport_parameters, transport_parameters_len))
    {
        return false;
    }

    return junkdatagramsenderQuicTlsEndExtension(writer, length_offset, payload_offset);
}

static bool junkdatagramsenderQuicBuildTlsClientHello(uint8_t *out, uint32_t out_len, uint32_t *written,
                                                      const char *hostname, const char *alpn)
{
    static const uint16_t cipher_suites[] = {
        kTlsCipherAes128GcmSha256,
        kTlsCipherAes256GcmSha384,
        kTlsCipherChacha20Poly1305Sha256,
    };

    uint8_t                                client_random[32];
    uint32_t                               handshake_len_offset   = 0;
    uint32_t                               handshake_body_offset  = 0;
    uint32_t                               extensions_len_offset  = 0;
    uint32_t                               extensions_body_offset = 0;
    junkdatagramsender_quic_bytes_writer_t writer                 = {
                        .out      = out,
                        .pos      = 0,
                        .capacity = out_len,
    };

    getRandomBytes(client_random, sizeof(client_random));

    if (! junkdatagramsenderQuicBytesPutU8(&writer, kTlsHandshakeClientHello))
    {
        return false;
    }

    handshake_len_offset = writer.pos;
    if (! junkdatagramsenderQuicBytesPutU24(&writer, 0))
    {
        return false;
    }
    handshake_body_offset = writer.pos;

    if (! junkdatagramsenderQuicBytesPutU16(&writer, kTlsLegacyVersionTls12) ||
        ! junkdatagramsenderQuicBytesPutBytes(&writer, client_random, sizeof(client_random)) ||
        ! junkdatagramsenderQuicBytesPutU8(&writer, 0) ||
        ! junkdatagramsenderQuicBytesPutU16(&writer, sizeof(cipher_suites)))
    {
        return false;
    }

    for (size_t i = 0; i < sizeof(cipher_suites) / sizeof(cipher_suites[0]); ++i)
    {
        if (! junkdatagramsenderQuicBytesPutU16(&writer, cipher_suites[i]))
        {
            return false;
        }
    }

    if (! junkdatagramsenderQuicBytesPutU8(&writer, 1) || ! junkdatagramsenderQuicBytesPutU8(&writer, 0))
    {
        return false;
    }

    extensions_len_offset = writer.pos;
    if (! junkdatagramsenderQuicBytesPutU16(&writer, 0))
    {
        return false;
    }
    extensions_body_offset = writer.pos;

    if (! junkdatagramsenderQuicTlsPutServerNameExtension(&writer, hostname) ||
        ! junkdatagramsenderQuicTlsPutSupportedGroupsExtension(&writer) ||
        ! junkdatagramsenderQuicTlsPutSignatureAlgorithmsExtension(&writer) ||
        ! junkdatagramsenderQuicTlsPutAlpnExtension(&writer, alpn) ||
        ! junkdatagramsenderQuicTlsPutSupportedVersionsExtension(&writer) ||
        ! junkdatagramsenderQuicTlsPutPskModesExtension(&writer) ||
        ! junkdatagramsenderQuicTlsPutKeyShareExtension(&writer) ||
        ! junkdatagramsenderQuicTlsPutTransportParametersExtension(&writer))
    {
        return false;
    }

    if (writer.pos - extensions_body_offset > UINT16_MAX ||
        ! junkdatagramsenderQuicBytesPatchU16(
            &writer, extensions_len_offset, (uint16_t) (writer.pos - extensions_body_offset)) ||
        ! junkdatagramsenderQuicBytesPatchU24(&writer, handshake_len_offset, writer.pos - handshake_body_offset))
    {
        return false;
    }

    *written = writer.pos;
    return true;
}

static bool junkdatagramsenderQuicBuildInitialLikeCryptoPacket(
    sbuf_t *buf, uint32_t write_limit, uint32_t min_datagram_size, uint32_t version, const uint8_t *dcid,
    uint8_t dcid_len, const uint8_t *scid, uint8_t scid_len, const uint8_t *token, uint32_t token_len,
    uint32_t packet_number, uint8_t packet_number_len, const uint8_t *crypto_data, uint32_t crypto_data_len)
{
    junkdatagramsender_quic_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = write_limit,
    };

    if (dcid_len > kQuicMaxConnectionIdLen || scid_len > kQuicMaxConnectionIdLen || (dcid_len > 0 && dcid == NULL) ||
        (scid_len > 0 && scid == NULL) || (token_len > 0 && token == NULL) ||
        (crypto_data_len > 0 && crypto_data == NULL) || packet_number_len < 1 || packet_number_len > 4)
    {
        return false;
    }

    uint8_t token_varint_size      = junkdatagramsenderQuicVarintLen(token_len);
    uint8_t crypto_len_varint_size = junkdatagramsenderQuicVarintLen(crypto_data_len);
    if (token_varint_size == 0 || crypto_len_varint_size == 0)
    {
        return false;
    }

    uint32_t crypto_frame_len = junkdatagramsenderQuicVarintLen(kQuicFrameCrypto) + junkdatagramsenderQuicVarintLen(0) +
                                crypto_len_varint_size + crypto_data_len;
    uint32_t payload_len        = crypto_frame_len;
    uint32_t length_field_value = packet_number_len + payload_len;
    uint32_t padding_len        = 0;

    uint8_t length_varint_size = junkdatagramsenderQuicVarintLen(length_field_value);
    if (length_varint_size == 0)
    {
        return false;
    }

    uint32_t header_len = 1U + 4U + 1U + dcid_len + 1U + scid_len + token_varint_size + token_len + length_varint_size +
                          packet_number_len;
    if (min_datagram_size > 0 && header_len + payload_len < min_datagram_size)
    {
        padding_len += min_datagram_size - (header_len + payload_len);
        payload_len += padding_len;
        length_field_value = packet_number_len + payload_len;

        length_varint_size = junkdatagramsenderQuicVarintLen(length_field_value);
        if (length_varint_size == 0)
        {
            return false;
        }
        header_len = 1U + 4U + 1U + dcid_len + 1U + scid_len + token_varint_size + token_len + length_varint_size +
                     packet_number_len;
        if (header_len + payload_len < min_datagram_size)
        {
            uint32_t extra = min_datagram_size - (header_len + payload_len);
            padding_len += extra;
            payload_len += extra;
            length_field_value = packet_number_len + payload_len;
        }
    }

    if (header_len + payload_len > write_limit)
    {
        return false;
    }

    if (! junkdatagramsenderQuicPutU8(&writer,
                                      (uint8_t) (kQuicLongHeaderBit | kQuicLongHeaderFixedBit |
                                                 (kQuicPacketTypeInitial << 4U) |
                                                 ((packet_number_len - 1U) & 0x03U))) ||
        ! junkdatagramsenderQuicPutU32(&writer, version) || ! junkdatagramsenderQuicPutU8(&writer, dcid_len) ||
        ! junkdatagramsenderQuicPutBytes(&writer, dcid, dcid_len) || ! junkdatagramsenderQuicPutU8(&writer, scid_len) ||
        ! junkdatagramsenderQuicPutBytes(&writer, scid, scid_len) ||
        ! junkdatagramsenderQuicPutVarint(&writer, token_len) ||
        ! junkdatagramsenderQuicPutBytes(&writer, token, token_len) ||
        ! junkdatagramsenderQuicPutVarint(&writer, length_field_value) ||
        ! junkdatagramsenderQuicPutPacketNumber(&writer, packet_number, packet_number_len) ||
        ! junkdatagramsenderQuicPutVarint(&writer, kQuicFrameCrypto) || ! junkdatagramsenderQuicPutVarint(&writer, 0) ||
        ! junkdatagramsenderQuicPutVarint(&writer, crypto_data_len) ||
        ! junkdatagramsenderQuicPutBytes(&writer, crypto_data, crypto_data_len) ||
        ! junkdatagramsenderQuicPutZeros(&writer, padding_len))
    {
        return false;
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static const char *junkdatagramsenderQuicRandomBaseDomain(void)
{
    static const char *domains[] = {
        "cloudflare.com",
        "google.com",
        "youtube.com",
        "facebook.com",
        "netflix.com",
        "github.com",
        "fastly.net",
        "akamai.com",
        "mozilla.org",
    };

    return domains[fastRand32() % (sizeof(domains) / sizeof(domains[0]))];
}

static const char *junkdatagramsenderQuicRandomHostname(char *buf, size_t buf_len)
{
    static const char *prefixes[] = {
        "www",
        "api",
        "edge",
        "cdn",
        "h3",
    };

    const char *base = junkdatagramsenderQuicRandomBaseDomain();
    if ((fastRand32() % 100U) < 35U &&
        junkdatagramsenderQuicFormatFits(
            stringNPrintf(
                buf, buf_len, "%s.%s", prefixes[fastRand32() % (sizeof(prefixes) / sizeof(prefixes[0]))], base),
            buf_len))
    {
        return buf;
    }
    return base;
}

static uint8_t junkdatagramsenderQuicRandomConnectionIdLen(void)
{
    return (uint8_t) junkdatagramsenderQuicRandomRange(8, kQuicMaxConnectionIdLen);
}

static uint8_t junkdatagramsenderQuicRandomPacketNumberLen(void)
{
    static const uint8_t lengths[] = {1, 2, 2, 4};
    return lengths[fastRand32() % (sizeof(lengths) / sizeof(lengths[0]))];
}

bool junkdatagramsenderQuicHttp3Generate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint8_t  dcid[kQuicMaxConnectionIdLen];
    uint8_t  scid[kQuicMaxConnectionIdLen];
    uint8_t  token[kQuicMaxTokenLen];
    uint8_t  client_hello[512];
    char     hostname[96];
    uint32_t client_hello_len = 0;

    uint32_t write_limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < write_limit)
    {
        write_limit = args->max_packet_size;
    }
    if (write_limit == 0 || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    const char *selected_hostname = junkdatagramsenderQuicRandomHostname(hostname, sizeof(hostname));
    if (! junkdatagramsenderQuicBuildTlsClientHello(
            client_hello, sizeof(client_hello), &client_hello_len, selected_hostname, "h3"))
    {
        return false;
    }

    uint8_t dcid_len = junkdatagramsenderQuicRandomConnectionIdLen();
    uint8_t scid_len = junkdatagramsenderQuicRandomConnectionIdLen();
    getRandomBytes(dcid, dcid_len);
    getRandomBytes(scid, scid_len);

    uint32_t token_len = 0;
    if ((fastRand32() % 100U) < 12U)
    {
        token_len = junkdatagramsenderQuicRandomRange(8, kQuicMaxTokenLen);
        getRandomBytes(token, token_len);
    }

    uint32_t min_datagram_size = args != NULL ? args->min_packet_size : 0;
    if (write_limit >= kQuicMinClientInitialDgram)
    {
        min_datagram_size = kQuicMinClientInitialDgram;
    }

    sbufSetLength(buf, 0);
    return junkdatagramsenderQuicBuildInitialLikeCryptoPacket(buf,
                                                              write_limit,
                                                              min_datagram_size,
                                                              kQuicVersion1,
                                                              dcid,
                                                              dcid_len,
                                                              scid,
                                                              scid_len,
                                                              token_len > 0 ? token : NULL,
                                                              token_len,
                                                              fastRand32(),
                                                              junkdatagramsenderQuicRandomPacketNumberLen(),
                                                              client_hello,
                                                              client_hello_len);
}
