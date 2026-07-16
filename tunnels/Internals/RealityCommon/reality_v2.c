#include "RealityCommon/reality_v2.h"

#include "wcrypto.h"
#include "wlibc.h"

static const uint8_t kSessionDomain[] = "WaterWall Reality v2/session";
static const uint8_t kC2sKeyDomain[]  = "WaterWall Reality v2/c2s key";
static const uint8_t kS2cKeyDomain[]  = "WaterWall Reality v2/s2c key";
static const uint8_t kC2sIvDomain[]   = "WaterWall Reality v2/c2s iv";
static const uint8_t kS2cIvDomain[]   = "WaterWall Reality v2/s2c iv";
static const uint8_t kRecordDomain[]  = "WaterWall Reality v2/profile record";

enum
{
    kTlsContentTypeAlert           = 0x15,
    kTlsContentTypeApplicationData = 0x17,
    kTls13InnerContentTypeAlert    = 0x15,
};

typedef struct reality_v2_profile_map_s
{
    uint16_t                    tls_version;
    uint16_t                    cipher_suite;
    reality_v2_record_profile_t profile;
} reality_v2_profile_map_t;

static const reality_v2_profile_map_t kRealityV2Profiles[] = {
    {kRealityV2Tls13, 0x1301, {kRealityV2RecordProfileOpaque, kRealityV2OpaquePrefixSize, 0, 0}},
    {kRealityV2Tls13, 0x1302, {kRealityV2RecordProfileOpaque, kRealityV2OpaquePrefixSize, 0, 0}},
    {kRealityV2Tls13, 0x1303, {kRealityV2RecordProfileOpaque, kRealityV2OpaquePrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC02B, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC02F, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC02C, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC030, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xCCA9, {kRealityV2RecordProfileOpaque, kRealityV2OpaquePrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xCCA8, {kRealityV2RecordProfileOpaque, kRealityV2OpaquePrefixSize, 0, 0}},
    {kRealityV2Tls12, 0xC013, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
    {kRealityV2Tls12, 0xC014, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
    {kRealityV2Tls12, 0x009C, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0x009D, {kRealityV2RecordProfileTls12Gcm, kRealityV2Tls12GcmPrefixSize, 0, 0}},
    {kRealityV2Tls12, 0x002F, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
    {kRealityV2Tls12, 0x0035, {kRealityV2RecordProfileTls12Cbc, kRealityV2Tls12CbcPrefixSize, 16, 20}},
};

static void realityV2WriteBe16(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t) (value >> 8);
    out[1] = (uint8_t) value;
}

void realityV2WriteBe64(uint8_t out[8], uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i)
    {
        out[7U - i] = (uint8_t) value;
        value >>= 8;
    }
}

uint64_t realityV2ReadBe64(const uint8_t in[8])
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < 8; ++i)
    {
        value = (value << 8) | in[i];
    }
    return value;
}

bool realityV2DeriveSessionId(const reality_v2_handshake_binding_t *binding,
                              uint8_t session_id[kRealityV2SessionIdSize])
{
    if (binding == NULL || session_id == NULL)
    {
        return false;
    }

    enum
    {
        kBindingSize = 2 + 2 + kRealityV2TlsRandomSize + kRealityV2TlsRandomSize,
        kInputSize   = sizeof(kSessionDomain) - 1 + kBindingSize,
    };

    uint8_t input[kInputSize];
    uint8_t *cursor = input;

    memoryCopy(cursor, kSessionDomain, sizeof(kSessionDomain) - 1);
    cursor += sizeof(kSessionDomain) - 1;
    realityV2WriteBe16(cursor, binding->tls_version);
    cursor += 2;
    realityV2WriteBe16(cursor, binding->cipher_suite);
    cursor += 2;
    memoryCopy(cursor, binding->client_random, kRealityV2TlsRandomSize);
    cursor += kRealityV2TlsRandomSize;
    memoryCopy(cursor, binding->server_random, kRealityV2TlsRandomSize);

    bool ok = blake2s(session_id, kRealityV2SessionIdSize, NULL, 0, input, sizeof(input)) == 0;
    memoryZero(input, sizeof(input));
    return ok;
}

static bool realityV2DeriveLabeled(const uint8_t root_key[kRealityV2KeySize], const uint8_t *domain,
                                   size_t domain_len, const uint8_t session_id[kRealityV2SessionIdSize],
                                   uint8_t *out, size_t out_len)
{
    uint8_t input[64];
    if (domain_len + kRealityV2SessionIdSize > sizeof(input))
    {
        return false;
    }

    memoryCopy(input, domain, domain_len);
    memoryCopy(input + domain_len, session_id, kRealityV2SessionIdSize);
    bool ok = blake2s(out, out_len, root_key, kRealityV2KeySize, input,
                      domain_len + kRealityV2SessionIdSize) == 0;
    memoryZero(input, sizeof(input));
    return ok;
}

bool realityV2DeriveSessionMaterial(const uint8_t root_key[kRealityV2KeySize],
                                    const reality_v2_handshake_binding_t *binding,
                                    reality_v2_session_material_t *material)
{
    if (root_key == NULL || binding == NULL || material == NULL)
    {
        return false;
    }

    reality_v2_session_material_t result = {0};
    bool ok = realityV2DeriveSessionId(binding, result.session_id) &&
              realityV2DeriveLabeled(root_key, kC2sKeyDomain, sizeof(kC2sKeyDomain) - 1, result.session_id,
                                     result.c2s_key, sizeof(result.c2s_key)) &&
              realityV2DeriveLabeled(root_key, kS2cKeyDomain, sizeof(kS2cKeyDomain) - 1, result.session_id,
                                     result.s2c_key, sizeof(result.s2c_key)) &&
              realityV2DeriveLabeled(root_key, kC2sIvDomain, sizeof(kC2sIvDomain) - 1, result.session_id,
                                     result.c2s_iv, sizeof(result.c2s_iv)) &&
              realityV2DeriveLabeled(root_key, kS2cIvDomain, sizeof(kS2cIvDomain) - 1, result.session_id,
                                     result.s2c_iv, sizeof(result.s2c_iv));

    if (ok)
    {
        *material = result;
    }
    memoryZero(&result, sizeof(result));
    return ok;
}

bool realityV2RecordProfileIsValid(const reality_v2_record_profile_t *profile)
{
    if (profile == NULL || profile->visible_prefix_len > kRealityV2MaxVisiblePrefixSize)
    {
        return false;
    }

    switch (profile->profile_id)
    {
        case kRealityV2RecordProfileOpaque:
            return profile->visible_prefix_len == kRealityV2OpaquePrefixSize && profile->block_size == 0 &&
                   profile->tls_mac_len == 0;
        case kRealityV2RecordProfileTls12Gcm:
            return profile->visible_prefix_len == kRealityV2Tls12GcmPrefixSize && profile->block_size == 0 &&
                   profile->tls_mac_len == 0;
        case kRealityV2RecordProfileTls12Cbc:
            return profile->visible_prefix_len == kRealityV2Tls12CbcPrefixSize &&
                   profile->block_size == kRealityV2Tls12CbcPrefixSize && profile->tls_mac_len > 0;
        default:
            return false;
    }
}

bool realityV2SelectRecordProfile(uint16_t tls_version, uint16_t cipher_suite,
                                  reality_v2_record_profile_t *profile)
{
    if (profile == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < sizeof(kRealityV2Profiles) / sizeof(kRealityV2Profiles[0]); ++i)
    {
        if (kRealityV2Profiles[i].tls_version == tls_version &&
            kRealityV2Profiles[i].cipher_suite == cipher_suite)
        {
            if (! realityV2RecordProfileIsValid(&kRealityV2Profiles[i].profile))
            {
                return false;
            }
            *profile = kRealityV2Profiles[i].profile;
            return true;
        }
    }
    return false;
}

bool realityV2RecordDescriptorIsValid(const reality_v2_record_descriptor_t *descriptor)
{
    if (descriptor == NULL || ! realityV2RecordProfileIsValid(&descriptor->profile) ||
        (descriptor->tls_version != kRealityV2Tls12 && descriptor->tls_version != kRealityV2Tls13))
    {
        return false;
    }
    if (descriptor->tls_version == kRealityV2Tls13 &&
        descriptor->profile.profile_id != kRealityV2RecordProfileOpaque)
    {
        return false;
    }

    if (descriptor->record_kind == kRealityV2RecordKindApplicationData)
    {
        return descriptor->outer_content_type == kTlsContentTypeApplicationData &&
               descriptor->visible_prefix_len == descriptor->profile.visible_prefix_len &&
               descriptor->tls13_inner_content_type == 0;
    }

    if (descriptor->record_kind != kRealityV2RecordKindAlert)
    {
        return false;
    }

    if (descriptor->tls_version == kRealityV2Tls13)
    {
        return descriptor->profile.profile_id == kRealityV2RecordProfileOpaque &&
               descriptor->outer_content_type == kTlsContentTypeApplicationData &&
               descriptor->visible_prefix_len == 0 &&
               descriptor->tls13_inner_content_type == kTls13InnerContentTypeAlert;
    }

    uint8_t expected_prefix = 0;
    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Gcm)
    {
        expected_prefix = kRealityV2Tls12GcmPrefixSize;
    }
    else if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        expected_prefix = kRealityV2Tls12CbcPrefixSize;
    }
    else if (descriptor->profile.profile_id != kRealityV2RecordProfileOpaque)
    {
        return false;
    }

    return descriptor->outer_content_type == kTlsContentTypeAlert &&
           descriptor->visible_prefix_len == expected_prefix &&
           descriptor->tls13_inner_content_type == 0;
}

bool realityV2BuildRecordDescriptor(uint16_t tls_version, const reality_v2_record_profile_t *profile,
                                    uint8_t record_kind, reality_v2_record_descriptor_t *descriptor)
{
    if (! realityV2RecordProfileIsValid(profile) || descriptor == NULL)
    {
        return false;
    }

    reality_v2_record_descriptor_t result = {
        .profile            = *profile,
        .tls_version        = tls_version,
        .record_kind        = record_kind,
        .outer_content_type = kTlsContentTypeApplicationData,
        .visible_prefix_len = profile->visible_prefix_len,
    };

    if (record_kind == kRealityV2RecordKindAlert)
    {
        if (tls_version == kRealityV2Tls13)
        {
            result.visible_prefix_len       = 0;
            result.tls13_inner_content_type = kTls13InnerContentTypeAlert;
        }
        else if (tls_version == kRealityV2Tls12)
        {
            result.outer_content_type = kTlsContentTypeAlert;
            if (profile->profile_id == kRealityV2RecordProfileOpaque)
            {
                result.visible_prefix_len = 0;
            }
        }
    }

    if (! realityV2RecordDescriptorIsValid(&result))
    {
        return false;
    }
    *descriptor = result;
    return true;
}

bool realityV2CalculateDescriptorLayout(const reality_v2_record_descriptor_t *descriptor,
                                        uint32_t payload_len, reality_v2_record_layout_t *layout)
{
    if (! realityV2RecordDescriptorIsValid(descriptor) || layout == NULL ||
        (descriptor->record_kind == kRealityV2RecordKindAlert && payload_len != kRealityV2AlertMessageSize))
    {
        return false;
    }

    uint64_t encoded_payload_len = payload_len;
    if (descriptor->tls13_inner_content_type != 0)
    {
        ++encoded_payload_len;
    }

    uint64_t body_len;
    uint64_t inner_len  = encoded_payload_len;
    uint64_t filler_len = 0;
    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        uint64_t padded_len = (uint64_t) payload_len + descriptor->profile.tls_mac_len + 1U;
        uint64_t remainder  = padded_len % descriptor->profile.block_size;
        if (remainder != 0)
        {
            padded_len += descriptor->profile.block_size - remainder;
        }
        if (padded_len < kRealityV2TagSize)
        {
            return false;
        }
        inner_len = padded_len - kRealityV2TagSize;
        if (inner_len < (uint64_t) payload_len + 2U)
        {
            return false;
        }
        filler_len = inner_len - payload_len - 2U;
        body_len   = descriptor->visible_prefix_len + padded_len;
    }
    else
    {
        body_len = (uint64_t) descriptor->visible_prefix_len + inner_len + kRealityV2TagSize;
    }

    if (body_len > kRealityV2MaxTlsRecordBody || body_len > UINT32_MAX || inner_len > UINT32_MAX ||
        filler_len > UINT32_MAX)
    {
        return false;
    }

    *layout = (reality_v2_record_layout_t) {
        .wire_body_len       = (uint32_t) body_len,
        .inner_plaintext_len = (uint32_t) inner_len,
        .filler_len          = (uint32_t) filler_len,
    };
    return true;
}

bool realityV2CalculateRecordLayout(const reality_v2_record_profile_t *profile, uint32_t payload_len,
                                    reality_v2_record_layout_t *layout)
{
    reality_v2_record_descriptor_t descriptor;
    uint16_t tls_version = profile != NULL && profile->profile_id == kRealityV2RecordProfileOpaque
                               ? kRealityV2Tls13
                               : kRealityV2Tls12;
    return realityV2BuildRecordDescriptor(tls_version,
                                          profile,
                                          kRealityV2RecordKindApplicationData,
                                          &descriptor) &&
           realityV2CalculateDescriptorLayout(&descriptor, payload_len, layout);
}

bool realityV2ValidateDescriptorBodyLength(const reality_v2_record_descriptor_t *descriptor,
                                           uint32_t body_len, uint32_t max_payload_len)
{
    if (! realityV2RecordDescriptorIsValid(descriptor) || body_len > kRealityV2MaxTlsRecordBody)
    {
        return false;
    }

    if (descriptor->record_kind == kRealityV2RecordKindAlert)
    {
        reality_v2_record_layout_t exact;
        return realityV2CalculateDescriptorLayout(descriptor, kRealityV2AlertMessageSize, &exact) &&
               body_len == exact.wire_body_len;
    }

    reality_v2_record_layout_t maximum;
    if (! realityV2CalculateDescriptorLayout(descriptor, max_payload_len, &maximum) ||
        body_len > maximum.wire_body_len)
    {
        return false;
    }

    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        reality_v2_record_layout_t minimum;
        if (! realityV2CalculateDescriptorLayout(descriptor, 0, &minimum) || body_len < minimum.wire_body_len)
        {
            return false;
        }
        return ((body_len - descriptor->visible_prefix_len) % descriptor->profile.block_size) == 0;
    }

    return body_len >= (uint32_t) descriptor->visible_prefix_len + kRealityV2TagSize;
}

bool realityV2ValidateRecordBodyLength(const reality_v2_record_profile_t *profile, uint32_t body_len,
                                       uint32_t max_payload_len)
{
    reality_v2_record_descriptor_t descriptor;
    uint16_t tls_version = profile != NULL && profile->profile_id == kRealityV2RecordProfileOpaque
                               ? kRealityV2Tls13
                               : kRealityV2Tls12;
    return realityV2BuildRecordDescriptor(tls_version,
                                          profile,
                                          kRealityV2RecordKindApplicationData,
                                          &descriptor) &&
           realityV2ValidateDescriptorBodyLength(&descriptor, body_len, max_payload_len);
}

bool realityV2ClassifyRecord(uint16_t tls_version, const reality_v2_record_profile_t *profile,
                             const uint8_t tls_record_header[kRealityV2TlsRecordHeaderSize],
                             uint32_t max_payload_len, reality_v2_record_descriptor_t *descriptor)
{
    if (tls_record_header == NULL || descriptor == NULL || tls_record_header[1] != 0x03 ||
        tls_record_header[2] != 0x03)
    {
        return false;
    }

    uint32_t body_len = ((uint32_t) tls_record_header[3] << 8) | tls_record_header[4];
    reality_v2_record_descriptor_t candidate;
    if (realityV2BuildRecordDescriptor(tls_version, profile, kRealityV2RecordKindAlert, &candidate) &&
        tls_record_header[0] == candidate.outer_content_type &&
        realityV2ValidateDescriptorBodyLength(&candidate, body_len, max_payload_len))
    {
        *descriptor = candidate;
        return true;
    }

    if (realityV2BuildRecordDescriptor(tls_version, profile, kRealityV2RecordKindApplicationData, &candidate) &&
        tls_record_header[0] == candidate.outer_content_type &&
        realityV2ValidateDescriptorBodyLength(&candidate, body_len, max_payload_len))
    {
        *descriptor = candidate;
        return true;
    }
    return false;
}

bool realityV2ValidateCbcInnerPlaintext(const reality_v2_record_profile_t *profile,
                                        const uint8_t *inner_plaintext, uint32_t inner_plaintext_len,
                                        uint32_t max_payload_len, uint32_t *payload_len)
{
    if (! realityV2RecordProfileIsValid(profile) ||
        profile->profile_id != kRealityV2RecordProfileTls12Cbc || inner_plaintext == NULL ||
        payload_len == NULL || inner_plaintext_len < 2)
    {
        return false;
    }

    uint32_t declared_len = ((uint32_t) inner_plaintext[0] << 8) | inner_plaintext[1];
    reality_v2_record_layout_t expected;
    if (declared_len > max_payload_len || ! realityV2CalculateRecordLayout(profile, declared_len, &expected) ||
        expected.inner_plaintext_len != inner_plaintext_len)
    {
        return false;
    }

    uint32_t filler_start = 2U + declared_len;
    for (uint32_t i = filler_start; i < inner_plaintext_len; ++i)
    {
        if (inner_plaintext[i] != 0)
        {
            return false;
        }
    }

    *payload_len = declared_len;
    return true;
}

bool realityV2BuildInnerPlaintext(const reality_v2_record_descriptor_t *descriptor,
                                  const uint8_t *payload, uint32_t payload_len,
                                  uint8_t *inner_plaintext, uint32_t inner_plaintext_len)
{
    reality_v2_record_layout_t layout;
    if (! realityV2CalculateDescriptorLayout(descriptor, payload_len, &layout) ||
        inner_plaintext == NULL || (payload == NULL && payload_len != 0) ||
        inner_plaintext_len != layout.inner_plaintext_len)
    {
        return false;
    }

    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        if (payload_len > UINT16_MAX)
        {
            return false;
        }
        realityV2WriteBe16(inner_plaintext, (uint16_t) payload_len);
        if (payload_len != 0)
        {
            memoryCopy(inner_plaintext + 2, payload, payload_len);
        }
        memoryZero(inner_plaintext + 2 + payload_len, layout.filler_len);
        return true;
    }

    if (payload_len != 0)
    {
        memoryCopy(inner_plaintext, payload, payload_len);
    }
    if (descriptor->tls13_inner_content_type != 0)
    {
        inner_plaintext[payload_len] = descriptor->tls13_inner_content_type;
    }
    return true;
}

bool realityV2ValidateInnerPlaintext(const reality_v2_record_descriptor_t *descriptor,
                                     const uint8_t *inner_plaintext, uint32_t inner_plaintext_len,
                                     uint32_t max_payload_len, uint32_t *payload_offset,
                                     uint32_t *payload_len)
{
    if (! realityV2RecordDescriptorIsValid(descriptor) || inner_plaintext == NULL ||
        payload_offset == NULL || payload_len == NULL)
    {
        return false;
    }

    if (descriptor->profile.profile_id == kRealityV2RecordProfileTls12Cbc)
    {
        if (inner_plaintext_len < 2)
        {
            return false;
        }
        uint32_t declared_len = ((uint32_t) inner_plaintext[0] << 8) | inner_plaintext[1];
        reality_v2_record_layout_t expected;
        if ((descriptor->record_kind == kRealityV2RecordKindApplicationData &&
             declared_len > max_payload_len) ||
            (descriptor->record_kind == kRealityV2RecordKindAlert &&
             declared_len != kRealityV2AlertMessageSize) ||
            ! realityV2CalculateDescriptorLayout(descriptor, declared_len, &expected) ||
            expected.inner_plaintext_len != inner_plaintext_len)
        {
            return false;
        }
        uint32_t filler_start = 2U + declared_len;
        for (uint32_t i = filler_start; i < inner_plaintext_len; ++i)
        {
            if (inner_plaintext[i] != 0)
            {
                return false;
            }
        }
        *payload_offset = 2;
        *payload_len    = declared_len;
        return true;
    }

    if (descriptor->record_kind == kRealityV2RecordKindAlert)
    {
        uint32_t expected_len = kRealityV2AlertMessageSize;
        if (descriptor->tls13_inner_content_type != 0)
        {
            ++expected_len;
        }
        if (inner_plaintext_len != expected_len ||
            (descriptor->tls13_inner_content_type != 0 &&
             inner_plaintext[inner_plaintext_len - 1] != descriptor->tls13_inner_content_type))
        {
            return false;
        }
        *payload_offset = 0;
        *payload_len    = kRealityV2AlertMessageSize;
        return true;
    }

    if (inner_plaintext_len > max_payload_len)
    {
        return false;
    }
    *payload_offset = 0;
    *payload_len    = inner_plaintext_len;
    return true;
}

bool realityV2SerializeAlert(uint8_t alert, uint8_t out[kRealityV2AlertMessageSize])
{
    if (out == NULL)
    {
        return false;
    }
    if (alert == kRealityV2AlertCloseNotify)
    {
        out[0] = 0x01;
        out[1] = 0x00;
        return true;
    }
    if (alert == kRealityV2AlertBadRecordMac)
    {
        out[0] = 0x02;
        out[1] = 0x14;
        return true;
    }
    return false;
}

bool realityV2ParseAlert(const uint8_t *data, uint32_t len, uint8_t *alert)
{
    if (data == NULL || alert == NULL || len != kRealityV2AlertMessageSize)
    {
        return false;
    }
    if (data[0] == 0x01 && data[1] == 0x00)
    {
        *alert = kRealityV2AlertCloseNotify;
        return true;
    }
    if (data[0] == 0x02 && data[1] == 0x14)
    {
        *alert = kRealityV2AlertBadRecordMac;
        return true;
    }
    return false;
}

bool realityV2SequenceAvailable(uint64_t sequence_number)
{
    return sequence_number != UINT64_MAX;
}

bool realityV2AddTlsRecordSequence(uint64_t base, uint64_t reality_sequence, uint64_t *tls_sequence)
{
    if (tls_sequence == NULL || UINT64_MAX - base < reality_sequence)
    {
        return false;
    }
    *tls_sequence = base + reality_sequence;
    return true;
}

void realityV2BuildNonce(const uint8_t base_iv[kRealityV2IvSize], uint64_t sequence_number,
                         uint8_t nonce[kRealityV2IvSize])
{
    uint8_t sequence_be[8];
    realityV2WriteBe64(sequence_be, sequence_number);
    memoryCopy(nonce, base_iv, kRealityV2IvSize);

    for (uint32_t i = 0; i < sizeof(sequence_be); ++i)
    {
        nonce[4U + i] ^= sequence_be[i];
    }
    memoryZero(sequence_be, sizeof(sequence_be));
}

bool realityV2BuildRecordAad(const reality_v2_record_descriptor_t *descriptor, uint8_t direction,
                            uint64_t sequence_number,
                            const uint8_t session_id[kRealityV2SessionIdSize],
                            const uint8_t tls_record_header[kRealityV2TlsRecordHeaderSize],
                            const uint8_t *visible_prefix, uint8_t visible_prefix_len,
                            uint8_t aad[kRealityV2RecordAadMaxSize], size_t *aad_len)
{
    if ((direction != kRealityV2DirectionClientToServer && direction != kRealityV2DirectionServerToClient) ||
        ! realityV2RecordDescriptorIsValid(descriptor) || session_id == NULL || tls_record_header == NULL ||
        (visible_prefix == NULL && visible_prefix_len != 0) ||
        visible_prefix_len != descriptor->visible_prefix_len || aad == NULL || aad_len == NULL ||
        tls_record_header[0] != descriptor->outer_content_type || tls_record_header[1] != 0x03 ||
        tls_record_header[2] != 0x03)
    {
        return false;
    }

    static_assert(sizeof(kRecordDomain) - 1 + 1 + 2 + 1 + 1 + 8 + kRealityV2SessionIdSize +
                          kRealityV2TlsRecordHeaderSize + 1 + kRealityV2MaxVisiblePrefixSize ==
                      kRealityV2RecordAadMaxSize,
                  "Reality v2 maximum record AAD size drifted");

    uint8_t *cursor = aad;
    memoryCopy(cursor, kRecordDomain, sizeof(kRecordDomain) - 1);
    cursor += sizeof(kRecordDomain) - 1;
    *cursor++ = descriptor->record_kind;
    realityV2WriteBe16(cursor, descriptor->tls_version);
    cursor += 2;
    *cursor++ = descriptor->profile.profile_id;
    *cursor++ = direction;
    realityV2WriteBe64(cursor, sequence_number);
    cursor += 8;
    memoryCopy(cursor, session_id, kRealityV2SessionIdSize);
    cursor += kRealityV2SessionIdSize;
    memoryCopy(cursor, tls_record_header, kRealityV2TlsRecordHeaderSize);
    cursor += kRealityV2TlsRecordHeaderSize;
    *cursor++ = visible_prefix_len;
    if (visible_prefix_len != 0)
    {
        memoryCopy(cursor, visible_prefix, visible_prefix_len);
    }
    cursor += visible_prefix_len;
    *aad_len = (size_t) (cursor - aad);
    return true;
}
