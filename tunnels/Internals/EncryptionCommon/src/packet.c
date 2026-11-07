#include "EncryptionCommon/packet.h"

static uint32_t packetPseudoHeaderSum(const uint8_t *packet, const ipv4_packet_view_t *view)
{
    return ((uint32_t) packet[12] << 8U) + packet[13] + ((uint32_t) packet[14] << 8U) + packet[15] +
           ((uint32_t) packet[16] << 8U) + packet[17] + ((uint32_t) packet[18] << 8U) + packet[19] + view->protocol +
           view->transport_length;
}

static encryption_packet_result_t packetView(sbuf_t *buf, ipv4_packet_view_t *view)
{
    const uint32_t length = sbufGetLength(buf);
    const uint8_t *packet = sbufGetRawPtr(buf);
    if (length > kEncryptionPacketMaxLength || ! ipv4packetviewParse(packet, length, view) ||
        view->ip_total_length != length)
        return kEncryptionPacketMalformed;
    if (view->fragmented)
        return kEncryptionPacketFragmented;
    if (view->protocol == IPPROTO_TCP)
    {
        if (! ipv4packetviewParseTcp(packet, length, view))
            return kEncryptionPacketMalformed;
    }
    else if (view->protocol == IPPROTO_UDP)
    {
        if (! ipv4packetviewParseUdp(packet, length, view) || view->udp_datagram_length != view->transport_length)
            return kEncryptionPacketMalformed;
    }
    else
        return kEncryptionPacketProtocol;

    const bool udp_zero = view->protocol == IPPROTO_UDP && packet[view->transport_offset + 6] == 0 &&
                          packet[view->transport_offset + 7] == 0;
    if (! sbufGetRecalculateChecksum(buf) &&
        (calcGenericChecksum(packet, view->ip_header_length, 0) != 0 ||
         (! udp_zero && calcGenericChecksum(packet + view->transport_offset,
                                            view->transport_length,
                                            packetPseudoHeaderSum(packet, view)) != 0)))
        return kEncryptionPacketChecksum;
    return kEncryptionPacketOk;
}

static void packetSetLengthAndChecksums(uint8_t *packet, const ipv4_packet_view_t *view, uint16_t total, bool udp_zero)
{
    PUT_BE16(packet + 2, total);
    if (view->protocol == IPPROTO_UDP)
        PUT_BE16(packet + view->transport_offset + 4, total - view->ip_header_length);
    const bool checksummed = calcFullPacketChecksum(packet, total);
    assert(checksummed);
    discard checksummed;
    if (udp_zero)
        PUT_BE16(packet + view->transport_offset + 6, 0);
}

bool encryptionPacketDeriveKeys(const uint8_t base_key[32], uint8_t upload_key[32], uint8_t download_key[32])
{
    static const unsigned char upload_label[]   = "WaterWall packet encryption client to server";
    static const unsigned char download_label[] = "WaterWall packet encryption server to client";
    if (wCryptoBlake2s(upload_key, 32, base_key, 32, upload_label, sizeof(upload_label) - 1) != kWCryptoOk ||
        wCryptoBlake2s(download_key, 32, base_key, 32, download_label, sizeof(download_label) - 1) != kWCryptoOk)
    {
        wCryptoZero(upload_key, 32);
        wCryptoZero(download_key, 32);
        return false;
    }
    return true;
}

encryption_packet_result_t encryptionEncodePacket(const uint8_t key[32], sbuf_t **buf)
{
    assert(buf != NULL && *buf != NULL && ! sbufIsSplice(*buf));
    assert(sbufGetHeadroom(*buf) >= kEncryptionPacketNonceSize);
    ipv4_packet_view_t               view   = {0};
    const encryption_packet_result_t parsed = packetView(*buf, &view);
    if (parsed != kEncryptionPacketOk)
        return parsed;
    const uint32_t total = (uint32_t) view.ip_total_length + kEncryptionPacketOverhead;
    if (total > kEncryptionPacketMaxLength)
        return kEncryptionPacketTooLarge;
    const uint8_t *original = sbufGetRawPtr(*buf);
    const bool     udp_zero = view.protocol == IPPROTO_UDP && ! sbufGetRecalculateChecksum(*buf) &&
                          original[view.transport_offset + 6] == 0 && original[view.transport_offset + 7] == 0;

    *buf = sbufReserveSpace(*buf, view.ip_total_length + kEncryptionPacketTagSize);
    sbufShiftLeft(*buf, kEncryptionPacketNonceSize);
    uint8_t *packet = sbufGetMutablePtr(*buf);
    memmove(packet, packet + kEncryptionPacketNonceSize, view.payload_offset);
    uint8_t *nonce   = packet + view.payload_offset;
    uint8_t *payload = nonce + kEncryptionPacketNonceSize;
    getRandomBytes(nonce, kEncryptionPacketNonceSize);
    /* Addresses, ports and other visible header fields may be rewritten by
     * packet transforms. Bind the transport protocol without binding them. */
    const uint8_t          ad[]   = {view.protocol};
    const wcrypto_status_t status = wCryptoXChaCha20Poly1305Encrypt(
        payload,
        sbufGetWritableCapacity(*buf) - view.payload_offset - kEncryptionPacketNonceSize,
        payload,
        view.payload_length,
        ad,
        sizeof(ad),
        nonce,
        key);
    if (status != kWCryptoOk)
        return kEncryptionPacketCryptoFailed;
    sbufSetLength(*buf, total);
    packetSetLengthAndChecksums(packet, &view, (uint16_t) total, udp_zero);
    sbufSetRecalculateChecksum(*buf, false);
    return kEncryptionPacketOk;
}

encryption_packet_result_t encryptionDecodePacket(const uint8_t key[32], sbuf_t *buf)
{
    assert(buf != NULL && ! sbufIsSplice(buf));
    ipv4_packet_view_t               view   = {0};
    const encryption_packet_result_t parsed = packetView(buf, &view);
    if (parsed != kEncryptionPacketOk)
        return parsed;
    if (view.payload_length < kEncryptionPacketOverhead)
        return kEncryptionPacketMalformed;
    uint8_t   *packet   = sbufGetMutablePtr(buf);
    const bool udp_zero = view.protocol == IPPROTO_UDP && ! sbufGetRecalculateChecksum(buf) &&
                          packet[view.transport_offset + 6] == 0 && packet[view.transport_offset + 7] == 0;
    uint8_t               *nonce   = packet + view.payload_offset;
    uint8_t               *payload = nonce + kEncryptionPacketNonceSize;
    const uint8_t          ad[]    = {view.protocol};
    const wcrypto_status_t status =
        wCryptoXChaCha20Poly1305Decrypt(payload,
                                        sbufGetWritableCapacity(buf) - view.payload_offset - kEncryptionPacketNonceSize,
                                        payload,
                                        view.payload_length - kEncryptionPacketNonceSize,
                                        ad,
                                        sizeof(ad),
                                        nonce,
                                        key);
    if (status != kWCryptoOk)
        return status == kWCryptoAuthenticationFailed ? kEncryptionPacketAuthentication : kEncryptionPacketCryptoFailed;
    memmove(packet + kEncryptionPacketNonceSize, packet, view.payload_offset);
    sbufShiftRight(buf, kEncryptionPacketNonceSize);
    const uint16_t total = view.ip_total_length - kEncryptionPacketOverhead;
    sbufSetLength(buf, total);
    packetSetLengthAndChecksums(sbufGetMutablePtr(buf), &view, total, udp_zero);
    sbufSetRecalculateChecksum(buf, false);
    return kEncryptionPacketOk;
}

const char *encryptionPacketResultName(encryption_packet_result_t result)
{
    switch (result)
    {
    case kEncryptionPacketOk:
        return "ok";
    case kEncryptionPacketMalformed:
        return "malformed IPv4 transport packet";
    case kEncryptionPacketFragmented:
        return "fragmented IPv4 packet";
    case kEncryptionPacketProtocol:
        return "packet protocol must be TCP or UDP";
    case kEncryptionPacketChecksum:
        return "invalid visible packet checksum";
    case kEncryptionPacketTooLarge:
        return "encrypted packet exceeds the IPv4 length limit";
    case kEncryptionPacketAuthentication:
        return "packet authentication failed";
    case kEncryptionPacketCryptoFailed:
        return "packet crypto operation failed";
    }
    return "unknown packet result";
}
