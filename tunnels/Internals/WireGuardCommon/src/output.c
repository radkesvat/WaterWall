#include "peer_store.h"

#include "loggers/network_logger.h"

bool wireguardCommonPeerCanSend(wireguard_peer_t *peer)
{
    wireguard_keypair_t *key = &peer->curr_keypair;
    if (! key->valid || ! key->sending_valid)
        return false;
    if (wireguardExpired(key->keypair_millis, REJECT_AFTER_TIME) || key->sending_counter >= REJECT_AFTER_MESSAGES)
    {
        LOGD("WireGuard: transport key expired or message limit reached (sending_counter=%" PRIu64 ")",
             key->sending_counter);
        keypairDestroy(key);
        wireguardPeerSyncReceivers(peer);
        return false;
    }
    return true;
}

err_t wireguardifOutputToPeer(wireguard_device_t *device, sbuf_t *q, const ip_addr_t *ipaddr, wireguard_peer_t *peer)
{
    assert(q);
    discard ipaddr;

    const uint32_t unpadded_len = sbufGetLength(q);
    if (! wireguardCommonPeerCanSend(peer))
    {
        if (unpadded_len != 0 && device->callbacks.key_unavailable != NULL)
            device->callbacks.key_unavailable(device->context, q, peer);
        else
        {
            LOGD("WireGuard: dropping packet: no valid transport keys (packet_bytes=%u)", unpadded_len);
            reuseBuffer(q);
        }
        return ERR_CONN;
    }

    const uint32_t header_len = sizeof(message_transport_data_t);
    uint32_t       padded_len = unpadded_len;
    if (unpadded_len < device->padding_mtu)
        padded_len = min((unpadded_len + 15U) & ~15U, device->padding_mtu);
    if (UNLIKELY(sbufGetHeadroom(q) < header_len))
    {
        LOGW("WireGuard: dropping packet: insufficient left padding for transport header "
             "(packet_bytes=%u, headroom_bytes=%zu, required_headroom_bytes=%u)",
             unpadded_len,
             sbufGetHeadroom(q),
             header_len);
        reuseBuffer(q);
        return ERR_BUF;
    }

    q = sbufReserveSpace(q, padded_len + WIREGUARD_AUTHTAG_LEN);
    sbufSetLength(q, padded_len + WIREGUARD_AUTHTAG_LEN);
    if (padded_len > unpadded_len)
        memoryZero(sbufGetMutablePtr(q) + unpadded_len, padded_len - unpadded_len);
    sbufShiftLeft(q, header_len);
    sbufWriteZeros(q, header_len);

    wireguard_keypair_t      *keypair = &peer->curr_keypair;
    message_transport_data_t *hdr     = (message_transport_data_t *) sbufGetMutablePtr(q);
    hdr->type                         = MESSAGE_TRANSPORT_DATA;
    hdr->receiver                     = keypair->remote_index;
    U64TO8_LITTLE(hdr->counter, keypair->sending_counter);
    if (UNLIKELY(! wireguardEncryptPacket(
            hdr->enc_packet, sbufGetWritableCapacity(q) - header_len, hdr->enc_packet, padded_len, keypair)))
    {
        LOGW("WireGuard: dropping packet: transport encryption failed "
             "(payload_bytes=%u, padded_bytes=%u, auth_tag_bytes=%u)",
             unpadded_len,
             padded_len,
             (unsigned) WIREGUARD_AUTHTAG_LEN);
        reuseBuffer(q);
        return ERR_IF;
    }

    if (keypair->sending_counter >= REKEY_AFTER_MESSAGES)
        peer->send_handshake = true;
    if (keypair->initiator)
        wireguardRequestRekeyAtAge(peer, keypair, REKEY_AFTER_TIME);

    wireguardBeginProcessing(device);
    const err_t result = wireguardifPeerOutput(device, q, peer, unpadded_len != 0);
    if (result == ERR_OK && peer->valid)
        peer->last_tx = wireguardRecoveryNow();
    wireguardEndProcessing(device);
    return result;
}

void wireguardCommonSendInner(wireguard_device_t *dev, sbuf_t *buf)
{

    if (UNLIKELY(sbufGetRecalculateChecksum(buf) && ! packettunnelConsumeChecksumRequest(buf)))
    {
        reuseBuffer(buf);
        return;
    }
    uint32_t buf_len = sbufGetLength(buf);
    uint8_t  version;

    if (UNLIKELY(buf_len < sizeof(ip4_hdr_t)))
    {
        reuseBuffer(buf);
        return;
    }
    uint8_t *data = sbufGetMutablePtr(buf);
    version       = IP_HDR_GET_VERSION(data);

    if (UNLIKELY((version == 6) && (buf_len < sizeof(ip6_hdr_t))))
    {
        reuseBuffer(buf);
        return;
    }

    wireguard_peer_t *peer = NULL;
    ip_addr_t         dest;

    if (version == 4)
    {
        ip4_hdr_t *header = (ip4_hdr_t *) data;
        ipAddrCopyFromIp4(dest, header->dest);
        peer = wireguardCommonPeerForIp(dev, &dest);
    }
    else if (version == 6)
    {
        ip6_hdr_t *header = (ip6_hdr_t *) data;
        ip6_addr_t dest_ip6;
        ip6AddrCopyFromPacket(dest_ip6, header->dest);
        ipAddrCopyFromIp6(dest, dest_ip6);
        peer = wireguardCommonPeerForIp(dev, &dest);
    }

    if (peer)
    {
        wireguardifOutputToPeer(dev, buf, &dest, peer);
    }
    else
    {
        LOGD("WireGuard: dropping packet: no allowed-IP peer route "
             "(packet_bytes=%u, ip_version=%u)",
             buf_len,
             (unsigned) version);
        reuseBuffer(buf);
    }
}
