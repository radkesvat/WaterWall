#include "dhcp.h"

enum
{
    kDhcpv4MsgDiscover = 1,
    kDhcpv4MsgRequest  = 3,
    kDhcpv4MsgDecline  = 4,
    kDhcpv4MsgRelease  = 7,
    kDhcpv4MsgInform   = 8,

    kDhcpv4OptSubnetMask     = 1,
    kDhcpv4OptRouter         = 3,
    kDhcpv4OptDns            = 6,
    kDhcpv4OptHostName       = 12,
    kDhcpv4OptDomainName     = 15,
    kDhcpv4OptBroadcastAddr  = 28,
    kDhcpv4OptRequestedIp    = 50,
    kDhcpv4OptLeaseTime      = 51,
    kDhcpv4OptMessageType    = 53,
    kDhcpv4OptServerId       = 54,
    kDhcpv4OptParameterList  = 55,
    kDhcpv4OptMaxMessageSize = 57,
    kDhcpv4OptRenewalTime    = 58,
    kDhcpv4OptRebindingTime  = 59,
    kDhcpv4OptClientId       = 61,
    kDhcpv4OptEnd            = 255,

    kDhcpv4HtypeEthernet  = 1,
    kDhcpv4HlenEthernet   = 6,
    kDhcpv4BootRequest    = 1,
    kDhcpv4MagicCookie    = 0x63825363U,
    kDhcpv4MinPacketSize  = 300,
    kDhcpv4FixedHeaderLen = 236,
    kDhcpv4BroadcastFlag  = 0x8000
};

typedef struct junkdatagramsender_dhcp_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_dhcp_writer_t;

typedef struct junkdatagramsender_dhcp_ipv4_tuple_s
{
    uint8_t client[4];
    uint8_t requested[4];
    uint8_t server[4];
} junkdatagramsender_dhcp_ipv4_tuple_t;

static bool junkdatagramsenderDhcpCanWrite(const junkdatagramsender_dhcp_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderDhcpPutBytes(junkdatagramsender_dhcp_writer_t *writer, const void *src, uint32_t len)
{
    if (! junkdatagramsenderDhcpCanWrite(writer, len))
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

static bool junkdatagramsenderDhcpPutU8(junkdatagramsender_dhcp_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderDhcpPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderDhcpPutU16(junkdatagramsender_dhcp_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderDhcpPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderDhcpPutU32(junkdatagramsender_dhcp_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderDhcpPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderDhcpPutOption(junkdatagramsender_dhcp_writer_t *writer, uint8_t code, const void *data,
                                            uint8_t data_len)
{
    return junkdatagramsenderDhcpPutU8(writer, code) && junkdatagramsenderDhcpPutU8(writer, data_len) &&
           junkdatagramsenderDhcpPutBytes(writer, data, data_len);
}

static bool junkdatagramsenderDhcpPutOptionU8(junkdatagramsender_dhcp_writer_t *writer, uint8_t code, uint8_t value)
{
    return junkdatagramsenderDhcpPutOption(writer, code, &value, sizeof(value));
}

static bool junkdatagramsenderDhcpPutOptionU16(junkdatagramsender_dhcp_writer_t *writer, uint8_t code, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderDhcpPutOption(writer, code, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderDhcpPutOptionIpv4(junkdatagramsender_dhcp_writer_t *writer, uint8_t code,
                                                const uint8_t ip[4])
{
    return ip != NULL && junkdatagramsenderDhcpPutOption(writer, code, ip, 4);
}

static uint8_t junkdatagramsenderDhcpRandomMessageType(void)
{
    static const uint8_t message_types[] = {
        kDhcpv4MsgDiscover,
        kDhcpv4MsgRequest,
        kDhcpv4MsgDecline,
        kDhcpv4MsgRelease,
        kDhcpv4MsgInform,
    };

    return message_types[fastRand32() % (sizeof(message_types) / sizeof(message_types[0]))];
}

static void junkdatagramsenderDhcpRandomMac(uint8_t mac[6])
{
    getRandomBytes(mac, 6);

    mac[0] &= 0xFEU; /* unicast */
    mac[0] |= 0x02U; /* locally administered */
}

static void junkdatagramsenderDhcpRandomIpv4Tuple(junkdatagramsender_dhcp_ipv4_tuple_t *tuple)
{
    uint8_t host = (uint8_t) (20U + (fastRand32() % 200U));

    switch (fastRand32() % 3U)
    {
    case 0:
        tuple->client[0]    = 192;
        tuple->client[1]    = 168;
        tuple->client[2]    = (uint8_t) (fastRand32() % 255U);
        tuple->client[3]    = host;
        tuple->requested[0] = tuple->client[0];
        tuple->requested[1] = tuple->client[1];
        tuple->requested[2] = tuple->client[2];
        tuple->requested[3] = (uint8_t) (host + 1U);
        tuple->server[0]    = tuple->client[0];
        tuple->server[1]    = tuple->client[1];
        tuple->server[2]    = tuple->client[2];
        tuple->server[3]    = 1;
        return;

    case 1:
        tuple->client[0]    = 10;
        tuple->client[1]    = (uint8_t) (fastRand32() % 255U);
        tuple->client[2]    = (uint8_t) (fastRand32() % 255U);
        tuple->client[3]    = host;
        tuple->requested[0] = tuple->client[0];
        tuple->requested[1] = tuple->client[1];
        tuple->requested[2] = tuple->client[2];
        tuple->requested[3] = (uint8_t) (host + 1U);
        tuple->server[0]    = tuple->client[0];
        tuple->server[1]    = tuple->client[1];
        tuple->server[2]    = tuple->client[2];
        tuple->server[3]    = 1;
        return;

    default:
        tuple->client[0]    = 172;
        tuple->client[1]    = (uint8_t) (16U + (fastRand32() % 16U));
        tuple->client[2]    = (uint8_t) (fastRand32() % 255U);
        tuple->client[3]    = host;
        tuple->requested[0] = tuple->client[0];
        tuple->requested[1] = tuple->client[1];
        tuple->requested[2] = tuple->client[2];
        tuple->requested[3] = (uint8_t) (host + 1U);
        tuple->server[0]    = tuple->client[0];
        tuple->server[1]    = tuple->client[1];
        tuple->server[2]    = tuple->client[2];
        tuple->server[3]    = 1;
        return;
    }
}

static const char *junkdatagramsenderDhcpRandomHostname(char *buf, size_t buf_len)
{
    static const char *prefixes[] = {
        "desktop",
        "laptop",
        "android",
        "iphone",
        "printer",
        "camera",
        "tablet",
        "ww",
    };

    const char *prefix = prefixes[fastRand32() % (sizeof(prefixes) / sizeof(prefixes[0]))];
    if (stringFormatFits(
            stringNPrintf(buf, buf_len, "%s-%04x", prefix, (unsigned int) (fastRand32() & 0xFFFFU)), buf_len))
    {
        return buf;
    }
    return "host";
}

static uint8_t junkdatagramsenderDhcpRandomParameterRequestList(uint8_t prl[12])
{
    static const uint8_t common_options[] = {
        kDhcpv4OptSubnetMask,
        kDhcpv4OptRouter,
        kDhcpv4OptDns,
        kDhcpv4OptDomainName,
        kDhcpv4OptBroadcastAddr,
        kDhcpv4OptLeaseTime,
        kDhcpv4OptRenewalTime,
        kDhcpv4OptRebindingTime,
    };

    uint8_t count = (uint8_t) (4U + (fastRand32() % 5U));
    for (uint8_t i = 0; i < count; ++i)
    {
        prl[i] = common_options[i];
    }

    for (uint8_t i = 0; i < count; ++i)
    {
        uint8_t j   = (uint8_t) (fastRand32() % count);
        uint8_t tmp = prl[i];
        prl[i]      = prl[j];
        prl[j]      = tmp;
    }

    return count;
}

static bool junkdatagramsenderDhcpBuildClientMessage(sbuf_t *buf, uint8_t dhcp_message_type, uint32_t xid,
                                                     const uint8_t client_mac[6], uint16_t secs, bool broadcast_flag,
                                                     const uint8_t ciaddr[4], const uint8_t requested_ip[4],
                                                     const uint8_t server_identifier[4], const char *hostname,
                                                     const uint8_t *parameter_request_list,
                                                     uint8_t        parameter_request_list_len)
{
    junkdatagramsender_dhcp_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = sbufGetMaximumWriteableSize(buf),
    };

    if (client_mac == NULL || writer.capacity < kDhcpv4MinPacketSize)
    {
        return false;
    }

    memorySet(sbufGetMutablePtr(buf), 0, kDhcpv4MinPacketSize);

    uint16_t flags = broadcast_flag ? kDhcpv4BroadcastFlag : 0;

    if (! junkdatagramsenderDhcpPutU8(&writer, kDhcpv4BootRequest) ||
        ! junkdatagramsenderDhcpPutU8(&writer, kDhcpv4HtypeEthernet) ||
        ! junkdatagramsenderDhcpPutU8(&writer, kDhcpv4HlenEthernet) || ! junkdatagramsenderDhcpPutU8(&writer, 0) ||
        ! junkdatagramsenderDhcpPutU32(&writer, xid) || ! junkdatagramsenderDhcpPutU16(&writer, secs) ||
        ! junkdatagramsenderDhcpPutU16(&writer, flags))
    {
        return false;
    }

    if (ciaddr != NULL)
    {
        if (! junkdatagramsenderDhcpPutBytes(&writer, ciaddr, 4))
        {
            return false;
        }
    }
    else if (! junkdatagramsenderDhcpPutU32(&writer, 0))
    {
        return false;
    }

    if (! junkdatagramsenderDhcpPutU32(&writer, 0) || ! junkdatagramsenderDhcpPutU32(&writer, 0) ||
        ! junkdatagramsenderDhcpPutU32(&writer, 0) || ! junkdatagramsenderDhcpPutBytes(&writer, client_mac, 6))
    {
        return false;
    }

    if (! junkdatagramsenderDhcpCanWrite(&writer, kDhcpv4FixedHeaderLen - writer.pos))
    {
        return false;
    }
    writer.pos = kDhcpv4FixedHeaderLen;

    if (! junkdatagramsenderDhcpPutU32(&writer, kDhcpv4MagicCookie) ||
        ! junkdatagramsenderDhcpPutOptionU8(&writer, kDhcpv4OptMessageType, dhcp_message_type))
    {
        return false;
    }

    uint8_t client_id[7];
    client_id[0] = kDhcpv4HtypeEthernet;
    memoryCopy(client_id + 1, client_mac, 6);
    if (! junkdatagramsenderDhcpPutOption(&writer, kDhcpv4OptClientId, client_id, sizeof(client_id)) ||
        ! junkdatagramsenderDhcpPutOptionU16(&writer, kDhcpv4OptMaxMessageSize, 576))
    {
        return false;
    }

    if (hostname != NULL && hostname[0] != '\0')
    {
        size_t hostname_len = stringLength(hostname);
        if (hostname_len > UINT8_MAX ||
            ! junkdatagramsenderDhcpPutOption(&writer, kDhcpv4OptHostName, hostname, (uint8_t) hostname_len))
        {
            return false;
        }
    }

    if (requested_ip != NULL && ! junkdatagramsenderDhcpPutOptionIpv4(&writer, kDhcpv4OptRequestedIp, requested_ip))
    {
        return false;
    }
    if (server_identifier != NULL &&
        ! junkdatagramsenderDhcpPutOptionIpv4(&writer, kDhcpv4OptServerId, server_identifier))
    {
        return false;
    }
    if (parameter_request_list != NULL && parameter_request_list_len > 0 &&
        ! junkdatagramsenderDhcpPutOption(
            &writer, kDhcpv4OptParameterList, parameter_request_list, parameter_request_list_len))
    {
        return false;
    }

    if (! junkdatagramsenderDhcpPutU8(&writer, kDhcpv4OptEnd))
    {
        return false;
    }

    if (writer.pos < kDhcpv4MinPacketSize)
    {
        writer.pos = kDhcpv4MinPacketSize;
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

bool junkdatagramsenderDhcpGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    discard args;

    uint8_t                              mac[6];
    uint8_t                              prl[12];
    char                                 hostname[32];
    junkdatagramsender_dhcp_ipv4_tuple_t tuple;

    junkdatagramsenderDhcpRandomMac(mac);
    junkdatagramsenderDhcpRandomIpv4Tuple(&tuple);

    uint8_t     msg_type          = junkdatagramsenderDhcpRandomMessageType();
    const bool  selecting_request = msg_type == kDhcpv4MsgRequest && (fastRand32() % 2U) == 0;
    const bool  include_hostname  = (fastRand32() % 100U) < 85U;
    const char *host    = include_hostname ? junkdatagramsenderDhcpRandomHostname(hostname, sizeof(hostname)) : NULL;
    uint8_t     prl_len = junkdatagramsenderDhcpRandomParameterRequestList(prl);

    const uint8_t *ciaddr            = NULL;
    const uint8_t *requested_ip      = NULL;
    const uint8_t *server_identifier = NULL;

    switch (msg_type)
    {
    case kDhcpv4MsgDiscover:
        break;

    case kDhcpv4MsgRequest:
        if (selecting_request)
        {
            requested_ip      = tuple.requested;
            server_identifier = tuple.server;
        }
        else
        {
            ciaddr = tuple.client;
        }
        break;

    case kDhcpv4MsgDecline:
        requested_ip      = tuple.requested;
        server_identifier = tuple.server;
        break;

    case kDhcpv4MsgRelease:
        ciaddr            = tuple.client;
        server_identifier = tuple.server;
        prl_len           = 0;
        break;

    case kDhcpv4MsgInform:
        ciaddr = tuple.client;
        break;

    default:
        return false;
    }

    sbufSetLength(buf, 0);
    return junkdatagramsenderDhcpBuildClientMessage(buf,
                                                    msg_type,
                                                    fastRand32(),
                                                    mac,
                                                    (uint16_t) (fastRand32() % 8U),
                                                    msg_type == kDhcpv4MsgDiscover || ((fastRand32() % 100U) < 30U),
                                                    ciaddr,
                                                    requested_ip,
                                                    server_identifier,
                                                    host,
                                                    prl_len > 0 ? prl : NULL,
                                                    prl_len);
}
