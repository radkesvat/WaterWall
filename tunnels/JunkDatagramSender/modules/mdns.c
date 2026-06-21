#include "mdns.h"

enum
{
    kMdnsHeaderSize = 12,
    kMdnsMaxWireNameLen = 255,
    kMdnsClassIn = 1,
    kMdnsClassInCacheFlush = 0x8001,
    kMdnsClassInUnicastResponse = 0x8001,
    kMdnsTypeA = 1,
    kMdnsTypePtr = 12,
    kMdnsTypeTxt = 16,
    kMdnsTypeAaaa = 28,
    kMdnsTypeSrv = 33,
    kMdnsTypeAny = 255,
    kMdnsResponseAuthoritative = 0x8400,
    kMdnsTtlHost = 120,
    kMdnsTtlService = 4500,
};

typedef struct junkdatagramsender_mdns_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_mdns_writer_t;

typedef struct junkdatagramsender_mdns_service_s
{
    const char *service_type;
    const char *instance_prefix;
    const char *txt1;
    const char *txt2;
    uint16_t    port;
} junkdatagramsender_mdns_service_t;

static bool junkdatagramsenderMdnsCanWrite(const junkdatagramsender_mdns_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderMdnsPutBytes(junkdatagramsender_mdns_writer_t *writer, const void *src,
                                           uint32_t len)
{
    if (! junkdatagramsenderMdnsCanWrite(writer, len))
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

static bool junkdatagramsenderMdnsPutU8(junkdatagramsender_mdns_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderMdnsPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderMdnsPutU16(junkdatagramsender_mdns_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderMdnsPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderMdnsPutU32(junkdatagramsender_mdns_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderMdnsPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderMdnsPatchU16(junkdatagramsender_mdns_writer_t *writer, uint32_t offset,
                                           uint16_t value)
{
    uint16_t network_value = htobe16(value);

    if (offset > writer->pos || sizeof(network_value) > writer->pos - offset)
    {
        return false;
    }

    memoryCopy(sbufGetMutablePtr(writer->buf) + offset, &network_value, sizeof(network_value));
    return true;
}

static const char *junkdatagramsenderMdnsFindDot(const char *label)
{
    while (*label != '\0')
    {
        if (*label == '.')
        {
            return label;
        }
        ++label;
    }
    return NULL;
}

static bool junkdatagramsenderMdnsPutName(junkdatagramsender_mdns_writer_t *writer, const char *name)
{
    const uint32_t start_pos = writer->pos;
    const char    *label = name;

    if (name == NULL || name[0] == '\0')
    {
        return false;
    }

    if (name[0] == '.' && name[1] == '\0')
    {
        return junkdatagramsenderMdnsPutU8(writer, 0);
    }

    while (*label != '\0')
    {
        const char *dot = junkdatagramsenderMdnsFindDot(label);
        size_t      label_len = dot != NULL ? (size_t) (dot - label) : stringLength(label);

        if (label_len == 0)
        {
            if (dot != NULL && dot[1] == '\0')
            {
                break;
            }
            return false;
        }
        if (label_len > 63)
        {
            return false;
        }
        if ((writer->pos - start_pos) + 1U + (uint32_t) label_len + 1U > kMdnsMaxWireNameLen)
        {
            return false;
        }

        if (! junkdatagramsenderMdnsPutU8(writer, (uint8_t) label_len) ||
            ! junkdatagramsenderMdnsPutBytes(writer, label, (uint32_t) label_len))
        {
            return false;
        }

        if (dot == NULL)
        {
            break;
        }
        label = dot + 1;
    }

    return junkdatagramsenderMdnsPutU8(writer, 0);
}

static bool junkdatagramsenderMdnsPutHeader(junkdatagramsender_mdns_writer_t *writer, uint16_t flags,
                                            uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                                            uint16_t arcount)
{
    return junkdatagramsenderMdnsPutU16(writer, 0) &&
           junkdatagramsenderMdnsPutU16(writer, flags) &&
           junkdatagramsenderMdnsPutU16(writer, qdcount) &&
           junkdatagramsenderMdnsPutU16(writer, ancount) &&
           junkdatagramsenderMdnsPutU16(writer, nscount) &&
           junkdatagramsenderMdnsPutU16(writer, arcount);
}

static bool junkdatagramsenderMdnsPutQuestion(junkdatagramsender_mdns_writer_t *writer, const char *qname,
                                              uint16_t qtype, bool prefer_unicast_response)
{
    return junkdatagramsenderMdnsPutName(writer, qname) &&
           junkdatagramsenderMdnsPutU16(writer, qtype) &&
           junkdatagramsenderMdnsPutU16(
               writer, prefer_unicast_response ? kMdnsClassInUnicastResponse : kMdnsClassIn);
}

static bool junkdatagramsenderMdnsBeginRecord(junkdatagramsender_mdns_writer_t *writer, const char *name,
                                              uint16_t type, uint16_t rclass, uint32_t ttl,
                                              uint32_t *rdlength_offset, uint32_t *rdata_offset)
{
    if (! junkdatagramsenderMdnsPutName(writer, name) ||
        ! junkdatagramsenderMdnsPutU16(writer, type) ||
        ! junkdatagramsenderMdnsPutU16(writer, rclass) ||
        ! junkdatagramsenderMdnsPutU32(writer, ttl))
    {
        return false;
    }

    *rdlength_offset = writer->pos;
    if (! junkdatagramsenderMdnsPutU16(writer, 0))
    {
        return false;
    }

    *rdata_offset = writer->pos;
    return true;
}

static bool junkdatagramsenderMdnsEndRecord(junkdatagramsender_mdns_writer_t *writer, uint32_t rdlength_offset,
                                            uint32_t rdata_offset)
{
    uint32_t rdlength = writer->pos - rdata_offset;
    if (rdlength > UINT16_MAX)
    {
        return false;
    }

    return junkdatagramsenderMdnsPatchU16(writer, rdlength_offset, (uint16_t) rdlength);
}

static bool junkdatagramsenderMdnsPutARecord(junkdatagramsender_mdns_writer_t *writer, const char *host_name,
                                             const uint8_t ip[4])
{
    uint32_t rdlength_offset = 0;
    uint32_t rdata_offset = 0;

    return ip != NULL &&
           junkdatagramsenderMdnsBeginRecord(writer,
                                             host_name,
                                             kMdnsTypeA,
                                             kMdnsClassInCacheFlush,
                                             kMdnsTtlHost,
                                             &rdlength_offset,
                                             &rdata_offset) &&
           junkdatagramsenderMdnsPutBytes(writer, ip, 4) &&
           junkdatagramsenderMdnsEndRecord(writer, rdlength_offset, rdata_offset);
}

static bool junkdatagramsenderMdnsPutAaaaRecord(junkdatagramsender_mdns_writer_t *writer,
                                                const char *host_name, const uint8_t ip[16])
{
    uint32_t rdlength_offset = 0;
    uint32_t rdata_offset = 0;

    return ip != NULL &&
           junkdatagramsenderMdnsBeginRecord(writer,
                                             host_name,
                                             kMdnsTypeAaaa,
                                             kMdnsClassInCacheFlush,
                                             kMdnsTtlHost,
                                             &rdlength_offset,
                                             &rdata_offset) &&
           junkdatagramsenderMdnsPutBytes(writer, ip, 16) &&
           junkdatagramsenderMdnsEndRecord(writer, rdlength_offset, rdata_offset);
}

static bool junkdatagramsenderMdnsPutPtrRecord(junkdatagramsender_mdns_writer_t *writer, const char *service_type,
                                               const char *instance_name)
{
    uint32_t rdlength_offset = 0;
    uint32_t rdata_offset = 0;

    return junkdatagramsenderMdnsBeginRecord(writer,
                                             service_type,
                                             kMdnsTypePtr,
                                             kMdnsClassIn,
                                             kMdnsTtlService,
                                             &rdlength_offset,
                                             &rdata_offset) &&
           junkdatagramsenderMdnsPutName(writer, instance_name) &&
           junkdatagramsenderMdnsEndRecord(writer, rdlength_offset, rdata_offset);
}

static bool junkdatagramsenderMdnsPutSrvRecord(junkdatagramsender_mdns_writer_t *writer,
                                               const char *instance_name, const char *host_name,
                                               uint16_t port)
{
    uint32_t rdlength_offset = 0;
    uint32_t rdata_offset = 0;

    return junkdatagramsenderMdnsBeginRecord(writer,
                                             instance_name,
                                             kMdnsTypeSrv,
                                             kMdnsClassInCacheFlush,
                                             kMdnsTtlService,
                                             &rdlength_offset,
                                             &rdata_offset) &&
           junkdatagramsenderMdnsPutU16(writer, 0) &&
           junkdatagramsenderMdnsPutU16(writer, 0) &&
           junkdatagramsenderMdnsPutU16(writer, port) &&
           junkdatagramsenderMdnsPutName(writer, host_name) &&
           junkdatagramsenderMdnsEndRecord(writer, rdlength_offset, rdata_offset);
}

static bool junkdatagramsenderMdnsPutTxtItem(junkdatagramsender_mdns_writer_t *writer, const char *value)
{
    size_t value_len = stringLength(value);
    if (value_len > UINT8_MAX)
    {
        return false;
    }

    return junkdatagramsenderMdnsPutU8(writer, (uint8_t) value_len) &&
           junkdatagramsenderMdnsPutBytes(writer, value, (uint32_t) value_len);
}

static bool junkdatagramsenderMdnsPutTxtRecord(junkdatagramsender_mdns_writer_t *writer,
                                               const junkdatagramsender_mdns_service_t *service,
                                               const char *instance_name)
{
    uint32_t rdlength_offset = 0;
    uint32_t rdata_offset = 0;

    if (service == NULL)
    {
        return false;
    }

    if (! junkdatagramsenderMdnsBeginRecord(writer,
                                            instance_name,
                                            kMdnsTypeTxt,
                                            kMdnsClassInCacheFlush,
                                            kMdnsTtlService,
                                            &rdlength_offset,
                                            &rdata_offset) ||
        ! junkdatagramsenderMdnsPutTxtItem(writer, "txtvers=1"))
    {
        return false;
    }

    if (service->txt1 != NULL && ! junkdatagramsenderMdnsPutTxtItem(writer, service->txt1))
    {
        return false;
    }
    if (service->txt2 != NULL && ! junkdatagramsenderMdnsPutTxtItem(writer, service->txt2))
    {
        return false;
    }

    return junkdatagramsenderMdnsEndRecord(writer, rdlength_offset, rdata_offset);
}

static const junkdatagramsender_mdns_service_t *junkdatagramsenderMdnsRandomService(void)
{
    static const junkdatagramsender_mdns_service_t services[] = {
        {.service_type = "_http._tcp.local", .instance_prefix = "web", .txt1 = "path=/", .txt2 = NULL, .port = 80},
        {.service_type = "_ssh._tcp.local", .instance_prefix = "ssh", .txt1 = NULL, .txt2 = NULL, .port = 22},
        {.service_type = "_ipp._tcp.local", .instance_prefix = "printer", .txt1 = "rp=printers/main", .txt2 = "qtotal=1", .port = 631},
        {.service_type = "_airplay._tcp.local", .instance_prefix = "airplay", .txt1 = "model=AppleTV", .txt2 = "srcvers=220.68", .port = 7000},
        {.service_type = "_googlecast._tcp.local", .instance_prefix = "cast", .txt1 = "id=000000000000", .txt2 = "ve=05", .port = 8009},
        {.service_type = "_workstation._tcp.local", .instance_prefix = "workstation", .txt1 = NULL, .txt2 = NULL, .port = 9},
        {.service_type = "_raop._tcp.local", .instance_prefix = "raop", .txt1 = "cn=0,1", .txt2 = "et=0,3,5", .port = 5000},
    };

    return &services[fastRand32() % (sizeof(services) / sizeof(services[0]))];
}

static bool junkdatagramsenderMdnsFormatFits(int written, size_t buf_len)
{
    return written > 0 && (size_t) written < buf_len;
}

static const char *junkdatagramsenderMdnsRandomHostName(char *buf, size_t buf_len)
{
    static const char *prefixes[] = {
        "iphone",
        "macbook",
        "android",
        "printer",
        "camera",
        "desktop",
        "speaker",
        "ww",
    };

    if (junkdatagramsenderMdnsFormatFits(
            stringNPrintf(buf,
                          buf_len,
                          "%s-%04x.local",
                          prefixes[fastRand32() % (sizeof(prefixes) / sizeof(prefixes[0]))],
                          (unsigned int) (fastRand32() & 0xFFFFU)),
            buf_len))
    {
        return buf;
    }
    return "host.local";
}

static const char *junkdatagramsenderMdnsBuildInstanceName(char *buf, size_t buf_len,
                                                           const junkdatagramsender_mdns_service_t *service)
{
    if (service != NULL &&
        junkdatagramsenderMdnsFormatFits(
            stringNPrintf(buf,
                          buf_len,
                          "%s-%04x.%s",
                          service->instance_prefix,
                          (unsigned int) (fastRand32() & 0xFFFFU),
                          service->service_type),
            buf_len))
    {
        return buf;
    }
    return "service._http._tcp.local";
}

static void junkdatagramsenderMdnsRandomIpv4(uint8_t ip[4])
{
    switch (fastRand32() % 3U)
    {
    case 0:
        ip[0] = 192;
        ip[1] = 168;
        ip[2] = (uint8_t) (fastRand32() % 255U);
        ip[3] = (uint8_t) (2U + (fastRand32() % 240U));
        return;
    case 1:
        ip[0] = 10;
        ip[1] = (uint8_t) (fastRand32() % 255U);
        ip[2] = (uint8_t) (fastRand32() % 255U);
        ip[3] = (uint8_t) (2U + (fastRand32() % 240U));
        return;
    default:
        ip[0] = 172;
        ip[1] = (uint8_t) (16U + (fastRand32() % 16U));
        ip[2] = (uint8_t) (fastRand32() % 255U);
        ip[3] = (uint8_t) (2U + (fastRand32() % 240U));
        return;
    }
}

static void junkdatagramsenderMdnsRandomIpv6LinkLocal(uint8_t ip[16])
{
    memorySet(ip, 0, 16);
    ip[0] = 0xFE;
    ip[1] = 0x80;
    getRandomBytes(ip + 8, 8);
}

static bool junkdatagramsenderMdnsBuildQuery(sbuf_t *buf, uint32_t write_limit)
{
    junkdatagramsender_mdns_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};
    char host_name[64];

    uint16_t question_count = (uint16_t) (1U + (fastRand32() % 3U));
    if (! junkdatagramsenderMdnsPutHeader(&writer, 0, question_count, 0, 0, 0))
    {
        return false;
    }

    for (uint16_t i = 0; i < question_count; ++i)
    {
        const junkdatagramsender_mdns_service_t *service = junkdatagramsenderMdnsRandomService();
        const char *qname = service->service_type;
        uint16_t qtype = kMdnsTypePtr;

        switch (fastRand32() % 5U)
        {
        case 0:
            qname = "_services._dns-sd._udp.local";
            qtype = kMdnsTypePtr;
            break;
        case 1:
        case 2:
            qname = service->service_type;
            qtype = kMdnsTypePtr;
            break;
        case 3:
            qname = junkdatagramsenderMdnsRandomHostName(host_name, sizeof(host_name));
            qtype = (fastRand32() % 2U) == 0 ? kMdnsTypeA : kMdnsTypeAaaa;
            break;
        default:
            qname = junkdatagramsenderMdnsRandomHostName(host_name, sizeof(host_name));
            qtype = kMdnsTypeAny;
            break;
        }

        if (! junkdatagramsenderMdnsPutQuestion(&writer, qname, qtype, (fastRand32() % 100U) < 20U))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderMdnsBuildHostAnnouncement(sbuf_t *buf, uint32_t write_limit)
{
    junkdatagramsender_mdns_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};
    char host_name[64];
    uint8_t ipv4[4];
    uint8_t ipv6[16];
    bool include_aaaa = (fastRand32() % 100U) < 45U;

    junkdatagramsenderMdnsRandomIpv4(ipv4);
    junkdatagramsenderMdnsRandomIpv6LinkLocal(ipv6);

    if (! junkdatagramsenderMdnsPutHeader(&writer, kMdnsResponseAuthoritative, 0, include_aaaa ? 2 : 1, 0, 0) ||
        ! junkdatagramsenderMdnsPutARecord(
            &writer, junkdatagramsenderMdnsRandomHostName(host_name, sizeof(host_name)), ipv4))
    {
        return false;
    }

    if (include_aaaa && ! junkdatagramsenderMdnsPutAaaaRecord(&writer, host_name, ipv6))
    {
        return false;
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static bool junkdatagramsenderMdnsBuildServiceAnnouncement(sbuf_t *buf, uint32_t write_limit)
{
    junkdatagramsender_mdns_writer_t writer = {.buf = buf, .pos = 0, .capacity = write_limit};
    const junkdatagramsender_mdns_service_t *service = junkdatagramsenderMdnsRandomService();
    char host_name[64];
    char instance_name[128];
    uint8_t ipv4[4];
    uint8_t ipv6[16];
    bool include_aaaa = (fastRand32() % 100U) < 35U;
    uint16_t answer_count = include_aaaa ? 5 : 4;

    const char *selected_host = junkdatagramsenderMdnsRandomHostName(host_name, sizeof(host_name));
    const char *selected_instance = junkdatagramsenderMdnsBuildInstanceName(
        instance_name, sizeof(instance_name), service);

    junkdatagramsenderMdnsRandomIpv4(ipv4);
    junkdatagramsenderMdnsRandomIpv6LinkLocal(ipv6);

    if (! junkdatagramsenderMdnsPutHeader(&writer, kMdnsResponseAuthoritative, 0, answer_count, 0, 0) ||
        ! junkdatagramsenderMdnsPutPtrRecord(&writer, service->service_type, selected_instance) ||
        ! junkdatagramsenderMdnsPutSrvRecord(&writer, selected_instance, selected_host, service->port) ||
        ! junkdatagramsenderMdnsPutTxtRecord(&writer, service, selected_instance) ||
        ! junkdatagramsenderMdnsPutARecord(&writer, selected_host, ipv4))
    {
        return false;
    }

    if (include_aaaa && ! junkdatagramsenderMdnsPutAaaaRecord(&writer, selected_host, ipv6))
    {
        return false;
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

bool junkdatagramsenderMdnsGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t write_limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < write_limit)
    {
        write_limit = args->max_packet_size;
    }
    if (write_limit < kMdnsHeaderSize || (args != NULL && args->min_packet_size > write_limit))
    {
        return false;
    }

    sbufSetLength(buf, 0);

    switch (fastRand32() % 4U)
    {
    case 0:
        return junkdatagramsenderMdnsBuildHostAnnouncement(buf, write_limit);
    case 1:
        return junkdatagramsenderMdnsBuildServiceAnnouncement(buf, write_limit);
    default:
        return junkdatagramsenderMdnsBuildQuery(buf, write_limit);
    }
}
