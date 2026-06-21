#include "dns.h"

enum
{
    kDnsHeaderSize           = 12,
    kDnsQuestionTail         = 4,
    kDnsMaxWireNameLen       = 255,
    kDnsClassIn              = 1,
    kDnsTypeA                = 1,
    kDnsTypeNs               = 2,
    kDnsTypeCname            = 5,
    kDnsTypeSoa              = 6,
    kDnsTypePtr              = 12,
    kDnsTypeMx               = 15,
    kDnsTypeTxt              = 16,
    kDnsTypeAaaa             = 28,
    kDnsTypeSrv              = 33,
    kDnsTypeSvcb             = 64,
    kDnsTypeHttps            = 65,
    kDnsTypeAny              = 255,
    kDnsTypeOpt              = 41,
    kDnsFlagRecursionDesired = 0x0100
};

typedef struct junkdatagramsender_dns_writer_s
{
    sbuf_t  *buf;
    uint32_t pos;
    uint32_t capacity;
} junkdatagramsender_dns_writer_t;

static bool junkdatagramsenderDnsCanWrite(const junkdatagramsender_dns_writer_t *writer, uint32_t len)
{
    return writer->pos <= writer->capacity && len <= writer->capacity - writer->pos;
}

static bool junkdatagramsenderDnsPutBytes(junkdatagramsender_dns_writer_t *writer, const void *src, uint32_t len)
{
    if (! junkdatagramsenderDnsCanWrite(writer, len))
    {
        return false;
    }

    memoryCopy(sbufGetMutablePtr(writer->buf) + writer->pos, src, len);
    writer->pos += len;
    return true;
}

static bool junkdatagramsenderDnsPutU8(junkdatagramsender_dns_writer_t *writer, uint8_t value)
{
    return junkdatagramsenderDnsPutBytes(writer, &value, sizeof(value));
}

static bool junkdatagramsenderDnsPutU16(junkdatagramsender_dns_writer_t *writer, uint16_t value)
{
    uint16_t network_value = htobe16(value);
    return junkdatagramsenderDnsPutBytes(writer, &network_value, sizeof(network_value));
}

static bool junkdatagramsenderDnsPutU32(junkdatagramsender_dns_writer_t *writer, uint32_t value)
{
    uint32_t network_value = htobe32(value);
    return junkdatagramsenderDnsPutBytes(writer, &network_value, sizeof(network_value));
}

static const char *junkdatagramsenderDnsFindDot(const char *label)
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

static bool junkdatagramsenderDnsPutQname(junkdatagramsender_dns_writer_t *writer, const char *name)
{
    const uint32_t start_pos = writer->pos;
    const char    *label     = name;

    if (name == NULL || name[0] == '\0')
    {
        return false;
    }

    if (name[0] == '.' && name[1] == '\0')
    {
        return junkdatagramsenderDnsPutU8(writer, 0);
    }

    while (*label != '\0')
    {
        const char *dot       = junkdatagramsenderDnsFindDot(label);
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
        if ((writer->pos - start_pos) + 1U + (uint32_t) label_len + 1U > kDnsMaxWireNameLen)
        {
            return false;
        }

        if (! junkdatagramsenderDnsPutU8(writer, (uint8_t) label_len) ||
            ! junkdatagramsenderDnsPutBytes(writer, label, (uint32_t) label_len))
        {
            return false;
        }

        if (dot == NULL)
        {
            break;
        }
        label = dot + 1;
    }

    return junkdatagramsenderDnsPutU8(writer, 0);
}

static bool junkdatagramsenderDnsBuildQuery(sbuf_t *buf, uint16_t id, const char *qname, uint16_t qtype,
                                            uint16_t qclass, bool recursion_desired, bool add_edns0,
                                            uint16_t edns_udp_size)
{
    junkdatagramsender_dns_writer_t writer = {
        .buf      = buf,
        .pos      = 0,
        .capacity = sbufGetMaximumWriteableSize(buf),
    };

    uint16_t flags   = recursion_desired ? kDnsFlagRecursionDesired : 0;
    uint16_t arcount = add_edns0 ? 1 : 0;

    if (! junkdatagramsenderDnsCanWrite(&writer, kDnsHeaderSize + kDnsQuestionTail))
    {
        return false;
    }

    if (! junkdatagramsenderDnsPutU16(&writer, id) || ! junkdatagramsenderDnsPutU16(&writer, flags) ||
        ! junkdatagramsenderDnsPutU16(&writer, 1) || ! junkdatagramsenderDnsPutU16(&writer, 0) ||
        ! junkdatagramsenderDnsPutU16(&writer, 0) || ! junkdatagramsenderDnsPutU16(&writer, arcount))
    {
        return false;
    }

    if (! junkdatagramsenderDnsPutQname(&writer, qname) || ! junkdatagramsenderDnsPutU16(&writer, qtype) ||
        ! junkdatagramsenderDnsPutU16(&writer, qclass))
    {
        return false;
    }

    if (add_edns0)
    {
        if (edns_udp_size < 512)
        {
            edns_udp_size = 512;
        }

        if (! junkdatagramsenderDnsPutU8(&writer, 0) || ! junkdatagramsenderDnsPutU16(&writer, kDnsTypeOpt) ||
            ! junkdatagramsenderDnsPutU16(&writer, edns_udp_size) || ! junkdatagramsenderDnsPutU32(&writer, 0) ||
            ! junkdatagramsenderDnsPutU16(&writer, 0))
        {
            return false;
        }
    }

    sbufSetLength(buf, writer.pos);
    return true;
}

static const char *junkdatagramsenderDnsRandomBaseDomain(void)
{
    static const char *domains[] = {
        "cloudflare.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "github.com",
        "wikipedia.org",
        "ubuntu.com",
        "debian.org",
        "iana.org",
        "mozilla.org",
    };

    return domains[fastRand32() % (sizeof(domains) / sizeof(domains[0]))];
}

static const char *junkdatagramsenderDnsRandomPrefix(void)
{
    static const char *prefixes[] = {
        "www",
        "api",
        "cdn",
        "mail",
        "static",
        "assets",
        "edge",
        "resolver",
    };

    return prefixes[fastRand32() % (sizeof(prefixes) / sizeof(prefixes[0]))];
}

static uint16_t junkdatagramsenderDnsRandomQtype(void)
{
    static const uint16_t qtypes[] = {
        kDnsTypeA,
        kDnsTypeAaaa,
        kDnsTypeTxt,
        kDnsTypeMx,
        kDnsTypeHttps,
        kDnsTypeSvcb,
        kDnsTypeNs,
        kDnsTypeSoa,
        kDnsTypeSrv,
        kDnsTypePtr,
        kDnsTypeCname,
        kDnsTypeAny,
    };

    return qtypes[fastRand32() % (sizeof(qtypes) / sizeof(qtypes[0]))];
}

static uint16_t junkdatagramsenderDnsRandomEdnsUdpSize(void)
{
    static const uint16_t sizes[] = {512, 1232, 1400, 4096};
    return sizes[fastRand32() % (sizeof(sizes) / sizeof(sizes[0]))];
}

static bool junkdatagramsenderDnsFormatFits(int written, size_t buf_len)
{
    return written > 0 && (size_t) written < buf_len;
}

static const char *junkdatagramsenderDnsBuildRandomName(char *buf, size_t buf_len)
{
    const char *base = junkdatagramsenderDnsRandomBaseDomain();

    switch (fastRand32() % 4U)
    {
    case 0:
        return base;
    case 1:
        if (junkdatagramsenderDnsFormatFits(
                stringNPrintf(buf, buf_len, "%s.%s", junkdatagramsenderDnsRandomPrefix(), base), buf_len))
        {
            return buf;
        }
        return base;
    case 2:
        if (junkdatagramsenderDnsFormatFits(
                stringNPrintf(buf, buf_len, "x%04x.%s", (unsigned int) (fastRand32() & 0xFFFFU), base), buf_len))
        {
            return buf;
        }
        return base;
    default:
        if (junkdatagramsenderDnsFormatFits(stringNPrintf(buf,
                                                          buf_len,
                                                          "%s-%u.%s",
                                                          junkdatagramsenderDnsRandomPrefix(),
                                                          (unsigned int) (fastRand32() % 10000U),
                                                          base),
                                            buf_len))
        {
            return buf;
        }
        return base;
    }
}

bool junkdatagramsenderDnsGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    discard args;

    char        qname[192];
    const char *selected_qname = junkdatagramsenderDnsBuildRandomName(qname, sizeof(qname));

    sbufSetLength(buf, 0);

    return junkdatagramsenderDnsBuildQuery(buf,
                                           (uint16_t) fastRand32(),
                                           selected_qname,
                                           junkdatagramsenderDnsRandomQtype(),
                                           kDnsClassIn,
                                           (fastRand32() % 100U) < 90U,
                                           (fastRand32() % 100U) < 70U,
                                           junkdatagramsenderDnsRandomEdnsUdpSize());
}
