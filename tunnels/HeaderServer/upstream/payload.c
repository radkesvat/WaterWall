#include "structure.h"

#include "loggers/network_logger.h"

static const uint8_t kHeaderServerProxyProtocolV2Signature[kHeaderServerProxyProtocolV2SignatureSize] = {
    0x0D,
    0x0A,
    0x0D,
    0x0A,
    0x00,
    0x0D,
    0x0A,
    0x51,
    0x55,
    0x49,
    0x54,
    0x0A,
};

enum
{
    kHeaderServerProxyProtocolV2VersionMask         = 0xF0,
    kHeaderServerProxyProtocolV2Version             = 0x20,
    kHeaderServerProxyProtocolV2VersionCommandProxy = 0x21,
    kHeaderServerProxyProtocolV2FamilyTcp4          = 0x11,
};

typedef enum headerserver_header_parse_result_e
{
    kHeaderServerHeaderParseNeedMore = 0,
    kHeaderServerHeaderParseDone,
    kHeaderServerHeaderParseError
} headerserver_header_parse_result_t;

static bool headerserverReadHeaderPort(headerserver_lstate_t *ls, line_t *l, uint16_t *port_out)
{
    if (bufferstreamGetBufLen(&ls->read_stream) < kHeaderServerHeaderSize)
    {
        return false;
    }

    sbuf_t  *header = bufferstreamReadExact(&ls->read_stream, kHeaderServerHeaderSize);
    uint16_t port_network;

    sbufReadUnAlignedUI16(header, &port_network);
    lineReuseBuffer(l, header);

    *port_out = ntohs(port_network);
    return true;
}

static bool headerserverStreamPrefixCanMatch(buffer_stream_t *stream, const uint8_t *expected, size_t expected_len)
{
    size_t available   = bufferstreamGetBufLen(stream);
    size_t compare_len = available < expected_len ? available : expected_len;

    for (size_t i = 0; i < compare_len; ++i)
    {
        if (bufferstreamViewByteAt(stream, i) != expected[i])
        {
            return false;
        }
    }

    return true;
}

static bool headerserverParseUint16Token(const char *value, uint16_t *out)
{
    if (value == NULL || value[0] == '\0')
    {
        return false;
    }

    uint32_t parsed = 0;
    for (const char *p = value; *p != '\0'; ++p)
    {
        if (*p < '0' || *p > '9')
        {
            return false;
        }

        parsed = (parsed * 10U) + (uint32_t) (*p - '0');
        if (parsed > UINT16_MAX)
        {
            return false;
        }
    }

    *out = (uint16_t) parsed;
    return true;
}

static bool headerserverParseIpv4Token(const char *value, ip_addr_t *out)
{
    *out = (ip_addr_t) {0};
    return ipaddr_aton(value, out) && out->type == IPADDR_TYPE_V4;
}

static size_t headerserverSplitProxyProtocolV1Line(char *line, char **tokens, size_t token_capacity)
{
    size_t count  = 0;
    char  *cursor = line;

    while (*cursor != '\0')
    {
        while (*cursor == ' ')
        {
            ++cursor;
        }

        if (*cursor == '\0')
        {
            break;
        }

        if (count == token_capacity)
        {
            return token_capacity + 1U;
        }

        tokens[count++] = cursor;

        while (*cursor != '\0' && *cursor != ' ')
        {
            ++cursor;
        }

        if (*cursor == ' ')
        {
            *cursor = '\0';
            ++cursor;
        }
    }

    return count;
}

static headerserver_header_parse_result_t headerserverReadProxyProtocolV1(headerserver_lstate_t *ls, line_t *l)
{
    buffer_stream_t *stream = &ls->read_stream;
    size_t           line_end;

    if (! bufferstreamFindCRLF(stream, &line_end))
    {
        if (bufferstreamGetBufLen(stream) > kHeaderServerProxyProtocolV1MaxHeaderSize)
        {
            LOGE("HeaderServer: PROXY protocol v1 header is longer than %u bytes",
                 (unsigned int) kHeaderServerProxyProtocolV1MaxHeaderSize);
            return kHeaderServerHeaderParseError;
        }

        return kHeaderServerHeaderParseNeedMore;
    }

    size_t full_len = line_end + 2U;
    if (full_len > kHeaderServerProxyProtocolV1MaxHeaderSize)
    {
        LOGE("HeaderServer: PROXY protocol v1 header is longer than %u bytes",
             (unsigned int) kHeaderServerProxyProtocolV1MaxHeaderSize);
        return kHeaderServerHeaderParseError;
    }

    char line[kHeaderServerProxyProtocolV1MaxHeaderSize + 1U];
    bufferstreamViewBytesAt(stream, 0, (uint8_t *) line, line_end);
    line[line_end] = '\0';

    char  *tokens[6];
    size_t token_capacity = sizeof(tokens) / sizeof(tokens[0]);
    size_t token_count    = headerserverSplitProxyProtocolV1Line(line, tokens, token_capacity);

    if (token_count < 2 || stringCompare(tokens[0], "PROXY") != 0)
    {
        LOGE("HeaderServer: invalid PROXY protocol v1 header");
        return kHeaderServerHeaderParseError;
    }

    if (stringCompare(tokens[1], "UNKNOWN") == 0)
    {
        LOGE("HeaderServer: PROXY protocol v1 UNKNOWN header does not provide IPv4 source fields");
        return kHeaderServerHeaderParseError;
    }

    if (token_count != token_capacity || stringCompare(tokens[1], "TCP4") != 0)
    {
        LOGE("HeaderServer: unsupported PROXY protocol v1 address family");
        return kHeaderServerHeaderParseError;
    }

    ip_addr_t src_ip;
    ip_addr_t ignored_dest_ip;
    if (! headerserverParseIpv4Token(tokens[2], &src_ip) || ! headerserverParseIpv4Token(tokens[3], &ignored_dest_ip))
    {
        LOGE("HeaderServer: invalid PROXY protocol v1 IPv4 address");
        return kHeaderServerHeaderParseError;
    }

    uint16_t src_port;
    uint16_t ignored_dest_port;
    if (! headerserverParseUint16Token(tokens[4], &src_port) ||
        ! headerserverParseUint16Token(tokens[5], &ignored_dest_port))
    {
        LOGE("HeaderServer: invalid PROXY protocol v1 port");
        return kHeaderServerHeaderParseError;
    }

    addresscontextSetIpPortProtocol(lineGetSourceAddressContext(l), &src_ip, src_port, IP_PROTO_TCP);
    lineReuseBuffer(l, bufferstreamReadExact(stream, full_len));
    return kHeaderServerHeaderParseDone;
}

static headerserver_header_parse_result_t headerserverReadProxyProtocolV2(headerserver_lstate_t *ls, line_t *l)
{
    buffer_stream_t *stream    = &ls->read_stream;
    size_t           available = bufferstreamGetBufLen(stream);

    if (available < kHeaderServerProxyProtocolV2BaseHeaderSize)
    {
        return kHeaderServerHeaderParseNeedMore;
    }

    uint8_t header[kHeaderServerProxyProtocolV2BaseHeaderSize];
    bufferstreamViewBytesAt(stream, 0, header, sizeof(header));

    if (memoryCompare(header, kHeaderServerProxyProtocolV2Signature, kHeaderServerProxyProtocolV2SignatureSize) != 0)
    {
        LOGE("HeaderServer: invalid PROXY protocol v2 signature");
        return kHeaderServerHeaderParseError;
    }

    uint8_t version_command = header[12];
    if ((version_command & kHeaderServerProxyProtocolV2VersionMask) != kHeaderServerProxyProtocolV2Version)
    {
        LOGE("HeaderServer: unsupported PROXY protocol v2 version");
        return kHeaderServerHeaderParseError;
    }

    if (version_command != kHeaderServerProxyProtocolV2VersionCommandProxy)
    {
        LOGE("HeaderServer: unsupported PROXY protocol v2 command");
        return kHeaderServerHeaderParseError;
    }

    if (header[13] != kHeaderServerProxyProtocolV2FamilyTcp4)
    {
        LOGE("HeaderServer: unsupported PROXY protocol v2 address family or transport");
        return kHeaderServerHeaderParseError;
    }

    uint16_t len_network;
    memoryCopy(&len_network, header + 14, sizeof(len_network));

    uint16_t address_len = ntohs(len_network);
    if (address_len < kHeaderServerProxyProtocolV2Ipv4AddressSize)
    {
        LOGE("HeaderServer: PROXY protocol v2 TCP4 address block is too short");
        return kHeaderServerHeaderParseError;
    }

    size_t full_len = kHeaderServerProxyProtocolV2BaseHeaderSize + (size_t) address_len;
    if (available < full_len)
    {
        return kHeaderServerHeaderParseNeedMore;
    }

    uint8_t address_block[kHeaderServerProxyProtocolV2Ipv4AddressSize];
    bufferstreamViewBytesAt(stream, kHeaderServerProxyProtocolV2BaseHeaderSize, address_block, sizeof(address_block));

    ip_addr_t src_ip = {0};
    src_ip.type      = IPADDR_TYPE_V4;
    memoryCopy(&src_ip.u_addr.ip4.addr, address_block, sizeof(src_ip.u_addr.ip4.addr));

    uint16_t src_port_network;
    memoryCopy(&src_port_network, address_block + 8, sizeof(src_port_network));

    addresscontextSetIpPortProtocol(lineGetSourceAddressContext(l), &src_ip, ntohs(src_port_network), IP_PROTO_TCP);
    lineReuseBuffer(l, bufferstreamReadExact(stream, full_len));
    return kHeaderServerHeaderParseDone;
}

static headerserver_header_parse_result_t headerserverReadProxyProtocol(headerserver_lstate_t *ls, line_t *l)
{
    buffer_stream_t *stream = &ls->read_stream;

    if (bufferstreamGetBufLen(stream) == 0)
    {
        return kHeaderServerHeaderParseNeedMore;
    }

    if (headerserverStreamPrefixCanMatch(
            stream, kHeaderServerProxyProtocolV2Signature, kHeaderServerProxyProtocolV2SignatureSize))
    {
        return headerserverReadProxyProtocolV2(ls, l);
    }

    static const uint8_t v1_prefix[] = "PROXY ";
    if (headerserverStreamPrefixCanMatch(stream, v1_prefix, sizeof(v1_prefix) - 1U))
    {
        return headerserverReadProxyProtocolV1(ls, l);
    }

    LOGE("HeaderServer: expected PROXY protocol v1 or v2 header");
    return kHeaderServerHeaderParseError;
}

static headerserver_header_parse_result_t headerserverReadConfiguredHeader(tunnel_t *t, line_t *l)
{
    headerserver_tstate_t *ts = tunnelGetState(t);
    headerserver_lstate_t *ls = lineGetState(l, t);

    switch (ts->override_mode)
    {
    case kHeaderServerOverrideModeHeaderPort: {
        uint16_t port = 0;
        if (! headerserverReadHeaderPort(ls, l, &port))
        {
            return kHeaderServerHeaderParseNeedMore;
        }

        if (port < kHeaderServerMinAllowedPort)
        {
            LOGW("HeaderServer: received invalid header port %u, closing line", (unsigned int) port);
            return kHeaderServerHeaderParseError;
        }

        addresscontextSetPort(lineGetDestinationAddressContext(l), port);
        return kHeaderServerHeaderParseDone;
    }

    case kHeaderServerOverrideModeProxyProtocolSourceFields:
        return headerserverReadProxyProtocol(ls, l);

    default:
        LOGE("HeaderServer: invalid delayed header mode");
        return kHeaderServerHeaderParseError;
    }
}

static void headerserverForwardBufferedPayload(tunnel_t *t, line_t *l)
{
    headerserver_lstate_t *ls  = lineGetState(l, t);
    sbuf_t                *buf = bufferstreamFullRead(&ls->read_stream);

    if (buf != NULL)
    {
        discard withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
    }
}

void headerserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kHeaderServerPhaseNone)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (ls->phase == kHeaderServerPhaseEstablished)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    bufferstreamPush(&ls->read_stream, buf);

    headerserver_header_parse_result_t result = headerserverReadConfiguredHeader(t, l);
    if (result == kHeaderServerHeaderParseNeedMore)
    {
        return;
    }

    if (result == kHeaderServerHeaderParseError)
    {
        headerserverCloseLineFromProtocolError(t, l);
        return;
    }

    ls->phase = kHeaderServerPhaseEstablished;

    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        return;
    }

    headerserverForwardBufferedPayload(t, l);
}
