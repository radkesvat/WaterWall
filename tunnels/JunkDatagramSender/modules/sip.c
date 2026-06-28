#include "sip.h"

typedef struct junkdatagramsender_sip_request_args_s
{
    const char    *method;
    const char    *request_uri;
    const char    *via_transport;
    const char    *via_sent_by;
    const char    *via_branch;
    unsigned int   max_forwards;
    const char    *from_display;
    const char    *from_uri;
    const char    *from_tag;
    const char    *to_display;
    const char    *to_uri;
    const char    *to_tag;
    const char    *call_id;
    unsigned int   cseq;
    const char    *contact_uri;
    const char    *user_agent;
    const char    *content_type;
    const uint8_t *body;
    size_t         body_len;
    const char    *extra_headers;
} junkdatagramsender_sip_request_args_t;

typedef struct junkdatagramsender_sip_response_args_s
{
    unsigned int   status_code;
    const char    *reason_phrase;
    const char    *via_value;
    const char    *from_value;
    const char    *to_value;
    const char    *call_id;
    unsigned int   cseq;
    const char    *cseq_method;
    const char    *contact_uri;
    const char    *server;
    const char    *content_type;
    const uint8_t *body;
    size_t         body_len;
    const char    *extra_headers;
} junkdatagramsender_sip_response_args_t;

typedef struct junkdatagramsender_sip_identity_s
{
    const char *user;
    const char *display;
    const char *domain;
} junkdatagramsender_sip_identity_t;

static uint32_t junkdatagramsenderSipWriteLimit(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < limit)
    {
        limit = args->max_packet_size;
    }
    return limit;
}

static bool junkdatagramsenderSipAppendChar(uint8_t *out, size_t out_len, size_t *pos, char c)
{
    if (*pos + 1U > out_len)
    {
        return false;
    }
    out[(*pos)++] = (uint8_t) c;
    return true;
}

static bool junkdatagramsenderSipAppendBytes(uint8_t *out, size_t out_len, size_t *pos, const void *data,
                                             size_t data_len)
{
    if (*pos + data_len > out_len)
    {
        return false;
    }
    if (data_len > 0 && data != NULL)
    {
        memoryCopy(out + *pos, data, data_len);
    }
    *pos += data_len;
    return true;
}

static bool junkdatagramsenderSipAppendStr(uint8_t *out, size_t out_len, size_t *pos, const char *s)
{
    if (s == NULL)
    {
        return true;
    }
    return junkdatagramsenderSipAppendBytes(out, out_len, pos, s, stringLength(s));
}

static bool junkdatagramsenderSipAppendUint(uint8_t *out, size_t out_len, size_t *pos, unsigned int value)
{
    char   tmp[16];
    size_t len = 0;

    do
    {
        tmp[len++] = (char) ('0' + (value % 10U));
        value /= 10U;
    } while (value != 0 && len < sizeof(tmp));

    while (len > 0)
    {
        if (! junkdatagramsenderSipAppendChar(out, out_len, pos, tmp[--len]))
        {
            return false;
        }
    }
    return true;
}

static bool junkdatagramsenderSipAppendSize(uint8_t *out, size_t out_len, size_t *pos, size_t value)
{
    char   tmp[32];
    size_t len = 0;

    do
    {
        tmp[len++] = (char) ('0' + (value % 10U));
        value /= 10U;
    } while (value != 0 && len < sizeof(tmp));

    while (len > 0)
    {
        if (! junkdatagramsenderSipAppendChar(out, out_len, pos, tmp[--len]))
        {
            return false;
        }
    }
    return true;
}

static bool junkdatagramsenderSipAppendCrlf(uint8_t *out, size_t out_len, size_t *pos)
{
    return junkdatagramsenderSipAppendStr(out, out_len, pos, "\r\n");
}

static bool junkdatagramsenderSipAppendHeader(uint8_t *out, size_t out_len, size_t *pos, const char *name,
                                              const char *value)
{
    if (name == NULL || value == NULL || value[0] == '\0')
    {
        return true;
    }

    return junkdatagramsenderSipAppendStr(out, out_len, pos, name) &&
           junkdatagramsenderSipAppendStr(out, out_len, pos, ": ") &&
           junkdatagramsenderSipAppendStr(out, out_len, pos, value) &&
           junkdatagramsenderSipAppendCrlf(out, out_len, pos);
}

static bool junkdatagramsenderSipAppendNameAddr(uint8_t *out, size_t out_len, size_t *pos, const char *display,
                                                const char *uri)
{
    if (uri == NULL || uri[0] == '\0')
    {
        return false;
    }

    if (display != NULL && display[0] != '\0')
    {
        if (! junkdatagramsenderSipAppendChar(out, out_len, pos, '"') ||
            ! junkdatagramsenderSipAppendStr(out, out_len, pos, display) ||
            ! junkdatagramsenderSipAppendStr(out, out_len, pos, "\" "))
        {
            return false;
        }
    }

    return junkdatagramsenderSipAppendChar(out, out_len, pos, '<') &&
           junkdatagramsenderSipAppendStr(out, out_len, pos, uri) &&
           junkdatagramsenderSipAppendChar(out, out_len, pos, '>');
}

static bool junkdatagramsenderSipAppendFromOrTo(uint8_t *out, size_t out_len, size_t *pos, const char *header_name,
                                                const char *display, const char *uri, const char *tag)
{
    if (header_name == NULL || uri == NULL || uri[0] == '\0')
    {
        return false;
    }

    if (! junkdatagramsenderSipAppendStr(out, out_len, pos, header_name) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, pos, ": ") ||
        ! junkdatagramsenderSipAppendNameAddr(out, out_len, pos, display, uri))
    {
        return false;
    }

    if (tag != NULL && tag[0] != '\0')
    {
        if (! junkdatagramsenderSipAppendStr(out, out_len, pos, ";tag=") ||
            ! junkdatagramsenderSipAppendStr(out, out_len, pos, tag))
        {
            return false;
        }
    }

    return junkdatagramsenderSipAppendCrlf(out, out_len, pos);
}

static bool junkdatagramsenderSipAppendContentLength(uint8_t *out, size_t out_len, size_t *pos, size_t body_len)
{
    return junkdatagramsenderSipAppendStr(out, out_len, pos, "Content-Length: ") &&
           junkdatagramsenderSipAppendSize(out, out_len, pos, body_len) &&
           junkdatagramsenderSipAppendCrlf(out, out_len, pos);
}

static bool junkdatagramsenderSipBuildRequest(uint8_t *out, size_t out_len, size_t *written,
                                              const junkdatagramsender_sip_request_args_t *a)
{
    size_t pos = 0;

    if (out == NULL || written == NULL || a == NULL || a->method == NULL || a->method[0] == '\0' ||
        a->request_uri == NULL || a->request_uri[0] == '\0' || a->via_sent_by == NULL || a->via_sent_by[0] == '\0' ||
        a->via_branch == NULL || a->via_branch[0] == '\0' || a->from_uri == NULL || a->from_uri[0] == '\0' ||
        a->from_tag == NULL || a->from_tag[0] == '\0' || a->to_uri == NULL || a->to_uri[0] == '\0' ||
        a->call_id == NULL || a->call_id[0] == '\0' || (a->body_len > 0 && a->body == NULL))
    {
        return false;
    }

    if (! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->method) ||
        ! junkdatagramsenderSipAppendChar(out, out_len, &pos, ' ') ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->request_uri) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, " SIP/2.0\r\n") ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, "Via: SIP/2.0/") ||
        ! junkdatagramsenderSipAppendStr(
            out, out_len, &pos, (a->via_transport != NULL && a->via_transport[0] != '\0') ? a->via_transport : "UDP") ||
        ! junkdatagramsenderSipAppendChar(out, out_len, &pos, ' ') ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->via_sent_by) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, ";branch=") ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->via_branch) ||
        ! junkdatagramsenderSipAppendCrlf(out, out_len, &pos) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, "Max-Forwards: ") ||
        ! junkdatagramsenderSipAppendUint(out, out_len, &pos, a->max_forwards == 0 ? 70U : a->max_forwards) ||
        ! junkdatagramsenderSipAppendCrlf(out, out_len, &pos) ||
        ! junkdatagramsenderSipAppendFromOrTo(out, out_len, &pos, "From", a->from_display, a->from_uri, a->from_tag) ||
        ! junkdatagramsenderSipAppendFromOrTo(out, out_len, &pos, "To", a->to_display, a->to_uri, a->to_tag) ||
        ! junkdatagramsenderSipAppendHeader(out, out_len, &pos, "Call-ID", a->call_id) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, "CSeq: ") ||
        ! junkdatagramsenderSipAppendUint(out, out_len, &pos, a->cseq) ||
        ! junkdatagramsenderSipAppendChar(out, out_len, &pos, ' ') ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->method) ||
        ! junkdatagramsenderSipAppendCrlf(out, out_len, &pos))
    {
        return false;
    }

    if (a->contact_uri != NULL && a->contact_uri[0] != '\0')
    {
        if (! junkdatagramsenderSipAppendStr(out, out_len, &pos, "Contact: <") ||
            ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->contact_uri) ||
            ! junkdatagramsenderSipAppendStr(out, out_len, &pos, ">\r\n"))
        {
            return false;
        }
    }

    if (! junkdatagramsenderSipAppendHeader(out, out_len, &pos, "User-Agent", a->user_agent) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->extra_headers))
    {
        return false;
    }

    if (a->body_len > 0 &&
        ! junkdatagramsenderSipAppendHeader(
            out, out_len, &pos, "Content-Type", a->content_type != NULL ? a->content_type : "application/sdp"))
    {
        return false;
    }

    if (! junkdatagramsenderSipAppendContentLength(out, out_len, &pos, a->body_len) ||
        ! junkdatagramsenderSipAppendCrlf(out, out_len, &pos) ||
        ! junkdatagramsenderSipAppendBytes(out, out_len, &pos, a->body, a->body_len))
    {
        return false;
    }

    *written = pos;
    return true;
}

static bool junkdatagramsenderSipBuildResponse(uint8_t *out, size_t out_len, size_t *written,
                                               const junkdatagramsender_sip_response_args_t *a)
{
    size_t pos = 0;

    if (out == NULL || written == NULL || a == NULL || a->status_code < 100 || a->status_code > 699 ||
        a->reason_phrase == NULL || a->reason_phrase[0] == '\0' || a->via_value == NULL || a->via_value[0] == '\0' ||
        a->from_value == NULL || a->from_value[0] == '\0' || a->to_value == NULL || a->to_value[0] == '\0' ||
        a->call_id == NULL || a->call_id[0] == '\0' || a->cseq_method == NULL || a->cseq_method[0] == '\0' ||
        (a->body_len > 0 && a->body == NULL))
    {
        return false;
    }

    if (! junkdatagramsenderSipAppendStr(out, out_len, &pos, "SIP/2.0 ") ||
        ! junkdatagramsenderSipAppendUint(out, out_len, &pos, a->status_code) ||
        ! junkdatagramsenderSipAppendChar(out, out_len, &pos, ' ') ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->reason_phrase) ||
        ! junkdatagramsenderSipAppendCrlf(out, out_len, &pos) ||
        ! junkdatagramsenderSipAppendHeader(out, out_len, &pos, "Via", a->via_value) ||
        ! junkdatagramsenderSipAppendHeader(out, out_len, &pos, "From", a->from_value) ||
        ! junkdatagramsenderSipAppendHeader(out, out_len, &pos, "To", a->to_value) ||
        ! junkdatagramsenderSipAppendHeader(out, out_len, &pos, "Call-ID", a->call_id) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, "CSeq: ") ||
        ! junkdatagramsenderSipAppendUint(out, out_len, &pos, a->cseq) ||
        ! junkdatagramsenderSipAppendChar(out, out_len, &pos, ' ') ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->cseq_method) ||
        ! junkdatagramsenderSipAppendCrlf(out, out_len, &pos))
    {
        return false;
    }

    if (a->contact_uri != NULL && a->contact_uri[0] != '\0')
    {
        if (! junkdatagramsenderSipAppendStr(out, out_len, &pos, "Contact: <") ||
            ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->contact_uri) ||
            ! junkdatagramsenderSipAppendStr(out, out_len, &pos, ">\r\n"))
        {
            return false;
        }
    }

    if (! junkdatagramsenderSipAppendHeader(out, out_len, &pos, "Server", a->server) ||
        ! junkdatagramsenderSipAppendStr(out, out_len, &pos, a->extra_headers))
    {
        return false;
    }

    if (a->body_len > 0 &&
        ! junkdatagramsenderSipAppendHeader(
            out, out_len, &pos, "Content-Type", a->content_type != NULL ? a->content_type : "application/sdp"))
    {
        return false;
    }

    if (! junkdatagramsenderSipAppendContentLength(out, out_len, &pos, a->body_len) ||
        ! junkdatagramsenderSipAppendCrlf(out, out_len, &pos) ||
        ! junkdatagramsenderSipAppendBytes(out, out_len, &pos, a->body, a->body_len))
    {
        return false;
    }

    *written = pos;
    return true;
}

static const junkdatagramsender_sip_identity_t *junkdatagramsenderSipRandomIdentity(void)
{
    static const junkdatagramsender_sip_identity_t identities[] = {
        {.user = "alice", .display = "Alice", .domain = "atlanta.voice.lan"},
        {.user = "bob", .display = "Bob", .domain = "biloxi.voice.lan"},
        {.user = "carol", .display = "Carol", .domain = "branch.voice.lan"},
        {.user = "1001", .display = "Desk Phone", .domain = "pbx.office.lan"},
        {.user = "2002", .display = "Conference Room", .domain = "voice.office.lan"},
        {.user = "service", .display = "Service", .domain = "sip.office.lan"},
    };

    return &identities[fastRand32() % (sizeof(identities) / sizeof(identities[0]))];
}

static const char *junkdatagramsenderSipRandomUserAgent(void)
{
    static const char *agents[] = {
        "SIP-UA/1.0",
        "Linphone/5.2.0",
        "MicroSIP/3.21.3",
        "Asterisk PBX 20.5.0",
        "FreeSWITCH-mod_sofia/1.10.10",
    };

    return agents[fastRand32() % (sizeof(agents) / sizeof(agents[0]))];
}

static const char *junkdatagramsenderSipRandomServer(void)
{
    static const char *servers[] = {
        "Asterisk PBX 20.5.0",
        "OpenSIPS (3.4.2)",
        "Kamailio (5.7.4)",
        "FreeSWITCH-mod_sofia/1.10.10",
        "SIP Proxy/2.0",
    };

    return servers[fastRand32() % (sizeof(servers) / sizeof(servers[0]))];
}

static bool junkdatagramsenderSipBuildEndpoint(char *host, size_t host_len, char *sent_by, size_t sent_by_len,
                                               uint16_t port)
{
    uint32_t selector   = fastRand32() % 2U;
    uint32_t last_octet = 10U + (fastRand32() % 200U);

    if (selector == 0)
    {
        if (! stringFormatFits(stringNPrintf(host, host_len, "192.0.2.%u", (unsigned int) last_octet),
                                              host_len))
        {
            return false;
        }
    }
    else if (selector == 1)
    {
        if (! stringFormatFits(stringNPrintf(host, host_len, "198.51.100.%u", (unsigned int) last_octet),
                                              host_len))
        {
            return false;
        }
    }
    return stringFormatFits(stringNPrintf(sent_by, sent_by_len, "%s:%u", host, (unsigned int) port),
                                           sent_by_len);
}

static bool junkdatagramsenderSipBuildSdp(char *body, size_t body_len, const char *user, const char *host)
{
    uint32_t session_id = fastRand32();
    uint16_t media_port = (uint16_t) (10000U + (fastRand32() % 40000U));

    return stringFormatFits(stringNPrintf(body,
                                                         body_len,
                                                         "v=0\r\n"
                                                         "o=%s %u %u IN IP4 %s\r\n"
                                                         "s=-\r\n"
                                                         "c=IN IP4 %s\r\n"
                                                         "t=0 0\r\n"
                                                         "m=audio %u RTP/AVP 0 8 96\r\n"
                                                         "a=rtpmap:0 PCMU/8000\r\n"
                                                         "a=rtpmap:8 PCMA/8000\r\n"
                                                         "a=rtpmap:96 opus/48000/2\r\n"
                                                         "a=sendrecv\r\n",
                                                         user,
                                                         (unsigned int) session_id,
                                                         (unsigned int) session_id,
                                                         host,
                                                         host,
                                                         (unsigned int) media_port),
                                           body_len);
}

static bool junkdatagramsenderSipFormatCommonFields(const junkdatagramsender_sip_identity_t *from,
                                                    const junkdatagramsender_sip_identity_t *to, char *from_uri,
                                                    size_t from_uri_len, char *to_uri, size_t to_uri_len,
                                                    char *request_uri, size_t request_uri_len, char *contact_uri,
                                                    size_t contact_uri_len, char *host, size_t host_len, char *sent_by,
                                                    size_t sent_by_len, char *branch, size_t branch_len, char *from_tag,
                                                    size_t from_tag_len, char *to_tag, size_t to_tag_len, char *call_id,
                                                    size_t call_id_len)
{
    uint16_t port = 5060U;

    if (! junkdatagramsenderSipBuildEndpoint(host, host_len, sent_by, sent_by_len, port))
    {
        return false;
    }

    return stringFormatFits(stringNPrintf(from_uri, from_uri_len, "sip:%s@%s", from->user, from->domain),
                                           from_uri_len) &&
           stringFormatFits(stringNPrintf(to_uri, to_uri_len, "sip:%s@%s", to->user, to->domain),
                                           to_uri_len) &&
           stringFormatFits(
               stringNPrintf(request_uri, request_uri_len, "sip:%s@%s", to->user, to->domain), request_uri_len) &&
           stringFormatFits(
               stringNPrintf(contact_uri, contact_uri_len, "sip:%s@%s:%u", from->user, host, (unsigned int) port),
               contact_uri_len) &&
           stringFormatFits(
               stringNPrintf(
                   branch, branch_len, "z9hG4bK%08x%08x", (unsigned int) fastRand32(), (unsigned int) fastRand32()),
               branch_len) &&
           stringFormatFits(stringNPrintf(from_tag, from_tag_len, "%08x", (unsigned int) fastRand32()),
                                           from_tag_len) &&
           stringFormatFits(stringNPrintf(to_tag, to_tag_len, "%08x", (unsigned int) fastRand32()),
                                           to_tag_len) &&
           stringFormatFits(
               stringNPrintf(
                   call_id, call_id_len, "%08x%08x@%s", (unsigned int) fastRand32(), (unsigned int) fastRand32(), host),
               call_id_len);
}

static bool junkdatagramsenderSipBuildHeaderValue(char *out, size_t out_len, const char *display, const char *uri,
                                                  const char *tag)
{
    if (tag != NULL && tag[0] != '\0')
    {
        return stringFormatFits(stringNPrintf(out, out_len, "\"%s\" <%s>;tag=%s", display, uri, tag),
                                               out_len);
    }

    return stringFormatFits(stringNPrintf(out, out_len, "\"%s\" <%s>", display, uri), out_len);
}

static bool junkdatagramsenderSipGenerateRequest(sbuf_t *buf, uint32_t write_limit)
{
    const junkdatagramsender_sip_identity_t *from = junkdatagramsenderSipRandomIdentity();
    const junkdatagramsender_sip_identity_t *to   = junkdatagramsenderSipRandomIdentity();
    char                                     host[48];
    char                                     sent_by[64];
    char                                     branch[40];
    char                                     from_tag[24];
    char                                     to_tag[24];
    char                                     call_id[96];
    char                                     from_uri[96];
    char                                     to_uri[96];
    char                                     request_uri[96];
    char                                     contact_uri[112];
    char                                     registrar_uri[96];
    char                                     expires_header[32];
    char                                     sdp_body[512];
    const char                              *method        = "OPTIONS";
    const char                              *to_display    = to->display;
    const char                              *content_type  = NULL;
    const uint8_t                           *body          = NULL;
    size_t                                   body_len      = 0;
    const char                              *extra_headers = "Accept: application/sdp\r\n"
                                                             "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, MESSAGE\r\n";
    size_t                                   written       = 0;

    if (from == to)
    {
        to = junkdatagramsenderSipRandomIdentity();
    }

    if (! junkdatagramsenderSipFormatCommonFields(from,
                                                  to,
                                                  from_uri,
                                                  sizeof(from_uri),
                                                  to_uri,
                                                  sizeof(to_uri),
                                                  request_uri,
                                                  sizeof(request_uri),
                                                  contact_uri,
                                                  sizeof(contact_uri),
                                                  host,
                                                  sizeof(host),
                                                  sent_by,
                                                  sizeof(sent_by),
                                                  branch,
                                                  sizeof(branch),
                                                  from_tag,
                                                  sizeof(from_tag),
                                                  to_tag,
                                                  sizeof(to_tag),
                                                  call_id,
                                                  sizeof(call_id)))
    {
        return false;
    }

    switch (fastRand32() % 5U)
    {
    case 0:
        method = "OPTIONS";
        break;
    case 1:
        method = "REGISTER";
        if (! stringFormatFits(
                stringNPrintf(registrar_uri, sizeof(registrar_uri), "sip:%s", from->domain), sizeof(registrar_uri)) ||
            ! stringFormatFits(stringNPrintf(expires_header,
                                                            sizeof(expires_header),
                                                            "Expires: %u\r\n",
                                                            (unsigned int) ((fastRand32() % 8U) == 0 ? 0U : 3600U)),
                                              sizeof(expires_header)))
        {
            return false;
        }
        memoryCopy(request_uri, registrar_uri, stringLength(registrar_uri) + 1U);
        memoryCopy(to_uri, from_uri, stringLength(from_uri) + 1U);
        to_display    = from->display;
        extra_headers = expires_header;
        break;
    case 2:
        method = "INVITE";
        if (! junkdatagramsenderSipBuildSdp(sdp_body, sizeof(sdp_body), from->user, host))
        {
            return false;
        }
        content_type  = "application/sdp";
        body          = (const uint8_t *) sdp_body;
        body_len      = stringLength(sdp_body);
        extra_headers = "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY\r\n"
                        "Supported: replaces, timer\r\n";
        break;
    case 3:
        method        = "BYE";
        extra_headers = "Reason: SIP;cause=200;text=\"Normal call clearing\"\r\n";
        break;
    default:
        method        = "MESSAGE";
        content_type  = "text/plain";
        body          = (const uint8_t *) "status=ok\r\n";
        body_len      = stringLength((const char *) body);
        extra_headers = "Accept: text/plain\r\n";
        break;
    }

    junkdatagramsender_sip_request_args_t request = {
        .method        = method,
        .request_uri   = request_uri,
        .via_transport = "UDP",
        .via_sent_by   = sent_by,
        .via_branch    = branch,
        .max_forwards  = 70U,
        .from_display  = from->display,
        .from_uri      = from_uri,
        .from_tag      = from_tag,
        .to_display    = to_display,
        .to_uri        = to_uri,
        .to_tag        = NULL,
        .call_id       = call_id,
        .cseq          = 1U + (fastRand32() % 9000U),
        .contact_uri   = contact_uri,
        .user_agent    = junkdatagramsenderSipRandomUserAgent(),
        .content_type  = content_type,
        .body          = body,
        .body_len      = body_len,
        .extra_headers = extra_headers,
    };

    if (! junkdatagramsenderSipBuildRequest(sbufGetMutablePtr(buf), write_limit, &written, &request))
    {
        return false;
    }

    sbufSetLength(buf, (uint32_t) written);
    return true;
}

static bool junkdatagramsenderSipGenerateResponse(sbuf_t *buf, uint32_t write_limit)
{
    const junkdatagramsender_sip_identity_t *from = junkdatagramsenderSipRandomIdentity();
    const junkdatagramsender_sip_identity_t *to   = junkdatagramsenderSipRandomIdentity();
    char                                     host[48];
    char                                     sent_by[64];
    char                                     branch[40];
    char                                     from_tag[24];
    char                                     to_tag[24];
    char                                     call_id[96];
    char                                     from_uri[96];
    char                                     to_uri[96];
    char                                     request_uri[96];
    char                                     contact_uri[112];
    char                                     via_value[128];
    char                                     from_value[144];
    char                                     to_value[144];
    char                                     sdp_body[512];
    const char                              *method       = "INVITE";
    const char                              *reason       = "OK";
    unsigned int                             status       = 200U;
    const char                              *content_type = NULL;
    const uint8_t                           *body         = NULL;
    size_t                                   body_len     = 0;
    size_t                                   written      = 0;

    if (from == to)
    {
        to = junkdatagramsenderSipRandomIdentity();
    }

    if (! junkdatagramsenderSipFormatCommonFields(from,
                                                  to,
                                                  from_uri,
                                                  sizeof(from_uri),
                                                  to_uri,
                                                  sizeof(to_uri),
                                                  request_uri,
                                                  sizeof(request_uri),
                                                  contact_uri,
                                                  sizeof(contact_uri),
                                                  host,
                                                  sizeof(host),
                                                  sent_by,
                                                  sizeof(sent_by),
                                                  branch,
                                                  sizeof(branch),
                                                  from_tag,
                                                  sizeof(from_tag),
                                                  to_tag,
                                                  sizeof(to_tag),
                                                  call_id,
                                                  sizeof(call_id)))
    {
        return false;
    }

    switch (fastRand32() % 6U)
    {
    case 0:
        status = 100U;
        reason = "Trying";
        method = "INVITE";
        break;
    case 1:
        status = 180U;
        reason = "Ringing";
        method = "INVITE";
        break;
    case 2:
        status = 200U;
        reason = "OK";
        method = "INVITE";
        if (! junkdatagramsenderSipBuildSdp(sdp_body, sizeof(sdp_body), to->user, host))
        {
            return false;
        }
        content_type = "application/sdp";
        body         = (const uint8_t *) sdp_body;
        body_len     = stringLength(sdp_body);
        break;
    case 3:
        status = 200U;
        reason = "OK";
        method = "REGISTER";
        break;
    case 4:
        status = 404U;
        reason = "Not Found";
        method = "OPTIONS";
        break;
    default:
        status = 486U;
        reason = "Busy Here";
        method = "INVITE";
        break;
    }

    if (! stringFormatFits(
            stringNPrintf(via_value, sizeof(via_value), "SIP/2.0/UDP %s;branch=%s", sent_by, branch),
            sizeof(via_value)) ||
        ! junkdatagramsenderSipBuildHeaderValue(from_value, sizeof(from_value), from->display, from_uri, from_tag) ||
        ! junkdatagramsenderSipBuildHeaderValue(to_value, sizeof(to_value), to->display, to_uri, to_tag))
    {
        return false;
    }

    junkdatagramsender_sip_response_args_t response = {
        .status_code   = status,
        .reason_phrase = reason,
        .via_value     = via_value,
        .from_value    = from_value,
        .to_value      = to_value,
        .call_id       = call_id,
        .cseq          = 1U + (fastRand32() % 9000U),
        .cseq_method   = method,
        .contact_uri   = (status >= 180U && status < 300U) ? contact_uri : NULL,
        .server        = junkdatagramsenderSipRandomServer(),
        .content_type  = content_type,
        .body          = body,
        .body_len      = body_len,
        .extra_headers = (status == 180U) ? "Allow-Events: presence, dialog\r\n" : NULL,
    };

    if (! junkdatagramsenderSipBuildResponse(sbufGetMutablePtr(buf), write_limit, &written, &response))
    {
        return false;
    }

    sbufSetLength(buf, (uint32_t) written);
    return true;
}

bool junkdatagramsenderSipGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t write_limit = junkdatagramsenderSipWriteLimit(buf, args);
    if (write_limit < 180U)
    {
        return false;
    }

    sbufSetLength(buf, 0);
    if ((fastRand32() % 100U) < 65U)
    {
        return junkdatagramsenderSipGenerateRequest(buf, write_limit);
    }
    return junkdatagramsenderSipGenerateResponse(buf, write_limit);
}
