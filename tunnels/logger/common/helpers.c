#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kLoggerTunnelPerPayloadPathMax = 1024
};

char *loggertunnelBuildStaticPath(const char *prefix, const char *suffix)
{
    const size_t prefix_len = stringLength(prefix);
    const size_t suffix_len = stringLength(suffix);
    const size_t total_len  = prefix_len + 1U + suffix_len + 1U;

    char *path = memoryAllocate(total_len);
    if (path == NULL)
    {
        return NULL;
    }

    snprintf(path, total_len, "%s-%s", prefix, suffix);
    return path;
}

static void loggertunnelWriteLogMessage(loggertunnel_tstate_t *state, const uint8_t *data, uint32_t len, bool is_upstream)
{
    const log_level_e level = (log_level_e) state->log_level;

    if (! loggerCheckWriteLevel(getNetworkLogger(), level))
    {
        return;
    }

    const size_t hex_len = ((size_t) len * 2U) + 1U;
    if (hex_len == 0U || (len > 0U && hex_len <= (size_t) len))
    {
        loggerPrint(getNetworkLogger(), level, "LoggerTunnel[%s]: %s payload len=%u", state->file_prefix,
                    is_upstream ? "upstream" : "downstream", len);
        return;
    }

    char *hex = memoryAllocate(hex_len);
    if (hex == NULL)
    {
        loggerPrint(getNetworkLogger(), level, "LoggerTunnel[%s]: %s payload len=%u", state->file_prefix,
                    is_upstream ? "upstream" : "downstream", len);
        return;
    }

    static const char digits[] = "0123456789abcdef";

    for (uint32_t i = 0; i < len; ++i)
    {
        hex[(size_t) i * 2U]       = digits[(data[i] >> 4U) & 0x0FU];
        hex[((size_t) i * 2U) + 1] = digits[data[i] & 0x0FU];
    }
    hex[hex_len - 1U] = '\0';

    loggerPrint(getNetworkLogger(), level, "LoggerTunnel[%s]: %s payload len=%u hex=%s", state->file_prefix,
                is_upstream ? "upstream" : "downstream", len, hex);

    memoryFree(hex);
}

static bool loggertunnelExtractIpv4TcpPayload(const sbuf_t *buf, const uint8_t **payload_ptr, uint32_t *payload_len)
{
    const uint8_t *packet = sbufGetRawPtr(buf);
    const uint32_t len    = sbufGetLength(buf);

    *payload_ptr = NULL;
    *payload_len = 0;

    if (len < sizeof(ip4_hdr_t))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) packet;
    if (IPH_V(ipheader) != 4 || IPH_PROTO(ipheader) != IP_PROTO_TCP)
    {
        return false;
    }

    const uint16_t ip_header_len = (uint16_t) IPH_HL_BYTES(ipheader);
    const uint16_t ip_total_len  = PP_NTOHS(IPH_LEN(ipheader));

    if (ip_header_len < sizeof(ip4_hdr_t) || ip_total_len < ip_header_len || ip_total_len > len)
    {
        return false;
    }

    if ((lwip_ntohs(IPH_OFFSET(ipheader)) & (IP_MF | IP_OFFMASK)) != 0)
    {
        return false;
    }

    if (ip_total_len < (uint16_t) (ip_header_len + sizeof(struct tcp_hdr)))
    {
        return false;
    }

    const struct tcp_hdr *tcp_header = (const struct tcp_hdr *) (packet + ip_header_len);
    const uint16_t        tcp_header_len = (uint16_t) TCPH_HDRLEN_BYTES(tcp_header);
    const uint16_t        headers_len    = (uint16_t) (ip_header_len + tcp_header_len);

    if (tcp_header_len < sizeof(struct tcp_hdr) || headers_len < ip_header_len || ip_total_len < headers_len)
    {
        return false;
    }

    const uint16_t tcp_payload_len = (uint16_t) (ip_total_len - headers_len);
    if (tcp_payload_len == 0)
    {
        return false;
    }

    *payload_ptr = packet + headers_len;
    *payload_len = tcp_payload_len;
    return true;
}

static bool loggertunnelWriteBytesToPath(const char *path, const uint8_t *data, uint32_t len, bool append)
{
    FILE *file = fopen(path, append ? "ab" : "wb");
    if (file == NULL)
    {
        LOGE("LoggerTunnel: failed to open output file %s: %s", path, strerror(errno));
        return false;
    }

    if (len > 0U && fwrite(data, 1, len, file) != len)
    {
        LOGE("LoggerTunnel: failed to write output file %s", path);
        fclose(file);
        return false;
    }

    if (fclose(file) != 0)
    {
        LOGE("LoggerTunnel: failed to close output file %s", path);
        return false;
    }

    return true;
}

static void loggertunnelWriteFilePayload(loggertunnel_tstate_t *state, const uint8_t *data, uint32_t len, bool is_upstream)
{
    mutexLock(&state->file_mutex);

    if (state->output_mode == kLoggerTunnelOutputModePerPayload)
    {
        const uint64_t seq = is_upstream ? ++state->up_counter : ++state->down_counter;
        char           path[kLoggerTunnelPerPayloadPathMax];

        const int written = snprintf(path, sizeof(path), "%s-%s-%llu.txt", state->file_prefix,
                                     is_upstream ? "up" : "down", (unsigned long long) seq);

        if (written <= 0 || (size_t) written >= sizeof(path))
        {
            LOGE("LoggerTunnel: generated file path was too long");
            mutexUnlock(&state->file_mutex);
            return;
        }

        (void) loggertunnelWriteBytesToPath(path, data, len, false);
        mutexUnlock(&state->file_mutex);
        return;
    }

    if (state->output_mode == kLoggerTunnelOutputModeSingleFile)
    {
        (void) loggertunnelWriteBytesToPath(state->all_path, data, len, true);
        mutexUnlock(&state->file_mutex);
        return;
    }

    (void) loggertunnelWriteBytesToPath(is_upstream ? state->up_path : state->down_path, data, len, true);
    mutexUnlock(&state->file_mutex);
}

void loggertunnelHandlePayload(tunnel_t *t, sbuf_t *buf, bool is_upstream)
{
    loggertunnel_tstate_t *state = tunnelGetState(t);
    const uint8_t         *data  = sbufGetRawPtr(buf);
    uint32_t               len   = sbufGetLength(buf);

    if (state->mode == kLoggerTunnelModeLog)
    {
        loggertunnelWriteLogMessage(state, data, len, is_upstream);
        return;
    }

    if (state->mode == kLoggerTunnelModeFile)
    {
        loggertunnelWriteFilePayload(state, data, len, is_upstream);
        return;
    }

    if (loggertunnelExtractIpv4TcpPayload(buf, &data, &len))
    {
        loggertunnelWriteFilePayload(state, data, len, is_upstream);
    }
}
