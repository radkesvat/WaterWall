#pragma once

#include "wwapi.h"

typedef enum junkdatagramsender_protocol_e
{
    kJunkDatagramSenderProtocolDns = 0,
    kJunkDatagramSenderProtocolDhcp,
    kJunkDatagramSenderProtocolNtp,
    kJunkDatagramSenderProtocolQuicHttp3,
    kJunkDatagramSenderProtocolRtpRtcpSrtp,
    kJunkDatagramSenderProtocolStunTurnIce,
    kJunkDatagramSenderProtocolMdns,
    kJunkDatagramSenderProtocolSnmp,
    kJunkDatagramSenderProtocolSyslog,
    kJunkDatagramSenderProtocolIpsecNatt,
    kJunkDatagramSenderProtocolSip,
    kJunkDatagramSenderProtocolTftp,
    kJunkDatagramSenderProtocolSsdp,
    kJunkDatagramSenderProtocolRadius,
    kJunkDatagramSenderProtocolGtpu,
    kJunkDatagramSenderProtocolGameUdpProtocols,
    kJunkDatagramSenderProtocolCoap,
    kJunkDatagramSenderProtocolCount
} junkdatagramsender_protocol_t;

typedef struct junkdatagramsender_module_args_s
{
    junkdatagramsender_protocol_t protocol;
    const char                   *protocol_name;
    uint16_t                      min_packet_size;
    uint16_t                      max_packet_size;
} junkdatagramsender_module_args_t;

typedef bool (*junkdatagramsender_generate_fn)(sbuf_t *buf, const junkdatagramsender_module_args_t *args);

typedef struct junkdatagramsender_module_descriptor_s
{
    junkdatagramsender_protocol_t  protocol;
    const char                    *canonical_name;
    junkdatagramsender_generate_fn generate;
} junkdatagramsender_module_descriptor_t;

const junkdatagramsender_module_descriptor_t *junkdatagramsenderGetModuleDescriptors(size_t *count);
const junkdatagramsender_module_descriptor_t *junkdatagramsenderFindProtocolDescriptor(
    junkdatagramsender_protocol_t protocol);

bool junkdatagramsenderGeneratePlaceholderPacket(sbuf_t *buf, const junkdatagramsender_module_args_t *args,
                                                 uint16_t fallback_min_size, uint16_t fallback_max_size);
