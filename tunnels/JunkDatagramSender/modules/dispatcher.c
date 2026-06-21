#include "module.h"

#include "dhcp.h"
#include "dns.h"
#include "ipsec_natt.h"
#include "mdns.h"
#include "ntp.h"
#include "quic_http3.h"
#include "rtp_rtcp_srtp.h"
#include "sip.h"
#include "snmp.h"
#include "stun_turn_ice.h"
#include "syslog.h"

const junkdatagramsender_module_descriptor_t *junkdatagramsenderGetModuleDescriptors(size_t *count)
{
    static const junkdatagramsender_module_descriptor_t descriptors[] = {
        {.protocol       = kJunkDatagramSenderProtocolDns,
         .canonical_name = "dns",
         .generate       = junkdatagramsenderDnsGenerate},
        {.protocol       = kJunkDatagramSenderProtocolDhcp,
         .canonical_name = "dhcp",
         .generate       = junkdatagramsenderDhcpGenerate},
        {.protocol       = kJunkDatagramSenderProtocolNtp,
         .canonical_name = "ntp",
         .generate       = junkdatagramsenderNtpGenerate},
        {.protocol       = kJunkDatagramSenderProtocolQuicHttp3,
         .canonical_name = "quic-http3",
         .generate       = junkdatagramsenderQuicHttp3Generate},
        {.protocol       = kJunkDatagramSenderProtocolRtpRtcpSrtp,
         .canonical_name = "rtp-rtcp-srtp",
         .generate       = junkdatagramsenderRtpRtcpSrtpGenerate},
        {.protocol       = kJunkDatagramSenderProtocolStunTurnIce,
         .canonical_name = "stun-turn-ice",
         .generate       = junkdatagramsenderStunTurnIceGenerate},
        {.protocol       = kJunkDatagramSenderProtocolMdns,
         .canonical_name = "mdns",
         .generate       = junkdatagramsenderMdnsGenerate},
        {.protocol       = kJunkDatagramSenderProtocolSnmp,
         .canonical_name = "snmp",
         .generate       = junkdatagramsenderSnmpGenerate},
        {.protocol       = kJunkDatagramSenderProtocolSyslog,
         .canonical_name = "syslog",
         .generate       = junkdatagramsenderSyslogGenerate},
        {.protocol       = kJunkDatagramSenderProtocolIpsecNatt,
         .canonical_name = "ipsec-nat-t",
         .generate       = junkdatagramsenderIpsecNattGenerate},
        {.protocol       = kJunkDatagramSenderProtocolSip,
         .canonical_name = "sip",
         .generate       = junkdatagramsenderSipGenerate},
    };

    if (count != NULL)
    {
        *count = sizeof(descriptors) / sizeof(descriptors[0]);
    }
    return descriptors;
}

const junkdatagramsender_module_descriptor_t *junkdatagramsenderFindProtocolDescriptor(
    junkdatagramsender_protocol_t protocol)
{
    size_t                                        count       = 0;
    const junkdatagramsender_module_descriptor_t *descriptors = junkdatagramsenderGetModuleDescriptors(&count);

    for (size_t i = 0; i < count; ++i)
    {
        if (descriptors[i].protocol == protocol)
        {
            return &descriptors[i];
        }
    }

    return NULL;
}
