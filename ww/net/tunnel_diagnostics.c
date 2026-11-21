#include "tunnel.h"

#include "loggers/network_logger.h"
#include "node_builder/config_policy.h"
#include "objects/node.h"

static const char *lineTransportName(const address_context_t *destination, char *mixed, size_t capacity)
{
    if (destination->proto_icmp || destination->proto_packet)
    {
        snprintf(mixed,
                 capacity,
                 "%s%s%s%s%s",
                 destination->proto_tcp ? "TCP+" : "",
                 destination->proto_udp ? "UDP+" : "",
                 destination->proto_icmp ? "ICMP" : "",
                 destination->proto_icmp && destination->proto_packet ? "+" : "",
                 destination->proto_packet ? "packet" : "");
        return mixed;
    }
    if (destination->proto_tcp && destination->proto_udp)
        return addresscontextDestinationIsPinned(destination)
                   ? "both TCP and UDP (pinned destination requires exactly one)"
                   : "both TCP and UDP";
    if (destination->proto_tcp)
        return "TCP";
    if (destination->proto_udp)
        return "UDP";
    return "no transport";
}

void tunnelLogTransportRequirement(tunnel_t *t, const address_context_t *destination, const char *requirement)
{
    if (! atomicLogRateLimiterShouldLog(&t->transport_refusal_log, 1000))
        return;
    const node_t *node = t->node;
    const char   *type = node != NULL && node->type != NULL ? node->type : "Tunnel";
    const char   *name = node != NULL && node->name != NULL ? node->name : "<internal>";
    char          mixed[32];
    LOGW("%s '%s' refused line: requires %s, line specifies %s",
         configPolicyDiagnostic(type),
         configPolicyDiagnostic(name),
         requirement,
         lineTransportName(destination, mixed, sizeof(mixed)));
}

void tunnelLogTransportRefusal(tunnel_t *t, const address_context_t *destination, uint8_t allowed)
{
    assert(allowed != 0 && (allowed & ~kAddressContextTransportBoth) == 0);
    const char *requirement = allowed == kAddressContextTransportTcp   ? "TCP"
                              : allowed == kAddressContextTransportUdp ? "UDP"
                                                                       : "TCP or UDP";
    tunnelLogTransportRequirement(t, destination, requirement);
}
