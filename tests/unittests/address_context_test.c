#include "address_context.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireDomainEquals(const address_context_t *ctx, const char *expected)
{
    require(ctx->domain != NULL, "copied domain is NULL");
    require(ctx->domain_len == stringLength(expected), "copied domain length changed");
    require(memoryEqual(ctx->domain, expected, stringLength(expected)), "copied domain bytes changed");
}

static void requireTcpPort(const address_context_t *ctx, uint16_t port)
{
    require(ctx->port == port, "copied port changed");
    require(ctx->proto_tcp, "copied TCP protocol flag is missing");
    require(! ctx->proto_udp, "copied UDP protocol flag was unexpectedly set");
    require(! ctx->proto_icmp, "copied ICMP protocol flag was unexpectedly set");
    require(! ctx->proto_packet, "copied packet protocol flag was unexpectedly set");
}

static void requireOptionalProtocols(const address_context_t *ctx, uint32_t expected, const char *message)
{
    require(ctx->optional_flags.detected_protocols == expected, message);
}

static ip_addr_t testIpv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    ip_addr_t ip       = {0};
    ip.type            = IPADDR_TYPE_V4;
    ip.u_addr.ip4.addr = PP_HTONL(LWIP_MAKEU32(a, b, c, d));
    return ip;
}

static void testDynamicDomainCopyKeepsMetadata(void)
{
    address_context_t source = {0};
    address_context_t copy   = {0};

    addresscontextDomainSet(&source, "example.com", (uint8_t) stringLength("example.com"));
    addresscontextSetPort(&source, 443);
    addresscontextSetOnlyProtocol(&source, IP_PROTO_TCP);
    addresscontextSetDomainStrategy(&source, kDsPreferIpV6);
    source.optional_flags.detected_protocols = kAddressContextProtocolBittorrent;

    addresscontextAddrCopy(&copy, &source);

    require(! copy.type_ip, "copied domain context became IP");
    require(! copy.domain_constant, "dynamic domain copy became constant");
    require(copy.domain_strategy == kDsPreferIpV6, "copied domain strategy changed");
    requireDomainEquals(&copy, "example.com");
    requireTcpPort(&copy, 443);
    requireOptionalProtocols(&copy, kAddressContextProtocolBittorrent, "dynamic domain copy lost optional protocols");
    require(copy.domain != source.domain, "dynamic domain copy reused source storage");

    addresscontextReset(&copy);
    addresscontextReset(&source);
}

static void testConstantDomainCopyKeepsMetadata(void)
{
    static const char domain[] = "constant.example";
    address_context_t source   = {0};
    address_context_t copy     = {0};

    addresscontextDomainSetConstMem(&source, domain, (uint8_t) stringLength(domain));
    addresscontextSetPort(&source, 8443);
    addresscontextSetOnlyProtocol(&source, IP_PROTO_TCP);
    source.optional_flags.detected_protocols = kAddressContextProtocolTls;

    addresscontextAddrCopy(&copy, &source);

    require(! copy.type_ip, "copied constant domain context became IP");
    require(copy.domain_constant, "constant domain copy became dynamic");
    require(copy.domain == domain, "constant domain copy did not preserve constant storage");
    requireDomainEquals(&copy, domain);
    requireTcpPort(&copy, 8443);
    requireOptionalProtocols(&copy, kAddressContextProtocolTls, "constant domain copy lost optional protocols");

    addresscontextReset(&copy);
    addresscontextReset(&source);
}

static void testIpCopyKeepsMetadata(void)
{
    ip_addr_t         ip     = {0};
    address_context_t source = {0};
    address_context_t copy   = {0};

    ip.type            = IPADDR_TYPE_V4;
    ip.u_addr.ip4.addr = PP_HTONL(LWIP_MAKEU32(127, 0, 0, 1));
    addresscontextSetIpPort(&source, &ip, 8080);
    addresscontextSetOnlyProtocol(&source, IP_PROTO_TCP);
    source.optional_flags.detected_protocols = kAddressContextProtocolHttp1;

    addresscontextAddrCopy(&copy, &source);

    require(copy.type_ip, "copied IP context became domain");
    require(addresscontextIsIpv4(&copy), "copied IP context is not IPv4");
    require(ip_addr_cmp(&copy.ip_address, &source.ip_address), "copied IP changed");
    requireTcpPort(&copy, 8080);
    requireOptionalProtocols(&copy, kAddressContextProtocolHttp1, "IP copy lost optional protocols");

    addresscontextReset(&copy);
    addresscontextReset(&source);
}

static void testResetClearsOptionalFlags(void)
{
    address_context_t ctx = {0};

    ctx.optional_flags.detected_protocols = kAddressContextProtocolHttp1 | kAddressContextProtocolTls;
    addresscontextReset(&ctx);

    requireOptionalProtocols(&ctx, 0, "reset did not clear optional protocols");
}

static void testEndpointSettersClearOptionalFlags(void)
{
    address_context_t ctx = {0};
    ip_addr_t         ip  = testIpv4Address(192, 0, 2, 1);

    ctx.optional_flags.detected_protocols = kAddressContextProtocolTls;
    addresscontextDomainSetByString(&ctx, "example.org");
    requireOptionalProtocols(&ctx, 0, "domain setter did not clear optional protocols");

    ctx.optional_flags.detected_protocols = kAddressContextProtocolBittorrent;
    addresscontextSetIpPortProtocol(&ctx, &ip, 443, IP_PROTO_TCP);
    requireOptionalProtocols(&ctx, 0, "IP setter did not clear optional protocols");

    addresscontextReset(&ctx);
}

static void testObservedDomainPreservesOptionalFlags(void)
{
    address_context_t ctx = {0};
    ip_addr_t         ip  = testIpv4Address(192, 0, 2, 2);

    addresscontextSetIpPortProtocol(&ctx, &ip, 443, IP_PROTO_TCP);
    ctx.optional_flags.detected_protocols = kAddressContextProtocolHttp1;

    const uint8_t observed[] = "observed.example";
    require(addresscontextSetObservedDomain(&ctx, observed, (uint32_t) sizeof(observed) - 1U),
            "failed to set observed domain");
    requireOptionalProtocols(&ctx, kAddressContextProtocolHttp1, "observed domain cleared optional protocols");

    addresscontextReset(&ctx);
}

int main(void)
{
    testDynamicDomainCopyKeepsMetadata();
    testConstantDomainCopyKeepsMetadata();
    testIpCopyKeepsMetadata();
    testResetClearsOptionalFlags();
    testEndpointSettersClearOptionalFlags();
    testObservedDomainPreservesOptionalFlags();
    return 0;
}
