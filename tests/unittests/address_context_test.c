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

static void testSockaddrIpv4HashIgnoresUnrelatedBytes(void)
{
    sockaddr_u first;
    sockaddr_u second;

    memorySet(&first, 0xAA, sizeof(first));
    memorySet(&second, 0x55, sizeof(second));

    first.sin.sin_family       = AF_INET;
    second.sin.sin_family      = AF_INET;
    first.sin.sin_port         = htons(5353);
    second.sin.sin_port        = first.sin.sin_port;
    first.sin.sin_addr.s_addr = PP_HTONL(LWIP_MAKEU32(192, 0, 2, 10));
    second.sin.sin_addr        = first.sin.sin_addr;

    require(sockaddrCalcHashWithPort(&first) == sockaddrCalcHashWithPort(&second),
            "IPv4 endpoint hash includes unrelated sockaddr bytes");
}

static void testSockaddrIpv6HashUsesOnlyEndpointFields(void)
{
    struct {
        sockaddr_u addr;
        uint8_t    trailing[sizeof(struct sockaddr_in6)];
    } first, second;

    memorySet(&first, 0xAA, sizeof(first));
    memorySet(&second, 0x55, sizeof(second));

    first.addr.sin6.sin6_family    = AF_INET6;
    second.addr.sin6.sin6_family   = AF_INET6;
    first.addr.sin6.sin6_port      = htons(5353);
    second.addr.sin6.sin6_port     = first.addr.sin6.sin6_port;
    first.addr.sin6.sin6_flowinfo  = htonl(7);
    second.addr.sin6.sin6_flowinfo = first.addr.sin6.sin6_flowinfo;
    first.addr.sin6.sin6_scope_id  = 3;
    second.addr.sin6.sin6_scope_id = first.addr.sin6.sin6_scope_id;

    for (size_t i = 0; i < sizeof(first.addr.sin6.sin6_addr.s6_addr); ++i)
    {
        first.addr.sin6.sin6_addr.s6_addr[i]  = (uint8_t) i;
        second.addr.sin6.sin6_addr.s6_addr[i] = (uint8_t) i;
    }

    require(sockaddrCalcHashWithPort(&first.addr) == sockaddrCalcHashWithPort(&second.addr),
            "IPv6 endpoint hash includes bytes beyond its fields");

    second.addr.sin6.sin6_flowinfo = htonl(8);
    require(sockaddrCalcHashWithPort(&first.addr) != sockaddrCalcHashWithPort(&second.addr),
            "IPv6 endpoint hash ignores flow information");
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

static void testResolvedDomainConvertsToSockAddr(void)
{
    address_context_t ctx = {0};

    addresscontextDomainSetByString(&ctx, "resolved.example");
    ctx.ip_address      = testIpv4Address(203, 0, 113, 10);
    ctx.port            = 5353;
    ctx.domain_resolved = true;

    require(addresscontextCanConvertToSockAddr(&ctx), "resolved domain is not convertible to sockaddr");

    sockaddr_u addr = addresscontextToSockAddr(&ctx);
    require(addr.sa.sa_family == AF_INET, "resolved domain converted to wrong sockaddr family");
    require(ntohs(addr.sin.sin_port) == 5353, "resolved domain converted with wrong port");
    require(addr.sin.sin_addr.s_addr == ctx.ip_address.u_addr.ip4.addr, "resolved domain converted with wrong IPv4");

    addresscontextReset(&ctx);
}

int main(void)
{
    testSockaddrIpv4HashIgnoresUnrelatedBytes();
    testSockaddrIpv6HashUsesOnlyEndpointFields();
    testDynamicDomainCopyKeepsMetadata();
    testConstantDomainCopyKeepsMetadata();
    testIpCopyKeepsMetadata();
    testResetClearsOptionalFlags();
    testEndpointSettersClearOptionalFlags();
    testObservedDomainPreservesOptionalFlags();
    testResolvedDomainConvertsToSockAddr();
    return 0;
}
