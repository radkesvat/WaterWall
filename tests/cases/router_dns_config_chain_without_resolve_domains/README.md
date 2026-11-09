# Router dns config chain without resolve domains

`dns.mode: "chain"` without `resolve-domains: true` must stop startup, because the internal resolver would never run.

Topology: `listener`: TcpListener → `router`; `router`: Router → `direct-connector` (default), rule `protocol: "dns"` → `dns-connector`; `dns-connector`: UdpConnector; `direct-connector`: TcpConnector. Startup is expected to fail, so nothing listens.

Expected log text: `requires Router->settings->resolve-domains to be`.

CTest: `waterwall.router_dns_config_chain_without_resolve_domains`.
