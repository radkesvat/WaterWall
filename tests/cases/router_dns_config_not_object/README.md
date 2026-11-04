# Router dns config not object

A `dns` value that is not an object must stop startup.

Topology: `listener`: TcpListener → `router`; `router`: Router → `direct-connector` (default), rule `protocol: "dns"` → `dns-connector`; `dns-connector`: UdpConnector; `direct-connector`: TcpConnector. Startup is expected to fail, so nothing listens.

Expected log text: `Router->settings->dns (object field) : expected an object`.

CTest: `waterwall.router_dns_config_not_object`.
