<!--
Documentation version: 164
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/DomainResolver.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/DomainResolver.mdx, and all files must keep the same documentation version.
-->

# DomainResolver

`DomainResolver` resolves an application's destination hostname before passing the
connection to the next node. Choose `native`, `direct`, or `chain` to control how
that resolver sends DNS queries.

Place it after a node that supplies the destination, such as `Socks5Server`, and
before the node that needs the resolved address:

```text
TcpListener -> Socks5Server -> DomainResolver -> application next
```

For a request to `example.com:443`, the application line waits for DNS, receives
the selected IP address, and continues to `next` on port 443. In `direct` and
`chain` modes, separate DNS lines connect to the configured DNS server. They do
not replace the application's destination or carry its payload.

An IP address or an already-resolved destination continues immediately. The node
preserves application payload bytes and resolves only `dest_ctx`, not `src_ctx`.

## Choose a DNS Mode

| Mode | How DNS is sent | Use it when |
| --- | --- | --- |
| `native` | The existing worker c-ares resolver opens native sockets using core DNS settings. | You want the normal resolver behavior without a DNS branch. |
| `direct` | A private WaterWall TCP/UDP connector sends queries to your explicit DNS servers. | You want DNS to use WaterWall lines without configuring a separate outbound chain. |
| `chain` | Resolver-owned DNS lines enter ordinary `next`, or the optional `dns-next` override. | You want to route DNS through a chosen proxy, VPN transport, or other suitable chain. |

`native` is the default. Neither `native` nor `direct` adds DNS encryption.
`chain` protects DNS when its selected branch provides protection; the mode name
alone does not encrypt traffic.

## Shared Settings

| Field | Default | Meaning |
| --- | --- | --- |
| Node `next` | — | The application continuation; also the default DNS entry in `chain`. |
| `settings.resolve` | `true` | Enable lookup; false passes through without lookup and rejects all other DNS policy fields. |
| `settings.mode` | `native` | One of `native`, `direct`, or `chain`. |
| `settings.strategy` | `core-settings` | How to choose an address from the DNS results. |
| `settings.verbose` | `false` | Log the start of a lookup at the DNS debug level. Resolved-address logs use the normal DNS logger. |
| `settings.servers` | — | Required in `direct` and `chain`; rejected in `native`. |
| `settings.dns-next` | Node `next` in `chain` | Optional nonempty DNS-entry override for `chain`; rejected in the other modes. |

An omitted `settings` object selects native mode and the shared defaults. If
provided, `settings` must be an object.

Use a string for `strategy`:

| Value | Address selection |
| --- | --- |
| `core-settings` | Use `dns.domain-strategy` from `core.json`. |
| `accept-dns-returned-order` | Use the first usable IPv4 or IPv6 result. |
| `prefer-ipv4` | Prefer IPv4 and fall back to IPv6. |
| `prefer-ipv6` | Prefer IPv6 and fall back to IPv4. |
| `only-ipv4` | Accept only IPv4 results. |
| `only-ipv6` | Accept only IPv6 results. |

Existing flat configurations without `resolve` also retain their numeric/case-insensitive legacy strategy parsing. With explicit `resolve`, strategies use the canonical strings above. Address selection is independent of DNS transport.

## Native Mode

Use `native` when the current core DNS configuration already provides the path
you need. Lookups share the existing resolver channel on their owner worker.
c-ares uses native sockets; the query does not enter a DNS branch selected by
this node. Core DNS settings determine servers, lookup sources, retries and cache
behavior. Without an explicit core server list, c-ares uses its normal system
resolver configuration.

Core enables `edns` and `stayopen` by default, keeping idle native DNS sockets
available for later queries. An explicit `dns.flags` value replaces that default
set.

Set `mode` to `native`, or omit it. Configure DNS options in `core.json`, not in
this node's `servers` or `dns-next` fields. Both fields are rejected in native
mode to avoid silently ignoring them.

### Native example

This complete node configuration exposes a local SOCKS5 TCP proxy. The explicit
resolver resolves the requested hostname, then `application-out` connects to its
IP address. Save it as a node configuration and include it from `core.json`.

```json
{
  "name": "dns-native",
  "nodes": [
    {
      "name": "local-in",
      "type": "TcpListener",
      "settings": {
        "address": "127.0.0.1",
        "port": 1080
      },
      "next": "socks"
    },
    {
      "name": "socks",
      "type": "Socks5Server",
      "settings": {
        "no-auth": true,
        "connect": true
      },
      "next": "resolve"
    },
    {
      "name": "resolve",
      "type": "DomainResolver",
      "settings": {
        "mode": "native",
        "strategy": "prefer-ipv4"
      },
      "next": "application-out"
    },
    {
      "name": "application-out",
      "type": "TcpConnector",
      "settings": {
        "address": "dest_context->address",
        "port": "dest_context->port"
      }
    }
  ]
}
```

If you want a specific native DNS server, merge the following `dns` field into
your existing `core.json`. Replace the documentation address with your resolver:

```json
{
  "dns": {
    "servers": ["203.0.113.53:53"]
  }
}
```

Consumers expose the same policy under `settings.dns-behaviour`; the standalone node keeps these DNS fields flat, alongside `verbose`. An explicit DomainResolver remains useful to choose lookup position before routing. Do not nest `dns-behaviour` on DomainResolver.

## Direct Mode

Use `direct` to send DNS through WaterWall's connector machinery while keeping
the configuration small. The resolver creates a private `TcpUdpConnector`
branch for DNS. You supply numeric DNS-server endpoints; you do not add a
DNS connector node or set `dns-next` yourself.

```text
application -> DomainResolver -> application next
                    |
                    +-> private TCP/UDP connector -> DNS server
```

Both UDP queries and TCP fallback use this private branch. The application
continues on its original `next` only after resolution succeeds. Direct mode
uses ordinary DNS transport and does not add a VPN or encryption.

### Direct example

This complete node configuration uses the same local SOCKS5 TCP entry, but DNS
is sent through the resolver's private connector. Replace `203.0.113.53` with a
reachable DNS-server IP, save this node file, and include it from `core.json`.
No separately configured DNS branch is needed.

```json
{
  "name": "dns-direct",
  "nodes": [
    {
      "name": "local-in",
      "type": "TcpListener",
      "settings": {
        "address": "127.0.0.1",
        "port": 1080
      },
      "next": "socks"
    },
    {
      "name": "socks",
      "type": "Socks5Server",
      "settings": {
        "no-auth": true,
        "connect": true
      },
      "next": "resolve"
    },
    {
      "name": "resolve",
      "type": "DomainResolver",
      "settings": {
        "mode": "direct",
        "strategy": "prefer-ipv4",
        "servers": [
          "203.0.113.53:53"
        ]
      },
      "next": "application-out"
    },
    {
      "name": "application-out",
      "type": "TcpConnector",
      "settings": {
        "address": "dest_context->address",
        "port": "dest_context->port"
      }
    }
  ]
}
```

The private connector must be available in the build. If it is unavailable,
direct mode fails construction with a diagnostic; native mode remains usable.
The `servers` grammar and inherited core options are described below.

## Chain Mode

Use `chain` to send DNS through your configured tunnel nodes. Set `mode` to
`chain` and provide numeric DNS-server endpoints in `servers`. By default, the
resolver sends its separate DNS lines into its ordinary `next`, just as it later
sends the resolved application line there. You do not need `dns-next` for this
shared path.

The lines have different destinations and lifetimes even when they traverse the
same nodes. While an application request waits for its address, the resolver
creates a DNS line addressed to a configured DNS server. After the answer arrives,
the application line continues with the selected destination IP and its original
service port. DNS never replaces the application payload.

Both UDP DNS and TCP fallback use the same selected entry. The downstream path
must support both. A Router can distinguish these DNS lines with `resolver-dns`;
a Router is not required when all lines should enter the same proxy path.

### Chain example: shared Router and VLESS over TLS

This complete client configuration accepts SOCKS5 TCP and UDP, sends all
resolver-generated DNS through the VPN, sends application destinations in Iran
directly, and sends other application traffic through the VPN:

```text
TcpUdpListener -> Socks5Server -> DomainResolver -> Router
                                                    |
                      DNS first, then default -------+-> VlessClient -> TlsClient -> TcpConnector
                                                    |
                      application IP in geoip:ir ----+-> TcpUdpConnector
```

```json
{
  "name": "dns-and-application-routing",
  "nodes": [
    {
      "name": "local-in",
      "type": "TcpUdpListener",
      "settings": {
        "address": "127.0.0.1",
        "port": 1080
      },
      "next": "socks"
    },
    {
      "name": "socks",
      "type": "Socks5Server",
      "settings": {
        "no-auth": true,
        "connect": true,
        "udp": true,
        "ipv4": "127.0.0.1"
      },
      "next": "resolve"
    },
    {
      "name": "resolve",
      "type": "DomainResolver",
      "settings": {
        "mode": "chain",
        "servers": [
          "203.0.113.53:53"
        ],
        "strategy": "prefer-ipv4"
      },
      "next": "router"
    },
    {
      "name": "router",
      "type": "Router",
      "settings": {
        "geoip-db-path": "/var/lib/waterwall/GeoLite2-Country.mmdb",
        "rules": [
          {
            "resolver-dns": true,
            "target": "vpn-client"
          },
          {
            "destination-ip": "geoip:ir",
            "target": "direct-out"
          }
        ]
      },
      "next": "vpn-client"
    },
    {
      "name": "direct-out",
      "type": "TcpUdpConnector",
      "settings": {
        "address": "dest_context->address",
        "port": "dest_context->port"
      }
    },
    {
      "name": "vpn-client",
      "type": "VlessClient",
      "settings": {
        "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
        "address": "dest_context->address",
        "port": "dest_context->port",
        "protocol": "dest_context->protocol",
        "domain-strategy": "do-not-resolve-domains"
      },
      "next": "vpn-tls"
    },
    {
      "name": "vpn-tls",
      "type": "TlsClient",
      "settings": {
        "sni": "vpn.example.net",
        "verify": true
      },
      "next": "vpn-out"
    },
    {
      "name": "vpn-out",
      "type": "TcpConnector",
      "settings": {
        "address": "198.51.100.20",
        "port": 443
      }
    }
  ]
}
```

Save this node file and include it from `core.json`. Before running it:

- Replace `203.0.113.53` with the numeric DNS-server address reachable from the
  remote VLESS server. Replace `198.51.100.20`, UUID and SNI with your VPN endpoint
  and credentials. These IP addresses are documentation placeholders.
- Set `geoip-db-path` to a readable MaxMind country database. Router needs this
  file to evaluate `geoip:ir`; an IP absent from the database does not match it
  and uses the default VPN route.
- Provide the remote path `TcpListener -> TlsServer -> VlessServer ->
  TcpUdpConnector`, with the same UUID, a trusted certificate for
  `vpn.example.net`, and both TCP and UDP VLESS commands enabled. The node
  references for VlessServer and TlsServer describe their settings.

The resolver's `next` is `router`, and `dns-next` is omitted. Both types of line
therefore reach the same Router:

1. A DNS line carries `resolver-dns: true`. The first rule sends it through
   `vpn-client`, regardless of the DNS server's country. This includes TCP
   fallback as well as UDP queries.
2. When DNS succeeds, the original application line reaches Router with its
   selected IP. It has no DNS marker. `geoip:ir` sends it to `direct-out` when
   that IP matches Iran; otherwise Router's `next` sends it to `vpn-client`.
3. A SOCKS request that already contains an IP needs no lookup and goes straight
   to the same application routing decision.

Keep the DNS rule first. It must win before the country rule can send a
DNS-server IP directly. This Router uses only metadata and has no root `sniffing`,
so it chooses the route during Init without waiting for payload. That lets a TCP
DNS line establish before c-ares writes its query.

`protocol: "dest_context->protocol"` lets VlessClient carry UDP and TCP DNS as well
as the chosen application flows. The logical destination is the DNS server or
application target; `vpn-out` independently connects to the numeric outer VPN
server. TLS encrypts that outer connection; plain VLESS does not.

### Bootstrap and failures

The outer VPN endpoint must be usable before protected DNS can work. A numeric
`vpn-out.address` avoids needing DNS to establish the DNS path. A hostname for
that endpoint requires an explicit independent bootstrap path; an unavailable
VPN route cannot resolve its own server name through itself.

A rejected route, timeout or failed VPN connection does not make this resolver
retry through native DNS or the Router's direct application branch. It may retry
another explicitly configured DNS server through the same selected chain.

### Optional separate DNS branch

Set `dns-next` only when DNS should start at a different entry from the original
application. This resolver fragment uses a separate `dns-vless` branch while
applications continue to `application-out`:

```json
{
  "name": "resolve",
  "type": "DomainResolver",
  "settings": {
    "mode": "chain",
    "servers": [
      "203.0.113.53:53"
    ],
    "dns-next": "dns-vless"
  },
  "next": "application-out"
}
```

Define `application-out` and an otherwise unbound `dns-vless` branch in the same
configuration. For example, that DNS branch can be
`VlessClient -> TlsClient -> TcpConnector`, with the same numeric bootstrap and
UDP/TCP requirements as above. A Router is optional on either path.

An explicit `dns-next` must be a nonempty node name. Naming the same node as
`next` is also supported and has the same shared-entry behavior as omission.
The override changes only DNS egress; it does not change the application `next`.

A distinct branch must not already belong to another predecessor. Startup
rejects self-targets, structural cycles, conflicting predecessors and non-L4 DNS
entries. Private predecessor helpers are included when resolving the callable
entry. This is not arbitrary many-to-one sharing of an existing VPN chain, and
structural checks cannot detect every runtime bootstrap dependency.

## Embedded policies and disabled resolution

On consuming nodes, the object must contain a boolean `resolve`. For example:

```json
{"dns-behaviour": {"resolve": true, "mode": "native", "strategy": "core-settings"}}
```

Direct and chain use the same `servers` grammar described below. Unknown fields,
empty/null/non-object policies and numeric strategies are rejected. Do not combine
this object with same-scope legacy `domain-strategy` or Router `resolve-domains`.
Omitting it retains each consumer's old settings and defaults. Strategy omission
retains the consumer's address preference; `core-settings` explicitly chooses the
core preference without changing DNS transport.

Use exactly `{"resolve": false}` inside `dns-behaviour` to disable local lookup.
Standalone DomainResolver uses flat `"resolve": false` instead. Both reject
`mode`, `strategy`, `servers` and `dns-next` while disabled. Preparation still
selects destination address, port and protocol; pre-resolved addresses survive.
A supported proxy can forward an unresolved hostname. Socket connectors, CTP
and datagram endpoints reject unresolved targets without OS/native fallback.

| Consumer | Default chain DNS entry |
| --- | --- |
| Standalone DomainResolver | Ordinary configured `next`; explicit same-next is also supported. |
| Router | Its logical inlet, without re-entering its hidden resolver. |
| SOCKS5, Trojan, VLESS and VMess clients | Its logical inlet with owned-DNS preparation; selected framing must carry UDP and TCP. |
| TcpConnector, UdpConnector and HttpProxyClient | Explicit `dns-next` required. HTTP resolution is CONNECT-only. |
| TcpUdpConnector and ConnectionToPackets | Explicit `dns-next` required. CTP remains IPv4-only. |
| UdpStatelessSocket | Explicit `dns-next` required; its ordinary `next` serves its peer/line role. |

For embedded policies, explicitly naming the owner is rejected. Omit the name for
a supported shared entry, or bind a separate, otherwise unowned branch. The
selected path must carry both UDP queries and TCP fallback. A rejected route or
failed lookup never switches to native DNS or an application fallback path.
Direct/chain channels and caches are private to one provider and worker; the
combined connector's children borrow one authoritative provider and branch.

### Router-owned protected DNS

This complete configuration resolves before GeoIP classification using Router's
own entry. Replace the documentation addresses, UUID, SNI and GeoIP database path
and provide the remote TLS/VLESS service as in the preceding chain example.

```json
{
  "name": "router-owned-dns-and-application-routing",
  "nodes": [
    {
      "name": "local-in",
      "type": "TcpUdpListener",
      "settings": {
        "address": "127.0.0.1",
        "port": 1080
      },
      "next": "socks"
    },
    {
      "name": "socks",
      "type": "Socks5Server",
      "settings": {
        "no-auth": true,
        "connect": true,
        "udp": true,
        "ipv4": "127.0.0.1"
      },
      "next": "router"
    },
    {
      "name": "router",
      "type": "Router",
      "settings": {
        "geoip-db-path": "/var/lib/waterwall/GeoLite2-Country.mmdb",
        "rules": [
          {
            "resolver-dns": true,
            "target": "vpn-client"
          },
          {
            "destination-ip": "geoip:ir",
            "target": "direct-out"
          }
        ],
        "dns-behaviour": {
          "resolve": true,
          "mode": "chain",
          "servers": [
            "203.0.113.53:53"
          ],
          "strategy": "prefer-ipv4"
        }
      },
      "next": "vpn-client"
    },
    {
      "name": "direct-out",
      "type": "TcpUdpConnector",
      "settings": {
        "address": "dest_context->address",
        "port": "dest_context->port"
      }
    },
    {
      "name": "vpn-client",
      "type": "VlessClient",
      "settings": {
        "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
        "address": "dest_context->address",
        "port": "dest_context->port",
        "protocol": "dest_context->protocol",
        "domain-strategy": "do-not-resolve-domains"
      },
      "next": "vpn-tls"
    },
    {
      "name": "vpn-tls",
      "type": "TlsClient",
      "settings": {
        "sni": "vpn.example.net",
        "verify": true
      },
      "next": "vpn-out"
    },
    {
      "name": "vpn-out",
      "type": "TcpConnector",
      "settings": {
        "address": "198.51.100.20",
        "port": 443
      }
    }
  ]
}
```

The leading `resolver-dns` rule sends UDP and TCP DNS through TLS/VLESS. The
unmarked application later matches `geoip:ir` for direct egress, or the default
VPN route. Root sniffing is unnecessary. Resolving only in the later VlessClient
would be too late for this Router's IP decision.

### Proxy-owned shared entry

This VLESS fragment resolves its logical target through its own proxy entry.
Define `vpn-tls -> TcpConnector` with a numeric outer VPN endpoint, as above.
Do not set `dns-next` to the embedding client name.

```json
{
  "name": "vpn-client",
  "type": "VlessClient",
  "next": "vpn-tls",
  "settings": {
    "uuid": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "dest_context->protocol",
    "dns-behaviour": {"resolve": true, "mode": "chain", "servers": ["203.0.113.53:53"]}
  }
}
```

The generated line keeps its numeric DNS target and exact UDP/TCP protocol. The
logical client consumes the destination pin; its outer connector independently
selects the VPN endpoint. The original application has no DNS-origin marker.

### Connector with a separate branch

This complete local SOCKS configuration gives the connector an explicit DNS
branch. Use a protected proxy branch in place of `dns-out` to protect DNS.

```json
{
  "name": "connector-dns-branch",
  "nodes": [
    {"name": "in", "type": "TcpListener", "next": "socks", "settings": {"address": "127.0.0.1", "port": 1080}},
    {"name": "socks", "type": "Socks5Server", "next": "app-out", "settings": {"no-auth": true, "connect": true}},
    {"name": "app-out", "type": "TcpConnector", "settings": {
      "address": "dest_context->address", "port": "dest_context->port",
      "dns-behaviour": {"resolve": true, "mode": "chain", "servers": ["203.0.113.53:53"], "dns-next": "dns-out"}
    }},
    {"name": "dns-out", "type": "TcpUdpConnector", "settings": {"address": "dest_context->address", "port": "dest_context->port"}}
  ]
}
```

## DNS Servers and Options for Direct and Chain

`servers` must contain 1–32 numeric endpoints. Supported forms are:

| Endpoint | Meaning |
| --- | --- |
| `192.0.2.53` | IPv4 address with the core DNS ports. |
| `192.0.2.53:5353` | IPv4 address using port 5353 for both UDP and TCP. |
| `2001:db8::53` | IPv6 address with the core DNS ports. |
| `[2001:db8::53]:5353` | IPv6 address using port 5353 for both UDP and TCP. |

Without a suffix, `dns.udp-port` and `dns.tcp-port` from core apply; each defaults
to 53. Hostnames, interface scopes, malformed addresses and zero or invalid
ports are rejected.

These modes inherit core c-ares retry, timeout, cache, flags, search-domain,
lookup/hosts-file, EDNS, port, rotation and failover settings. Their explicit
server list replaces core server discovery. Configured core
`socket-send-buffer-size`, `socket-receive-buffer-size`, `sortlist` and
`resolvconf-path` are rejected because this backend does not support those
requirements.

Each direct/chain provider, whether standalone or embedded, keeps a reusable
channel and cache per worker across queries. With the default core flags
`["edns", "stayopen"]`, c-ares also retains idle UDP and TCP DNS connections so
later queries can reuse their DNS lines and transport connections. Errors,
downstream closure, server or connection rotation, and shutdown can still close
those connections; a later query opens another when needed. Setting core
`"dns": {"flags": ["edns"]}` disables idle connection reuse without changing the
provider's channel lifetime.

A failed query may retry another configured server, but never switches to native
DNS or another mode. Closing one application request does not cancel other
requests sharing the channel.

## DNS Destinations and Router Matching

Generated DNS lines carry an authoritative DNS-server destination and exact UDP
or TCP transport. The first logical proxy destination selector or outbound
adapter honors that endpoint even if it has a fixed target configured. It then
consumes the one-shot destination pin, allowing an independent outer connector
to select its VPN server normally. A transport-specific connector rejects a
pinned destination with the wrong transport.

Both UDP and TCP DNS lines automatically carry the `resolver-dns` marker. Router
can match that metadata without inspecting DNS payload. Matching is optional;
chain mode can enter a suitable proxy directly without Router. The marker follows the logical
DNS destination, survives Router's protocol-observation reset, and is absent
from the original application and an independently created outer VPN carrier.
It does not identify arbitrary application DNS, TUN packets, or traffic merely
because it uses port 53.

## Scope of the Selected Mode

Each policy controls lookups owned by its consumer. TcpConnector, UdpConnector,
TcpUdpConnector, Router, SOCKS5/Trojan/VLESS/VMess clients, HttpProxyClient,
ConnectionToPackets and UdpStatelessSocket share this parser and backend.
UdpConnector's packet-balanced destinations and UdpStatelessSocket's asynchronous
outbound datagrams use their selected provider too. Omitted policies preserve
existing defaults; proxy-local resolution and Router resolution remain disabled.
There is no automatic transport-policy inheritance between nodes.

WireGuard hostname peer endpoints still resolve synchronously during startup.
HttpClient authority/Host and TlsClient SNI do not select a transport endpoint.
PTC fake DNS and TunDevice system-DNS configuration have separate responsibilities.
Selecting chain mode does not control every DNS source or intercept arbitrary
application DNS. Bootstrap the outer VPN endpoint numerically or through an
independent policy/path.

## Runtime and Failure Behavior

On upstream `Init`, the node initializes its application-line state. If DNS is
needed, it delays the next node's `Init` until it has selected an address. It
then forwards that Init and releases retained application payload in FIFO order.
Downstream replies and `Est` can pass once the next Init has started, including
replies made synchronously during that call.

Pending application input is bounded by both 2 MiB of logical bytes and 2 MiB of
retained allocation charge per line. The first queued input pauses its source.
This local DNS/order hold is separate from a received Pause and does not pause
the DNS exchange itself. FIFO drain respects consumer pressure; reentrant input
cannot overtake older bytes. Overflow or resolution failure closes only the
already-initialized directions. Finish destroys local state first and never
reflects a callback toward the side that sent Finish.

Resolution fails if the destination is neither a valid IP nor a domain, submission
fails, or no returned address satisfies the chosen strategy. `direct` and `chain`
retain their no-native-fallback behavior on transport errors and timeouts.

Once next Init has returned, the application FIFO is empty and pressure
notifications have settled, an application normal line permanently bypasses the
resolver. Its full resolver state, including prepare-hook storage, is destroyed
and zeroed first. Internal consumers must use that preparation storage during
Init. Generated DNS lines remain with their transport owner and never deliver
DNS callbacks into the application's previous node. Persistent worker packet
lines remain chain-owned and are not destroyed by the resolver.

The resolver borrows application lines and owns the separate normal DNS lines.
Owner-worker quiescence closes lookup admission, detaches readiness/timer roots
and settles c-ares callbacks and retained references. Channel cleanup drains DNS
lines while neighbors and pools remain alive. Worker stop releases the quiesced
transport; final destruction releases configuration and private children.

## Node Metadata

The application edge is a transparent middle node; it cannot be the chain's
head or tail. Its DNS side edge is separately constrained to L4. Upstream Init
and downstream Est are supported; downstream Init and upstream Est retain the
constructor's rejection behavior. Payload, Pause/Resume and Finish retain their
ordinary bidirectional meanings.

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayerAnything` |
| `layer_group_prev_node` | `kNodeLayerSameAsNext` |
| `layer_group_next_node` | `kNodeLayerSameAsPrev` |
| `required_padding_left` | `0` bytes |
