<!--
Documentation version: 110
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Router.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/Router.mdx, and all files must keep the same documentation version.
-->

# Router

A layer-4 **rule-based router**. It sits in a chain like a middle tunnel and, on
the **first upstream payload** of each connection, walks an ordered list of rules
to decide where that connection should go:

- the **first** rule whose conditions **all** match (logical `AND`) wins, and the
  connection is handed to that rule's `target` node;
- if **no** rule matches, the connection continues to the node's top-level
  `next` — the **default route**.

```text
client ──▶ Router ──▶ evaluate rules on the first payload
                        │
                        ├─ first matching rule ──▶ its target node
                        └─ no rule matches     ──▶ next (default route)
```

A rule is a `target` plus at least one condition. Conditions can test where the
connection comes from (`source-ips`, `source-port`), where it goes
(`destination-ip`, `destination-port`, `destination-domain`, `network`), what it
carries (`protocol`, `attributes` — sniffed from the first bytes), and who opened
it (`username`, `password`). The full list is in the
[condition reference](#condition-reference).

```json
{
    "name": "router",
    "type": "Router",
    "settings": {
        "rules": [
            { "destination-port": 22, "target": "ssh_path" },
            { "protocol": "tls", "target": "tls_path" }
        ]
    },
    "next": "default_path"
}
```

**Matching semantics**, in one line each:

- **Within one condition** → `OR` (e.g. `destination-port: [80,443]` matches either).
- **Across conditions in one rule** → `AND` (every condition must match).
- **Across rules** → first match wins, in JSON order; later rules are skipped.
- **No match anywhere** → the default `next` route.

## How a connection is routed

The word "router" suggests an immediate, stateless decision. `Router` is the
opposite — a **deferred branch selector**. It holds the connection until the
first upstream payload arrives, so that content-based matchers (`protocol`,
`attributes`, domain sniffing) have bytes to inspect, and only then commits the
whole connection to one branch:

```text
upstream Init ──▶ Router sets up only its own per-line state
                  (no branch is chosen or initialized yet)

first payload ──▶ buffer ──▶ sniff ──▶ evaluate rules top to bottom
                     ▲          │
                     └──────────┘ a detector asked for more bytes:
                                  wait for the next payload (bounded window)
                                │
                                │ decision
                 ┌──────────────┴─────────────────┐
          first matching rule               no rule matched
                 ▼                                ▼
        Init that rule's target          Init the default `next`
        replay the buffered bytes        replay the buffered bytes
```

Step by step:

1. Upstream `Init` initializes only the router's own per-line state and clears
   stale optional routing metadata (detected-protocol flags) on the destination.
   **No branch is initialized yet.**
2. The first upstream payload is buffered and handed to the classifier
   (`routerClassify`).
3. **Sniffing runs first**, scoped to what the config actually needs (see
   [Sniffing](#sniffing)). If a detector needs more bytes, Router keeps
   buffering and re-runs classification on the next payload, within a bounded
   window (see [The sniff window](#the-sniff-window)).
4. **Rules are tested top to bottom in JSON order.** For each rule every
   configured condition is evaluated and `AND`-combined; the first fully
   matching rule selects its `target`.
5. The chosen branch (a rule `target`, or the default `next`) receives `Init`,
   and the buffered bytes are **replayed** to it — nothing is lost. From then on
   payloads flow straight through to that branch, and downstream traffic returns
   through the router.

With `resolve-domains` enabled, an internal `DomainResolver` runs before step 1
and hands the line to Router only after the destination is usable — see
[Resolving domains before routing](#resolving-domains-before-routing).

Consequences worth knowing:

- **A `target` is a real branch, not a fire-and-forget address.** Each target
  node is **folded into the same chain** during `onChain` (exactly like
  [`SniffRouter`](../SniffRouter/description.md) routes), so it gets a per-line
  state slot and its **downstream** traffic flows back **through** the `Router`
  to the previous node.
- **`next` is the default route, not "rule 0".** It is a normal upstream
  continuation used when no rule matches (or when no rules are configured).
- **The decision is made once per connection.** Later payloads are forwarded to
  the selected branch without being reclassified.
- **The client must speak first.** Because the decision is deferred to the first
  upstream payload, a flow where the **server** sends the first bytes sits
  unclassified until upstream bytes arrive — the same limitation `SniffRouter`
  has. Place `Router` where the client side sends first (the common case).

## Settings

The node must define a top-level `next` (the **default route**) and a `settings`
object:

| key | type | required | description |
|-----|------|----------|-------------|
| `rules` | array | no | ordered list of routing rule objects (see [Rules](#rules)). Omitted → everything goes to `next`; present but empty → configuration error |
| `sniffing` | array | no | domain-sniffing modes: `http1`, `http2`, `http`, `tls`, `quic`, `http3` (see [Domain sniffing](#domain-sniffing)). Missing or empty disables domain sniffing |
| `sniff-even-if-domain-is-already-provided` | boolean | no | default `false` (see [When domain sniffing runs](#when-domain-sniffing-runs)) |
| `resolve-domains` | boolean | no | default `false`. Resolve an unresolved domain destination before Router classifies (see [Resolving domains before routing](#resolving-domains-before-routing)) |
| `geoip-db-path` | string | only with `geoip:` tokens | path to a MaxMind country database used by `geoip:<cc>` (see [GeoIP](#geoip)) |
| `geosite-db-path` | string | only with `geosite:` tokens | path to a Router geosite JSON database used by `geosite:<list>` (see [GeoSite](#geosite)) |

A `Router` with no `rules` still sends every connection to `next` (a warning is
logged at startup). Domain sniffing, if enabled and allowed for the line, still
runs in that case, because nodes further up the chain (e.g. a connector) may use
the observed domain.

## Rules

Every rule **must** contain a `target` — the name of the node to route to when
the rule matches — and **at least one** condition:

| key | type | required | description |
|-----|------|----------|-------------|
| `target` | string | **yes** | name of an existing node; must not be the Router itself |

Multiple conditions in the same rule are `AND`-combined. A rule with only
`target` and no conditions is a configuration error. Unknown keys inside a rule
are ignored with a warning.

### Condition reference

| condition | accepts | meaning & notes |
|-----------|---------|-----------------|
| `source-ips` | string or array | Match the line **source** IP against single IPs, CIDR ranges, or `geoip:<cc>` country tokens (e.g. `["10.0.0.0/8", "geoip:ir"]`). A bare IP is a `/32` (or `/128`) host route. Numeric and GeoIP entries are OR-combined. |
| `source-port` | integer or array of integers | Match `src_ctx.port` — the local/inbound port the peer connected to (resolved per-connection, even on multiport backends; i.e. the destination port in the peer's packets) — against exact ports, e.g. `53` or `[80, 443]`. |
| `source-port-range` | two-integer array | Match `src_ctx.port` against an inclusive range, e.g. `[1000, 2000]`. If combined with `source-port`, the exact ports and range are OR-combined. |
| `destination-ip` | string or array | Match the line **destination** IP (`dest_ctx`) against single IPs, CIDR ranges, or `geoip:<cc>`. Numeric and GeoIP entries are OR-combined. A domain-only destination has no IP and does not match; combine with `resolve-domains` when needed. |
| `destination-port` | integer or array of integers | Match `dest_ctx.port` against exact ports, e.g. `53` or `[80, 443]`. |
| `destination-port-range` | two-integer array | Match `dest_ctx.port` against an inclusive range, e.g. `[1000, 2000]`. If combined with `destination-port`, the exact ports and range are OR-combined. |
| `destination-domain` | string or array | Match `dest_ctx.domain`, case-insensitive: exact (`google.com`), wildcard (`*.google.com`, subdomains only), `*` (any domain), or GeoSite lists (`geosite:cn`, see [GeoSite](#geosite)). The domain may come from an earlier tunnel or from [domain sniffing](#domain-sniffing). |
| `network` | string or array | Match the destination transport flags: `tcp`, `udp`, `icmp`, `packet`, or combined in one string `"tcp,udp"`. OR within the field. |
| `protocol` | string or array | Match an application protocol detected from the first upstream payload: `http1`, `tls`, `bittorrent`. OR within the field. See [Protocol detection](#protocol-detection). |
| `attributes` | non-empty array | Match sniffed facts. Currently supports `"http_upgrade_present"`. See [Attribute sniffing](#attribute-sniffing). |
| `username` | string or array | Exact, **case-sensitive** match against authenticated credential markers on the line. No authenticated username → no match. See [Authenticated identity](#authenticated-identity-username--password). |
| `password` | string or array | Exact, **case-sensitive** match against authenticated credential markers on the line. No authenticated password → no match. |

## Sniffing

Rules like `protocol`, `attributes`, and — for IP-only destinations —
`destination-domain` need information that only exists **inside** the
connection's first bytes. Router can sniff three kinds of facts from the
buffered first payload. Each kind has its own switch and its own storage; none
of them implies another:

| fact | switched on by | stored in | matched by |
|------|----------------|-----------|------------|
| destination domain — HTTP `Host`, HTTP/2 `:authority`, TLS/QUIC SNI | root `sniffing` setting | `dest_ctx.domain` | `destination-domain` |
| application protocol — `http1`, `tls`, `bittorrent` | automatic: any rule that uses `protocol` | `dest_ctx.optional_flags.detected_protocols` | `protocol` |
| HTTP `Upgrade:` header present | a rule that uses `attributes`, plus `sniffing` containing `http1` | Router's per-line state | `attributes` |

All three read the same buffered first payload and share the same bounded
window (see [The sniff window](#the-sniff-window)).

### Domain sniffing

`destination-domain` rules match `dest_ctx.domain` — and that field is often
empty by the time the line reaches Router:

- An upstream proxy tunnel (`Socks5Server`, `TrojanServer`, `VlessServer`, …)
  passes on whatever the client requested. That may be a hostname — but a
  client can just as well send a literal IP, because it resolved the name
  itself, uses DoH/DoT or another DNS path, or forwards traffic that was
  IP-only from the start.
- A transparent flow (e.g. `TunDevice → PacketsToConnection`) only ever has an
  IP destination.

Domain sniffing recovers the name from data the client itself put inside the
connection — the HTTP/1 `Host` header, the HTTP/2 `:authority` pseudo-header,
or the TLS/QUIC SNI — and stores it in `dest_ctx.domain`, where
`destination-domain` rules and nodes further up the chain can use it. It is
enabled by the root-level `sniffing` setting, outside `rules`:

```json
{ "sniffing": ["http", "tls", "http3"] }
```

| value | reads |
|-------|-------|
| `http1` | the HTTP/1 `Host` header |
| `http2` | cleartext HTTP/2 prior-knowledge `:authority`, falling back to `host` |
| `http` | alias for `http1` + `http2` |
| `tls` | the TLS ClientHello SNI |
| `quic` | the QUIC Initial TLS ClientHello SNI |
| `http3` | alias for `quic` |

Details:

- Values are parsed case-insensitively. A missing or empty array disables
  domain sniffing entirely.
- `http` intentionally does **not** include HTTP/3; use `["http", "http3"]`
  when you want HTTP/1, cleartext HTTP/2, and HTTP/3 domain sniffing together.
- `http2` applies only to TCP-only destinations and only to prior-knowledge
  cleartext HTTP/2; h2c **upgrade** requests are covered by `http1` Host
  sniffing. `quic`/`http3` applies only to UDP-only destinations.
- The first enabled sniffer that finds a name wins; the remaining sniffers are
  skipped.
- Build requirements: `http2` needs the CMake option
  `router_enable_http2_sniffing` (default `ON`, requires nghttp2);
  `quic`/`http3` needs `router_enable_quic_sniffing` (default `ON`, requires
  OpenSSL). Because `http` expands to `http1` + `http2`, it also needs the
  HTTP/2 build option.
- These values configure root `settings.sniffing` only; they are **not** valid
  `rules[].protocol` values.

### When domain sniffing runs

A Host/:authority/SNI value is data the **client** put inside the connection.
That is exactly what you want for labeling an IP-only destination — but a
domain that is already on `dest_ctx` was chosen by an earlier tunnel or by the
config, and overwriting it with client-supplied data could change what an
upstream connector resolves and connects to. So, per line:

- **`dest_ctx.domain` is empty** → domain sniffing runs.
- **`dest_ctx.domain` is already set** → domain sniffing is skipped and the
  existing domain stays unchanged (the default,
  `sniff-even-if-domain-is-already-provided: false`).

Set `sniff-even-if-domain-is-already-provided: true` only when the chain
deliberately trusts the application-layer Host/:authority/SNI more than the
domain already on the line.

This switch affects only domain sniffing. Protocol detection and attribute
sniffing never touch `dest_ctx.domain`, so they run regardless of it.

### What a sniffed domain changes

A found domain is written to `dest_ctx.domain` through the observed-domain
path, which **preserves the endpoint**: IP address, port, transport flags,
optional protocol flags, and address type are kept. What an upstream connector
later does depends on the destination shape:

| destination shape | result |
|-------------------|--------|
| concrete IP, no existing domain | domain stored, `domain_resolved = true` → upstream connectors keep using the original IP and do **not** resolve the sniffed name |
| wildcard/any IP (`0.0.0.0`, `::`), no existing domain | domain stored, but not treated as resolved because there is no concrete endpoint IP |
| existing domain, default setting | domain sniffing is skipped; `dest_ctx.domain` is not overwritten |
| domain-only (no IP), with `sniff-even-if-domain-is-already-provided: true` | sniffed domain **replaces** `dest_ctx.domain`, `domain_resolved = false` → an upstream connector will DNS-resolve and connect to the **new** name |

### Protocol detection

The `protocol` condition matches an application protocol detected from the
first upstream payload. It needs no root `sniffing`: if any rule uses
`protocol`, the requested detectors run automatically before classification.

| value | detects |
|-------|---------|
| `http1` | an HTTP/1 request method prefix (`GET `, `POST `, …) — note: **not** the HTTP/2 preface |
| `tls` | a TLS ClientHello record |
| `bittorrent` | the BitTorrent handshake prefix (`0x13` followed by `BitTorrent protocol`) |

- Multiple values are OR-combined: `"protocol": ["tls", "bittorrent"]` matches
  either.
- Unknown values are **fatal** configuration errors. `http`, `http2`, `quic`,
  and `http3` are domain-sniffing modes, not `protocol` values, and are
  rejected here.
- `http1` is a cheap method-prefix signal: any payload that begins with an HTTP
  verb token is flagged `http1`, even if it is not really HTTP. `tls` and
  `bittorrent` are stronger structural/signature checks.

Detected bits live in `dest_ctx.optional_flags.detected_protocols`. They are
**optional routing metadata, not endpoint identity**: only Router's own
sniffing sets them, and Router **clears them in upstream `Init`** before each
new classification — so chaining two Routers never lets the second inherit
stale protocol bits from the first.

### Attribute sniffing

`attributes` matches sniffed boolean facts about the connection. The only value
today is `"http_upgrade_present"`, which matches when the first HTTP/1 request
carries an `Upgrade:` header (e.g. a WebSocket or other protocol upgrade):

```json
{ "attributes": ["http_upgrade_present"], "target": "ws_backend" }
```

- It requires root `sniffing` to include `http1`. Otherwise the bit is never
  set and such rules never match (Router logs a warning at startup).
- Unlike domain sniffing, the upgrade check **also runs when a destination
  domain is already provided** — it never writes to `dest_ctx.domain`.
- It constrains **only** rules that request it; other rules can still match the
  same connection by their own conditions.
- The `attributes` array must be **non-empty**, and unknown attribute names are
  **fatal** configuration errors (so a typo can't silently turn a rule into a
  match-all).

### The sniff window

Every detector reads the payload Router has buffered so far. When a detector
reports **"needs more bytes"** — a partial HTTP request, a split TLS
ClientHello, a partial HTTP/2 preface/HEADERS block — Router keeps the pending
buffer and re-runs classification when the next payload arrives.

The wait is **bounded**:

- Non-matching payloads are rejected on their first bytes: an HTTP detector
  bails the moment the bytes are not a method, a TLS detector the moment byte 0
  is not `0x16`, and so on.
- A plausible-but-incomplete payload can delay classification only up to the
  shared sniff window of **8 KiB** (`kGenericSnifferMaxWindowBytes`). Once the
  buffered bytes reach that size, detectors report their fact as absent and
  Router classifies with the facts it has.

One more consequence: Router makes **one shared decision per connection**, so a
single rule with `protocol` or `http_upgrade_present` means Router inspects the
first-payload window of **every** connection on that node — not just the
connections that end up matching that rule.

## Resolving domains before routing

When `resolve-domains` is `true`, Router creates an internal `DomainResolver`
placed before itself in the chain. That resolver receives upstream `Init`
first and uses the core DNS strategy to resolve the destination when — and only
when — it is an unresolved domain. Router's own `Init`, first-payload
buffering, sniffing, and rule classification run only after that resolution has
succeeded.

Use it when an earlier node supplies a **domain** destination but your rules
need an **IP** fact — `destination-ip`, including its `geoip:` tokens.

Notes:

- Destinations that are already IP-typed or already marked domain-resolved pass
  through the resolver unchanged.
- The resolver runs before Router's own domain sniffing, so it never
  re-resolves a domain that Router sniffs later. A domain sniffed on a
  concrete-IP line is stored for matching only — the original IP remains the
  connection endpoint (see
  [What a sniffed domain changes](#what-a-sniffed-domain-changes)).

## GeoIP & GeoSite databases

`geoip:<cc>` and `geosite:<list>` tokens need their databases configured, but
only when a parsed rule actually uses them.

### GeoIP

`geoip-db-path` points to a **MaxMind country database** and enables
`geoip:<cc>` tokens in `source-ips` and `destination-ip`. Country codes are
two-letter ISO-3166 codes, parsed case-insensitively (e.g. `geoip:ir`,
`geoip:us`).

- Required only when at least one parsed rule uses a `geoip:` token.
- An IP that is not found in the database simply does not match.
- A domain-only destination has no IP to look up; combine with
  `resolve-domains` when needed.

### GeoSite

`geosite-db-path` points to a Router geosite JSON database generated by
`tunnels/Router/geosite_ww_style_generator/do_the_job.py` and enables
`geosite:<list>` tokens in `destination-domain`.

- Validated and loaded only when at least one parsed rule uses a `geosite:`
  token. A missing, empty, unreadable, or invalid-JSON path, an invalid GeoSite
  regex, or a reference to an unknown list name **fails Router creation**.
- At startup Router resolves the referenced list names once, compiles only
  those lists (exact-domain and suffix-domain hash sets, plain substring
  patterns, and STC `cregex` programs), then releases the raw JSON database.

Entry types inside a list:

| GeoSite type | match behavior |
|--------------|----------------|
| `full` | exact domain |
| `domain` (alias `root_domain`) | the root domain and its subdomains |
| `plain` (alias `keyword`) | case-insensitive substring |
| `regex` (alias `regexp`) | STC `cregex` pattern, matched case-insensitively |

## Authenticated identity (`username` / `password`)

`username` and `password` match credential markers that **authenticating
tunnels** stored on the line, so Router needs no users-table lookup. Both
matches are exact and case-sensitive. When a rule contains both `username` and
`password`, they must match the same credential marker; stacked authentication
layers do not mix a username from one layer with a password from another.

How they get populated:

| upstream tunnel | username | password |
|-----------------|----------|----------|
| `Socks5Server` | the client-supplied SOCKS username | the client-supplied SOCKS password |
| `TrojanServer` / `VlessServer` (user mode) | the **account name** resolved from the authenticated user | the raw password (Trojan) / canonical UUID (Vless), resolved in one locked lookup |
| `TrojanServer` / `VlessServer` (local allowlist mode) | optional configured local username | optional local raw password (Trojan) / canonical UUID (Vless) |

> The username differs **in kind** by protocol: SOCKS5 exposes the client-typed
> username, while Trojan/Vless expose the server-side account name. A connection
> with no authenticated credential never matches a `username`/`password` condition.

## Recipes

### Share one inbound port across backends, by domain

Route GeoSite-CN and a vendor wildcard one way, everything else direct. Domain
sniffing lets `destination-domain` rules work even for IP-only destinations:

```json
{
    "name": "router",
    "type": "Router",
    "settings": {
        "geosite-db-path": "/var/lib/waterwall/geosite_generated.json",
        "sniffing": ["http", "tls", "http3"],
        "rules": [
            { "destination-domain": ["geosite:cn", "*.vendor.example"], "target": "cn_proxy" }
        ]
    },
    "next": "default_direct"
}
```

### Split WebSocket upgrades from plain HTTP

Send upgrade requests to a WebSocket backend; plain HTTP falls through to `next`:

```json
{
    "name": "router",
    "type": "Router",
    "settings": {
        "sniffing": ["http1"],
        "rules": [
            { "attributes": ["http_upgrade_present"], "target": "ws_backend" }
        ]
    },
    "next": "http_backend"
}
```

### Multi-condition rule (everything is `AND`)

```json
{
    "network": "udp",
    "destination-port": 443,
    "protocol": "bittorrent",
    "target": "bittorrent_sink"
}
```

This rule matches only a connection that is UDP **and** targets port 443 **and**
is detected as BitTorrent. Any one failing → the rule is skipped.

### Per-user and per-source routing

```json
{
    "name": "router",
    "type": "Router",
    "settings": {
        "geoip-db-path": "/var/lib/GeoLite2-Country.mmdb",
        "rules": [
            { "username": "alice", "target": "premium_path" },
            { "source-ips": ["10.0.0.0/8", "geoip:ir"], "target": "lan_path" }
        ]
    },
    "next": "default_path"
}
```

## Router vs SniffRouter

Both share the same lazy-decision, target-folding lifecycle; they differ in the
**decision input**:

- Use **`Router`** to route on a flexible mix of **connection facts** —
  source/destination address, ports, network type, detected protocol,
  authenticated identity, and (optionally sniffed) destination domain.
- Use **[`SniffRouter`](../SniffRouter/description.md)** when you only need to
  route on the **first decrypted/visible bytes** (HTTP `Host`/`:authority`,
  TLS/QUIC SNI, or the
  ReverseClient/ReverseServer handshake) — for example to share one TLS port
  between several HTTP backends.

## Module architecture (for contributors)

Each condition is its own matcher/parser module under `modules/<field>/`,
mirroring how `AuthenticationServer` splits each API into a module:

```text
modules/
  matchers.c            # dispatcher table tying all matchers together
  source_ips/           # one module per condition; each owns:
  source_port/          #   <field>Parse   -> read + validate the field from JSON
  network/              #   <field>Match   -> test the condition
  protocol/             #   <field>Destroy -> free owned memory
  attributes/
  destination_ip/
  destination_domain/
  destination_port/
  username/
  password/
```

Every matcher implements the same interface over its own slice of
`router_rule_t`:

```c
router_field_parse_t  <field>Parse  (router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                  <field>Match  (const router_rule_t *rule, const router_match_ctx_t *mctx);
void                  <field>Destroy(router_rule_t *rule);
```

`router_match_ctx_t` carries the `line_t` (for routing metadata: source/destination
address, ports, network type, optional detected protocols, and authenticated user)
plus the buffered first-payload window used by sniffing before the matcher table
runs. `modules/matchers.c` is the single registry of matchers; adding a condition
type is: create `modules/<field>/`, then add one row to the `kRouterMatchers`
table.
