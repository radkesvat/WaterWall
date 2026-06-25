# Router

A layer-4 **rule-based router**. It sits in a chain like a middle tunnel and, on
the **first upstream payload** of each connection, walks an ordered list of rules
to decide where that connection should go:

- the **first** rule whose conditions **all** match (logical `AND`) wins, and the
  connection is handed to that rule's `target` node;
- if **no** rule matches, the connection continues to the node's top-level
  `next` — the **default route**.

## At a glance

```text
client ──▶ Router ──▶ evaluate rules on the first payload
                        │
                        ├─ first matching rule ──▶ its target node
                        └─ no rule matches     ──▶ next (default route)
```

A rule is `target` **plus at least one condition**. Conditions you can use:

| Condition | Matches on | Example value |
|-----------|------------|---------------|
| `source-ips` | client source IP, CIDR, or `geoip:<cc>` | `["10.0.0.0/8", "geoip:ir"]` |
| `source-port` | local/inbound port the peer connected to | `[80, 443]` |
| `source-port-range` | inclusive local/inbound port range | `[1000, 2000]` |
| `destination-ip` | destination IP, CIDR, or `geoip:<cc>` | `"geoip:us"` |
| `destination-port` | destination port, single or list | `443` |
| `destination-port-range` | inclusive destination port range | `[1000, 2000]` |
| `destination-domain` | destination domain: exact, wildcard, `*`, or `geosite:<list>` | `["*.example.com", "geosite:cn"]` |
| `network` | transport type: `tcp`, `udp`, `icmp`, `packet` | `"tcp,udp"` |
| `protocol` | app protocol sniffed from first bytes: `http1`, `tls`, `bittorrent` | `"tls"` |
| `attributes` | sniffed facts: `http_upgrade_present` | `["http_upgrade_present"]` |
| `username` | authenticated username on the line | `"alice"` |
| `password` | authenticated password on the line | `"s3cret"` |

**Matching semantics**, in one line each:

- **Within one condition** → `OR` (e.g. `destination-port: [80,443]` matches either).
- **Across conditions in one rule** → `AND` (every condition must match).
- **Across rules** → first match wins, in JSON order; later rules are skipped.
- **No match anywhere** → the default `next` route.

## Mental model: a deferred branch selector

The word "router" suggests an immediate, stateless decision. `Router` is the
opposite — it is a **deferred branch selector**, and most surprises come from
missing that:

- **It does not route at `Init`.** It waits for the first upstream payload so
  content-based matchers (`protocol`, `attributes`, domain sniffing) have bytes
  to inspect. Those buffered bytes are then **replayed** to the chosen branch with
  nothing lost.
- **A `target` is a real branch, not a fire-and-forget address.** Each `target`
  node is **folded into the same chain** during `onChain` (exactly like
  [`SniffRouter`](../SniffRouter/description.md) routes), so the target gets a
  per-line state slot and its **downstream** traffic flows back **through** the
  `Router` to the previous node.
- **`next` is the default route, not "rule 0".** It is a normal upstream
  continuation used when no rule matches (or when no rules are configured).
- **The client must speak first.** Because the decision is deferred to the first
  upstream payload, a flow where the **server speaks first** (no initial client
  bytes) will sit unclassified until bytes arrive — the same limitation
  `SniffRouter` has. Place `Router` where the client side sends first (the common
  case).

## Lifecycle: how a connection is routed

If `resolve-domains` is enabled, an internal `DomainResolver` runs before step 1
and forwards `Init` to Router only after the original destination is either
already usable or DNS resolution has succeeded.

1. Upstream `Init` initializes only the router's own per-line state and clears any
   stale optional routing metadata on the destination. **No branch is initialized
   yet.**
2. The first upstream payload is buffered and passed to the rule evaluator
   (`routerClassify`).
3. **Sniffing runs first**, scoped to what the rules actually need:
   - if any rule uses `protocol`, the requested protocol detectors run and store
     their result in `dest_ctx.optional_flags`;
   - if `sniffing` is enabled, Host/SNI detection runs to populate
     `dest_ctx.domain`. Domain sniffing runs even with no rules configured,
     because branches further up the chain (e.g. a connector) may still use that
     metadata.
   - if a detector **needs more bytes**, Router keeps buffering and re-evaluates
     on the next payload (see [First-payload buffering](#first-payload-buffering)).
4. **Rules are tested top to bottom in JSON order.** For each rule every
   configured condition is evaluated and `AND`-combined; the first fully matching
   rule selects its `target`.
5. The chosen branch (a rule `target`, or the default `next`) is initialized and
   the buffered bytes are **replayed** to it. From then on payloads flow straight
   through to that branch, and downstream traffic returns through the router.

## Settings

The node must define a top-level `next` (the **default route**) and a `settings`
object:

| key | type | required | description |
|-----|------|----------|-------------|
| `rules` | array | no | ordered list of routing rule objects (see [Rules](#rules)) |
| `resolve-domains` | boolean | no | default `false`. Resolve an unresolved domain destination before Router classifies the first payload |
| `sniffing` | array | no | domain-sniffing methods: `http1`, `tls`. Missing or empty disables domain sniffing |
| `sniff-even-if-domain-is-already-provided` | boolean | no | default `false`. When `false`, Router will not sniff or overwrite a destination that already has `dest_ctx.domain` |
| `geoip-db-path` | string | only with `geoip:` tokens | path to a MaxMind country database used by `geoip:<cc>` |
| `geosite-db-path` | string | only with `geosite:` tokens | path to a Router geosite JSON database (see [GeoIP & GeoSite](#geoip--geosite-databases)) |

A `Router` with no `rules` still sends every connection to `next` (a warning is
logged at startup); if `sniffing` is enabled it may first inspect the initial
payload to fill `dest_ctx.domain`.

## Optional DNS resolution before routing

When `resolve-domains` is `true`, Router creates an internal `DomainResolver`
before itself in the chain. That resolver receives upstream `Init` first and
uses the core DNS strategy to resolve `dest_ctx` only when the destination is an
unresolved domain. Router's own `Init`, first-payload buffering, sniffing, and
rule classification run only after that resolution succeeds.

The resolver deliberately does nothing for destinations that are already
IP-typed or already marked domain-resolved. Because it runs before Router's
Host/SNI sniffing, it also does not re-resolve sniffed domains. If a line already
has an IP destination, Router may still store a sniffed Host/SNI domain as
metadata for `destination-domain` matching, but the original IP remains the
connection endpoint.

## Rules

### Rule object

Every rule **must** contain a `target` and **at least one** match condition:

| key | type | required | description |
|-----|------|----------|-------------|
| `target` | string | **yes** | name of the node to route to when this rule matches |

Multiple conditions in the same rule are `AND`-combined. Unknown keys inside a
rule are ignored with a warning. An empty rule (only `target`) is a configuration
error.

### Condition reference

| condition | accepts | meaning & notes |
|-----------|---------|-----------------|
| `source-ips` | string or array | Match the line **source** IP against single IPs, CIDR ranges, or `geoip:<cc>` country tokens (e.g. `geoip:ir`). A bare IP is a `/32` (or `/128`) host route. Numeric and GeoIP entries are OR-combined. |
| `source-port` | integer or array of integers | Match `src_ctx.port` — the local/inbound port the peer connected to (resolved per-connection, even on multiport backends; i.e. the destination port in the peer's packets) — against exact ports, e.g. `53` or `[80, 443]`. |
| `source-port-range` | two-integer array | Match `src_ctx.port` against an inclusive range, e.g. `[1000, 2000]`. If combined with `source-port`, the exact ports and range are OR-combined. |
| `destination-ip` | string or array | Match the line **destination** IP (`dest_ctx`) against single IPs, CIDR ranges, or `geoip:<cc>`. Numeric and GeoIP entries are OR-combined. A domain-only destination has no IP and does not match. |
| `destination-port` | integer or array of integers | Match `dest_ctx.port` against exact ports, e.g. `53` or `[80, 443]`. |
| `destination-port-range` | two-integer array | Match `dest_ctx.port` against an inclusive range, e.g. `[1000, 2000]`. If combined with `destination-port`, the exact ports and range are OR-combined. |
| `destination-domain` | string or array | Match `dest_ctx.domain`, case-insensitive: exact (`google.com`), wildcard (`*.google.com`, subdomains only), `*` (any domain), or compiled GeoSite lists (`geosite:cn`). Can match a sniffed Host/SNI value (see [Sniffing](#sniffing-host--sni)). |
| `network` | string or array | Match the destination transport flags: `tcp`, `udp`, `icmp`, `packet`, or combined in one string `"tcp,udp"`. OR within the field. |
| `protocol` | string or array | Match an application protocol detected from the first upstream payload: `http1`, `tls`, `bittorrent`. OR within the field. See [Protocol detection](#protocol-detection). |
| `attributes` | non-empty array | Match sniffed facts. Currently supports `"http_upgrade_present"`. See [Attributes](#attributes). |
| `username` | string or array | Exact, **case-sensitive** match of the authenticated username on the line. No authenticated username → no match. See [Authenticated identity](#authenticated-identity-username--password). |
| `password` | string or array | Exact, **case-sensitive** match of the authenticated password on the line. No authenticated password → no match. |

> **GeoSite domain semantics:** `domain` lists match the root and its subdomains,
> `full` lists match exactly, `plain` lists match by substring, and `regex` lists
> use STC `cregex` syntax (case-insensitive).

## Sniffing (Host / SNI)

`sniffing` lets Router read the destination **domain** from the connection's own
first bytes, so `destination-domain` rules can classify an originally IP-only
destination (e.g. a transparent-proxy flow). It is a root-level setting, outside
`rules`:

```json
{ "sniffing": ["http1", "tls"] }
```

| value | reads |
|-------|-------|
| `http1` | the HTTP/1 `Host` header |
| `tls` | the TLS ClientHello SNI |

Values are an array, parsed case-insensitively. Missing or empty disables domain
sniffing. The old `http` value was removed — use `http1`.

### Why Router won't overwrite an existing domain by default

A Host header or TLS SNI is data the **client** put inside the connection. It is
great for labelling an IP-only destination, but a domain already on `dest_ctx` was
usually chosen by an earlier tunnel or the config parser — replacing it with
client-supplied Host/SNI could change what an upstream connector resolves and
connects to. So by default (`sniff-even-if-domain-is-already-provided: false`)
Router treats Host/SNI as **extra metadata for IP-backed destinations only** and
never lets it redirect a domain-backed destination.

### What sniffing stores

When Host/SNI is found, Router writes it to `dest_ctx.domain` **without replacing
the endpoint** — the original IP, port, transport flags, optional protocol flags,
and address type are all preserved. The resolution behavior then depends on the
destination shape:

| destination shape | result |
|-------------------|--------|
| concrete IP | domain stored, `domain_resolved = true` → upstream connectors keep using the original IP and do **not** re-resolve the sniffed name |
| wildcard/any IP (`0.0.0.0`, `::`) | not treated as resolved; domain stored as a hint only |
| domain-only (no IP), with `sniff-even-if-domain-is-already-provided: true` | sniffed domain replaces `dest_ctx.domain`, `domain_resolved = false` → an upstream connector will DNS-resolve and connect to the **new** name |

Enable `sniff-even-if-domain-is-already-provided` only when the chain deliberately
trusts the application-layer Host/SNI more than the domain already on the line.

## Protocol detection

The `protocol` condition matches an application protocol that Router detects from
the first upstream payload:

| value | detects |
|-------|---------|
| `http1` | an HTTP/1 request method prefix (`GET `, `POST `, …) — note: **not** the HTTP/2 preface |
| `tls` | a TLS ClientHello record |
| `bittorrent` | the BitTorrent handshake prefix (`0x13` followed by `BitTorrent protocol`) |

Multiple values are OR-combined: `"protocol": ["tls", "bittorrent"]` matches
either. The old `http` value was removed; unknown values are **fatal**
configuration errors.

Detected bits live in `dest_ctx.optional_flags.detected_protocols`. They are
**optional routing metadata, not endpoint identity**: only Router's own sniffing
sets them, and Router **clears them in upstream `Init`** before each new
classification — so chaining two Routers never lets the second inherit stale
protocol bits from the first.

> `http1` is a cheap method-prefix signal: any payload that begins with an HTTP
> verb token is flagged `http1`, even if it is not really HTTP. `tls` and
> `bittorrent` are stronger structural/signature checks.

## Attributes

`attributes` matches sniffed boolean facts about the connection. The only value
today is `"http_upgrade_present"`, which matches when the first HTTP/1 request
carries an `Upgrade:` header (e.g. a WebSocket or other protocol upgrade):

```json
{ "attributes": ["http_upgrade_present"], "target": "ws_backend" }
```

Rules and behavior:

- It requires root `sniffing` to include `"http1"`. If HTTP sniffing is disabled
  the bit is never set and such rules never match (Router logs a warning at
  startup if the attribute is used without `http1` sniffing).
- Unlike Host/SNI sniffing, the upgrade check **also runs when a destination
  domain is already provided**, and it never overwrites `dest_ctx.domain`.
- It constrains **only** rules that request it; other rules can still match the
  same connection by their own conditions.
- The `attributes` array must be **non-empty**, and unknown attribute names are
  **fatal** configuration errors (so a typo can't silently turn a rule into a
  match-all).

## First-payload buffering

Sniffing and protocol/attribute detection all read the buffered first payload.
When a detector reports **"needs more bytes"**, Router keeps its pending buffer
and re-evaluates as more data arrives, until the fact is found, the detector
decides it is absent, or the bounded sniff window is exhausted.

Two consequences worth knowing:

- Because Router makes **one shared decision per connection**, enabling any
  `protocol` or `http_upgrade_present` rule means Router inspects the first-payload
  window before classifying **every** connection on that node — not just the
  connection that eventually matches the rule.
- The wait is **bounded**: non-matching payloads are rejected on their first
  bytes (an HTTP detector bails the moment the bytes aren't a method, a TLS
  detector the moment byte 0 isn't `0x16`, etc.), and partial-but-plausible
  payloads only delay classification up to the sniff window.

## GeoIP & GeoSite databases

`geoip:<cc>` and `geosite:<list>` tokens need their databases configured, but only
when a parsed rule actually uses them:

- **`geoip-db-path`** — a MaxMind country database. Enables `geoip:<cc>` tokens in
  `source-ips` and `destination-ip`.
- **`geosite-db-path`** — a Router geosite JSON database generated by
  `tunnels/Router/geosite_ww_style_generator/do_the_job.py`. Enables
  `geosite:<list>` tokens in `destination-domain`.

`geosite-db-path` is validated and loaded only when at least one parsed rule uses
a `geosite:` token. A missing, empty, unreadable, or invalid-JSON path, an invalid
GeoSite regex, or a reference to an unknown list name **fails Router creation**.
Router resolves the referenced list names once at startup, compiles only those
lists into exact-domain and suffix-domain hash sets, plain substring patterns, and
STC `cregex` programs, then releases the raw JSON database. `full`, `domain`,
`plain`, and `regex` GeoSite entry types are supported; regex matching is
case-insensitive.

## Authenticated identity (`username` / `password`)

`username` and `password` match credentials that the **authenticating tunnel**
stored on the line (`lineGetAuthenticatedUsername` / `lineGetAuthenticatedPassword`),
so Router needs no users-table lookup. Both matches are exact and case-sensitive.

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

Route GeoSite-CN and a vendor wildcard one way, everything else direct. Host/SNI
sniffing lets domain rules work even for IP-only destinations:

```json
{
    "name": "router",
    "type": "Router",
    "settings": {
        "geosite-db-path": "/var/lib/waterwall/geosite_generated.json",
        "sniffing": ["http1", "tls"],
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
  route on the **first decrypted/visible bytes** (HTTP `Host`, TLS SNI, or the
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
  username/
  destination_port/
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
