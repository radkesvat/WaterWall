# TcpConnector Node

`TcpConnector` is an outbound TCP client node. It builds a destination address from its own configuration or from the line routing context, opens a TCP connection, and forwards traffic between the previous node and the remote server.

In practice, this node is used at the end of a chain.

## What It Does

- Chooses a destination address and port.
- Resolves a domain name if needed.
- Opens an outbound TCP socket.
- Forwards upstream payloads from the previous node to the remote socket.
- Forwards remote socket payloads back downstream to the previous node.
- Applies optional socket options such as `TCP_NODELAY`, `TCP_FASTOPEN`, `SO_REUSEADDR`, `SO_MARK`, device binding, and source-IP binding when supported by the platform.

This node behaves like a chain end. Its downstream entry callbacks are disabled because the outbound connection is initiated from upstream `init`.

## Configuration Example

```json
{
  "name": "outbound-tcp",
  "type": "TcpConnector",
  "settings": {
    "address": "example.com",
    "port": 443,
    "nodelay": true,
    "fastopen": false,
    "reuseaddr": false,
    "large-send-buffer": true,
    "large-recv-buffer": 4194304,
    "fwmark": 10,
    "interface": "eth0",
    "source-ip": "192.0.2.10",
    "domain-strategy": 0
  }
}
```

### Multi-Destination Example

```json
{
  "name": "outbound-tcp",
  "type": "TcpConnector",
  "settings": {
    "addresses": [
      {
        "address": "192.0.2.10",
        "port": 443,
        "weight": 5,
        "nodelay": true,
        "fastopen": false,
        "reuseaddr": false,
        "large-send-buffer": true,
        "large-recv-buffer": 4194304,
        "fwmark": 10,
        "interface": "eth0",
        "source-ip": "192.0.2.10",
        "domain-strategy": 1
      },
      {
        "address": "198.51.100.20",
        "port": "dest_context->port",
        "weight": 1,
        "interface": "eth1",
        "source-ip": "198.51.100.10"
      }
    ],
    "address-selection": "weighted-random",
    "nodelay": true,
    "fastopen": false,
    "reuseaddr": false,
    "large-send-buffer": true,
    "large-recv-buffer": true,
    "fwmark": -1,
    "domain-strategy": 0
  }
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TcpConnector"`.

### `settings`

- Either `address` + `port`, or `addresses`

  Choose exactly one style:
  - legacy single-destination fields: `address` and `port`
  - multi-destination field: `addresses` (the parser also accepts `adresses`)

  Do not mix `addresses` with the top-level `address` / `port` fields.

- `address` `(string)`
  Destination address selection for the legacy single-destination form.

  Supported values in the current implementation:
  - a constant IPv4 address
  - a constant IPv6 address
  - a constant domain name
  - `"src_context->address"`
  - `"dest_context->address"`

  Examples:
  - `"93.184.216.34"`
  - `"2606:2800:220:1:248:1893:25c8:1946"`
  - `"example.com"`
  - `"src_context->address"`

  This field expects a host, domain, IP address, CIDR IP range, or supported routing-context token. It is not a full URL
  parser; do not include a scheme such as `https://` or a path.

- `port` `(number or special string)`
  Destination port selection for the legacy single-destination form.

  Supported values in the current implementation:
  - a constant number such as `443`
  - `"src_context->port"`
  - `"dest_context->port"`

- `addresses` `(array of objects)`
  Destination list.

  The parser also accepts the alias `adresses`, but `addresses` is the documented spelling.

  Each object must contain:
  - `address`
  - `port`

  `address` and `port` inside each element support the same forms as the legacy top-level fields.

  `weight` is optional and defaults to `1`. If set, it must be a positive integer. The default `address-selection` mode
  uses these weights to choose one destination for each new line.

  Each object may also contain its own:
  - `nodelay`
  - `fastopen`
  - `reuseaddr`
  - `large-send-buffer`
  - `large-recv-buffer`
  - `fwmark`
  - `interface`
  - `source-ip`
  - `domain-strategy`

  If any of these fields is omitted in an address object, the top-level value from `settings` is used as that object's default. For `interface` and `source-ip`, a per-address JSON `null` disables an inherited top-level value.

## Optional `settings` Fields

- `nodelay` `(boolean)`
  Enables `TCP_NODELAY` on the outbound socket.
  Default: `true`

- `fastopen` `(boolean)`
  Requests `TCP_FASTOPEN` on the outbound socket when the platform exposes that socket option.
  Default: `false`

- `reuseaddr` `(boolean)`
  Enables `SO_REUSEADDR` on the outbound socket.
  Default: `false`

- `large-send-buffer` `(boolean or positive integer)`
  Sets `SO_SNDBUF` on outbound sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `false`, or `true` when this option is omitted and the chain contains `MuxClient` or `MuxServer`.

- `large-recv-buffer` `(boolean or positive integer)`
  Sets `SO_RCVBUF` on outbound sockets.
  `true` uses WaterWall's default large socket buffer size, currently `4194304` bytes. `false` leaves the kernel default unchanged. A positive integer sets the requested byte size directly.
  Default: `false`, or `true` when this option is omitted and the chain contains `MuxClient` or `MuxServer`.

- `fwmark` `(integer)`
  Linux-style socket mark.
  When the platform provides `SO_MARK`, this value is applied to the outbound socket before connect.
  Default: not set

- `interface` `(string)`
  Restricts the outbound socket to a local network device where supported.
  On Linux this uses `SO_BINDTODEVICE`. On platforms without device binding, WaterWall falls back to binding the socket to the interface's IPv4 address.

- `source-ip` `(string)`
  Binds the outbound socket to a specific local source IP with an ephemeral source port before connect.
  This is useful when the host has multiple local addresses and the default route would choose the wrong source address.

  When `addresses` is used, each destination object can override `source-ip`. This is the supported local source-address
  pool model: add multiple destination objects with the same remote `address`/`port` and different `source-ip` values
  if the foreign host owns multiple floating/helper IPs.

- `address-selection` `(string)`
  Selects how `addresses` chooses one destination object for a new line.

  Supported values:
  - `weighted-random`
    Default. Picks a pseudo-random destination with probability proportional to each object's `weight`.
  - `fixed`
    Always uses the first destination object.
  - `round-robin`
    Rotates through destination objects.
  - `random`
    Picks a pseudo-random destination and ignores weights.

- `domain-strategy` `(integer)`
  Selects how domain DNS results are chosen.
  Default: `0`

  Supported values follow WaterWall's domain strategy enum:
  - `0`: invalid/unspecified, accept either IPv4 or IPv6
  - `1`: prefer IPv4
  - `2`: prefer IPv6
  - `3`: only IPv4
  - `4`: only IPv6

When `addresses` is used, these optional fields can be set at the top level as defaults and overridden independently by each address object.
For `large-send-buffer` and `large-recv-buffer`, an omitted top-level value becomes `true` automatically when the finalized chain contains `MuxClient` or `MuxServer`. A per-address omitted value inherits the effective top-level value. Explicit `false` still disables explicit socket buffer sizing.

## Detailed Behavior

### Chain behavior

`TcpConnector` receives line creation from upstream. During upstream `init`, it decides where to connect and immediately starts the outbound TCP connection attempt.

The normal flow is:

- previous node creates or passes a line
- `TcpConnector` selects destination address and port
- optional DNS resolution happens
- outbound socket is created
- asynchronous connect begins
- after connect succeeds, the previous node receives downstream `est`
- data starts flowing in both directions

### Address selection

`address` can come from three places:

- constant value from JSON
- `src_context->address`
- `dest_context->address`

The same is true for `port`.

When `addresses` is used, the same selection rules apply inside each array element.
The connector first picks one destination object using `address-selection`, then resolves that chosen object's `address` and `port` for the line.
The chosen object's socket options and `domain-strategy` are used for that line; omitted option fields inherit the top-level defaults.

This makes `TcpConnector` useful in chains where earlier nodes decode or rewrite routing information. For example, a protocol-aware node can fill `dest_context`, and `TcpConnector` can connect to that decoded target.

For paired SNI/IP reverse TLS or Reality-style paths, keep the layers decoupled by using `TlsClient`/`RealityClient`
`sni-endpoints` to fill the generic destination context, then configure:

```json
{
  "name": "tcp-connector",
  "type": "TcpConnector",
  "settings": {
    "address": "dest_context->address",
    "port": "dest_context->port"
  }
}
```

If you instead configure `TlsClient.settings.snis` and `TcpConnector.settings.addresses`, SNI selection and TCP
destination selection are independent.

### Domain resolution

If the selected destination is a domain name, the connector resolves it asynchronously after upstream `init`. Payloads that arrive while DNS or connect is pending are kept in the normal pre-connect write queue. If resolution fails, the line is finished and no outbound connection is created.

### Subnet randomization on constant IP addresses

If `address` is a constant IP string with a CIDR suffix, the connector randomizes the host part before connecting.

Examples:

- `"198.51.100.0/24"`
- `"2001:db8:1::/64"`

This is only used for constant IP addresses, not for domains and not for `src_context` or `dest_context` lookups.

Current implementation notes:

- IPv4 prefixes wider than `/32` are rejected.
- IPv6 prefixes broader than `/64` are rejected.
- A more specific prefix produces a smaller random range.
- If the range size becomes zero or effectively one host, the destination behaves like a fixed address.

### Socket creation and options

After the destination is ready, `TcpConnector` creates a TCP socket and may apply these options:

- `TCP_NODELAY` when `nodelay` is enabled
- `TCP_FASTOPEN` when `fastopen` is enabled and the platform supports it
- `SO_REUSEADDR` when `reuseaddr` is enabled
- `SO_SNDBUF` when `large-send-buffer` is enabled or set to a byte size
- `SO_RCVBUF` when `large-recv-buffer` is enabled or set to a byte size
- `SO_MARK` when `fwmark` is set and the platform supports it
- `SO_BINDTODEVICE` when `interface` is set and the platform supports it
- `bind(source-ip, 0)` when `source-ip` is set

For weighted `addresses`, these options are taken from the selected address object after applying top-level defaults.

### Data flow direction

- Previous node to remote server: upstream payload -> socket write
- Remote server to previous node: socket read -> downstream payload

Once the outbound socket connects, the node calls downstream `est` toward the previous node.

### Flow control and buffering

While the connection is still being established, or while the socket is temporarily backpressured, `TcpConnector` queues outgoing payloads.

Current thresholds:

- above `1 KB` queued data, the previous node is paused
- when pending writes finish, the previous node is resumed
- above `16 MB` queued data, the connection is closed and the line is finished

This prevents unlimited buffering when the remote side is slow or the connection is not ready yet.

### Idle timeout behavior

Each outbound connection is tracked in an idle table with a timeout of about `300 seconds`. Read and write activity refreshes that timeout. If the connection expires, the socket is closed and downstream `finish` is sent to the previous node.

## Notes And Caveats

- This node is meant to be used as an outbound chain end.
- `fwmark` and device binding are platform-dependent. `fwmark` is not available on Windows.
- DNS resolution in this path is asynchronous.
