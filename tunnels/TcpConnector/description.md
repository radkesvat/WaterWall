# TcpConnector Node

`TcpConnector` is an outbound TCP client node. It builds a destination address from its own configuration or from the line routing context, opens a TCP connection, and forwards traffic between the previous node and the remote server.

In practice, this node is used at the end of a chain.

## What It Does

- Chooses a destination address and port.
- Resolves a domain name if needed.
- Opens an outbound TCP socket.
- Forwards upstream payloads from the previous node to the remote socket.
- Forwards remote socket payloads back downstream to the previous node.
- Applies optional socket options such as `TCP_NODELAY`, `TCP_FASTOPEN`, and `SO_MARK` when supported by the platform.

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
    "fwmark": 10,
    "domain-strategy": 0
  }
}
```

### Weighted Multi-Destination Example

```json
{
  "name": "outbound-tcp",
  "type": "TcpConnector",
  "settings": {
    "addresses": [
      {
        "address": "192.0.2.10",
        "port": 443,
        "weight": 5
      },
      {
        "address": "198.51.100.20",
        "port": "dest_context->port",
        "weight": 1
      }
    ],
    "nodelay": true,
    "fastopen": false,
    "reuseaddr": false
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
  - weighted multi-destination field: `addresses` (the parser also accepts `adresses`)

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

- `port` `(number or special string)`
  Destination port selection for the legacy single-destination form.

  Supported values in the current implementation:
  - a constant number such as `443`
  - `"src_context->port"`
  - `"dest_context->port"`

- `addresses` `(array of objects)`
  Weighted destination list.

  The parser also accepts the alias `adresses`, but `addresses` is the documented spelling.

  Each object must contain:
  - `address`
  - `port`
  - `weight`

  `address` and `port` inside each element support the same forms as the legacy top-level fields.

  `weight` must be a positive integer.
  Each new line chooses exactly one element from the array, with probability proportional to its weight.

## Optional `settings` Fields

- `nodelay` `(boolean)`
  Enables `TCP_NODELAY` on the outbound socket.
  Default: `true`

- `fastopen` `(boolean)`
  Requests `TCP_FASTOPEN` on the outbound socket when the platform exposes that socket option.
  Default: `false`

- `reuseaddr` `(boolean)`
  Parsed from JSON and stored in the tunnel state.
  Default: `false`

  Note: in the current implementation this option is not applied to the socket with `setsockopt`.

- `fwmark` `(integer)`
  Linux-style socket mark.
  When the platform provides `SO_MARK`, this value is applied to the outbound socket.
  Default: not set

- `domain-strategy` `(integer)`
  Parsed and stored in the tunnel state.
  Default: `0`

  Note: the current connector path does not apply this value during DNS resolution.

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
The connector first picks one destination object by weight, then resolves that chosen object's `address` and `port` for the line.

This makes `TcpConnector` useful in chains where earlier nodes decode or rewrite routing information. For example, a protocol-aware node can fill `dest_context`, and `TcpConnector` can connect to that decoded target.

### Domain resolution

If the selected destination is a domain name, the connector resolves it synchronously during upstream `init`. If resolution fails, the line is finished immediately and no outbound connection is created.

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
- `SO_MARK` when `fwmark` is set and the platform supports it

The code currently parses `reuseaddr`, but it does not call `SO_REUSEADDR` for the outbound socket.

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
- `domain-strategy` is currently stored but not actively used by the connector path.
- `reuseaddr` is currently parsed but not applied.
- DNS resolution in this path is synchronous.
