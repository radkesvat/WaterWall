# SynReply

`SynReply` is an internal Layer 3 middle node. For each qualifying upstream TCP SYN, it hands the original packet to `next`, then sends one separate SYN-ACK to `prev` while that worker's path is open. Both neighbors must use the chain-owned worker packet line. A retransmitted SYN gets another reply. The TCP endpoints handle the rest of the handshake.

## Packet flow

In a `RawSocket → SynReply → TunDevice` chain, captured SYNs travel toward `TunDevice`, and generated replies return toward `RawSocket`.

| Packet arriving at SynReply | Original packet | Generated reply |
| --- | --- | --- |
| Upstream, unfragmented IPv4 opening SYN with no payload and valid headers and checksums | Forwarded unchanged to `next` | One SYN-ACK toward the sender, with the TCP ports reversed |
| Other upstream traffic, including IPv6, fragments, SYNs carrying data, and subsequent ACKs | Forwarded unchanged to `next` | None |
| Any downstream traffic, including a real listener's SYN-ACK | Forwarded unchanged to `prev` | None |

Opening SYNs may carry TCP options or ECN flags. SynReply checks the IPv4 and TCP checksums on the bytes it receives and preserves any pending checksum-repair request on the original. Packets with an unspecified (`0.0.0.0`), limited broadcast (`255.255.255.255`), or multicast (`224.0.0.0/4`) address at either end pass through without a reply.

## Settings

Set `type` to `"SynReply"` and `next` to the name of the next Layer 3 node. All three fields below are optional. Omitting `settings` or using `{}` applies all defaults.

| Setting | JSON type and accepted values | Default | Effect on the generated SYN-ACK |
| --- | --- | --- | --- |
| `reply-source-ip` | String containing one unicast IPv4 address, e.g. `"192.0.2.20"` | Destination IPv4 address of each observed SYN | Sets the reply's source address. A configured address **must belong to the server running SynReply**. The reply's destination is always the original sender. |
| `ttl` | Integer, `1`–`255` | `64` | Sets the outgoing IPv4 time to live. |
| `fake-checksum` | Boolean, `true` or `false` | `false` | `true` produces a nonzero, invalid TCP checksum. `false` produces a valid TCP checksum. The IPv4 header checksum is valid in both modes. |

Unknown or duplicate keys, `null`, and values of the wrong JSON type fail at startup. The address parser rejects hostnames and CIDR prefixes.

## Examples

### Observe a SYN-ACK on a local test interface

This Linux tunnel configuration uses a TUN interface in an isolated test namespace. The passive `BlackHole` consumes the original SYN, so the only SYN-ACK in the trace comes from `SynReply`. Choose an unused subnet in the namespace and load the configuration with permission to create the TUN interface. [TunDevice](../../TunDevice/description.md) · [BlackHole](../../BlackHole/description.md)

```json
{
  "name": "synreply-local",
  "nodes": [
    {
      "name": "tun-in",
      "type": "TunDevice",
      "next": "syn-reply",
      "settings": {
        "device-name": "wwsyn0",
        "device-ip": "192.0.2.1/30",
        "gso": false,
        "route-table": "off"
      }
    },
    {
      "name": "syn-reply",
      "type": "SynReply",
      "next": "sink",
      "settings": { "ttl": 48 }
    },
    {
      "name": "sink",
      "type": "BlackHole",
      "settings": { "mode": "passive" }
    }
  ]
}
```

In the test namespace, check that the route to the peer selects `wwsyn0`, then start a two-packet capture.

```sh
ip route get 192.0.2.2
tcpdump -nnv -i wwsyn0 -c 2 'tcp port 443'
```

In a second shell in the same namespace, make one connection attempt. Use the peer address `.2` because `.1` is assigned to the test host itself.

```sh
python3 -c "import socket; socket.create_connection(('192.0.2.2', 443), timeout=2).close()"
```

For example, if the client uses port `54321`, these are the expected packets.

| Observed at `wwsyn0` | Source | Destination | TCP flags | IPv4 TTL |
| --- | --- | --- | --- | --- |
| Client's original SYN | `192.0.2.1:54321` | `192.0.2.2:443` | SYN | Set by the client |
| SynReply's generated reply | `192.0.2.2:443` | `192.0.2.1:54321` | SYN, ACK | `48` |

The capture of the reply is the success criterion. The sink also consumes the client's subsequent ACK and any application data. In a chain with an actual TCP listener beyond `SynReply`, that listener can send its own response to the forwarded SYN.

## Node metadata

| Property | Value |
| --- | --- |
| `type` | `SynReply` |
| `flags` | `0` (no flags set) |
| `can_have_prev` / `can_have_next` | `true` / `true` |
| `layer_group` | `kNodeLayer3` |
| `layer_group_prev_node` / `layer_group_next_node` | `kNodeLayer3` / `kNodeLayer3` |
| `required_padding_left` | `0` bytes |
| Per-line state | `0` bytes |
| Build option | `INCLUDE_SYN_REPLY`, enabled by default |
