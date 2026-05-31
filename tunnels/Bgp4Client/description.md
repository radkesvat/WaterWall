# Bgp4Client

`Bgp4Client` wraps upstream stream payloads in BGP-like frames and unwraps downstream frames from `Bgp4Server`.

The intended pair is:

```text
TcpListener -> Bgp4Client -> ... -> Bgp4Server -> TcpConnector
```

On the first upstream payload, the client prepends a synthetic BGP OPEN body before the application bytes, then wraps the result with:

```text
16-byte marker | 2-byte body length | 1-byte BGP type | body
```

Later upstream payloads are wrapped with a random non-OPEN BGP type. Downstream payloads are parsed from a `buffer_stream_t`, validated for marker and length, stripped of marker, length, and type, then forwarded toward the previous tunnel.

The body length is encoded in network byte order and covers the BGP type byte plus body bytes, matching the older tunnel's framing contract. `settings.password` is still accepted for configuration compatibility, but the historical implementation did not use it for encryption or authentication.

`Bgp4Client` initializes line state during `UpStreamInit`, forwards `Init` immediately, and destroys local line state before forwarding directional `Finish`. It advertises enough left padding for the largest first OPEN prefix. It is a normal layer-4 stream tunnel, not a packet-line tunnel.
