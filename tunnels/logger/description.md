# LoggerTunnel Node

`LoggerTunnel` is a transparent Waterwall tunnel that observes payload callbacks without modifying data or changing line lifecycle.

It can sit at the beginning, middle, or end of a chain because every callback simply forwards in the correct direction after a null check, and only payload callbacks perform logging side effects.

## What It Does

- forwards upstream lifecycle with `tunnelNext*` when a next tunnel exists
- forwards downstream lifecycle with `tunnelPrev*` when a previous tunnel exists
- logs only during payload callbacks
- never changes payload bytes, line state, padding, or ownership
- supports network-log output, raw file output, and IPv4 TCP-payload extraction to files

## Typical Placement

Because `LoggerTunnel` is a passive observer, it can be placed almost anywhere:

- `TcpListener <--> LoggerTunnel <--> TcpConnector`
- `TunDevice <--> LoggerTunnel <--> IpManipulator`
- `UdpListener <--> LoggerTunnel`

If it is the first or last node in a chain segment, missing `prev` or `next` links are handled by null checks instead of synthetic lifecycle behavior.

## Configuration Example

### Log mode

```json
{
  "name": "trace-http",
  "type": "LoggerTunnel",
  "settings": {
    "mode": "log",
    "level": "info"
  },
  "next": "next-node"
}
```

### Raw file mode

```json
{
  "name": "payload-dump",
  "type": "LoggerTunnel",
  "settings": {
    "mode": "file",
    "output-mode": "split-direction"
  },
  "next": "next-node"
}
```

### IPv4 TCP transport-payload file mode

```json
{
  "name": "tcp-body-dump",
  "type": "LoggerTunnel",
  "settings": {
    "mode": "tcp-payload-file",
    "output-mode": "per-payload"
  },
  "next": "next-node"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen node name. This value is also used as the filename prefix for file output.

- `type` `(string)`
  Must be exactly `"LoggerTunnel"`.

### `settings`

`settings` must be a non-empty object and must include:

- `mode` `(string)`
  One of:
  - `log`
  - `file`
  - `tcp-payload-file`

## Optional `settings` Fields

### `level`

Used only when `mode` is `log`.

Accepted values:

- `debug`
- `info`
- `warning`
- `error`
- `fatal`

Default:

- `debug`

### `output-mode`

Used when `mode` is `file` or `tcp-payload-file`.

Accepted values:

- `per-payload`
- `split-direction`
- `single-file`

Default:

- `split-direction`

## Detailed Behavior

### Lifecycle behavior

All non-payload callbacks are pure pass-through operations:

- upstream `Init`, `Est`, `Finish`, `Pause`, and `Resume` forward to `tunnelNext*` if `t->next != NULL`
- downstream `Init`, `Est`, `Finish`, `Pause`, and `Resume` forward to `tunnelPrev*` if `t->prev != NULL`

`LoggerTunnel` does not create lines, destroy lines, hold extra line references, or add per-line state.

### Payload behavior

Payload logging happens before forwarding in both directions:

- upstream payload is logged first, then forwarded with `tunnelNextUpStreamPayload()` when `t->next != NULL`
- downstream payload is logged first, then forwarded with `tunnelPrevDownStreamPayload()` when `t->prev != NULL`

No payload bytes are rewritten or consumed by the tunnel.

### `log` mode

In `log` mode:

- the tunnel writes one network-log record per payload callback
- the record includes tunnel name, direction, payload length, and a hex rendering of the payload bytes
- the configured `level` controls the logger severity

### `file` mode

In `file` mode:

- the exact `sbuf_t` payload bytes are written to files
- no separators or framing bytes are added
- writes are serialized through tunnel state so multi-worker output stays consistent

#### `per-payload`

Each payload is written to its own file in the current working directory:

- upstream: `<tunnel-name>-up-1.txt`, `<tunnel-name>-up-2.txt`, ...
- downstream: `<tunnel-name>-down-1.txt`, `<tunnel-name>-down-2.txt`, ...

#### `split-direction`

All payloads are appended by direction:

- upstream: `<tunnel-name>-up.txt`
- downstream: `<tunnel-name>-down.txt`

#### `single-file`

All payloads from both directions are appended to:

- `<tunnel-name>-all.txt`

### `tcp-payload-file` mode

In `tcp-payload-file` mode the tunnel inspects each payload buffer and writes only IPv4 TCP transport payload bytes:

- non-IPv4 buffers are ignored
- IPv6 is ignored
- non-TCP IPv4 packets are ignored
- fragmented IPv4 packets are ignored
- packets whose TCP segment has no bytes beyond the IPv4 and TCP headers are ignored
- when a matching IPv4 TCP packet contains transport data, only that transport payload is written

The selected `output-mode` controls filenames exactly like `file` mode.

## Notes And Caveats

- `required_padding_left = 0` because `LoggerTunnel` never prepends bytes.
- File output uses the current working directory.
- File output uses raw bytes even though the filenames end in `.txt`.
- `tcp-payload-file` is intentionally IPv4-only in this implementation.
- Logging failures do not change forwarding behavior; payload is still passed through unchanged.
