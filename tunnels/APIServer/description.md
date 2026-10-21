<!--
Documentation version: 6
Sync note: Keep synchronized with WaterWall-Docs/docs/02-noderefs/APIServer.mdx and the Persian node reference.
-->

# APIServer

`APIServer` exposes explicitly registered node operations over a reliable byte
stream. It is a terminal node and opens no socket itself. Access uses independent
static operator credentials and exact per-operation permissions. Target nodes
own their request and result schemas: see
[AuthenticationClient status](../AuthenticationClient/description.md) and the
[AuthenticationServer management API](../AuthenticationServer/description.md#management-api).

## Placement

```text
TcpListener -> APIServer
TcpListener -> HttpServer -> APIServer
UdpListener -> TcpOverUdpServer -> APIServer
```

Direct `UdpListener -> APIServer` is unsupported: API frames require an ordered
reliable stream. The UDP composition requires a matching `TcpOverUdpClient` on
the caller side. See the [transport examples](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/transports.mdx)
for complete compositions and HTTP body handling.

APIServer authenticates callers but provides no transport encryption. Bind local
examples to loopback; remote access requires an authenticated encrypted transport
with peer identity verification. API tokens do not prevent unauthenticated resource
consumption. Restrict endpoint reachability or authenticate peers in the transport;
bounded input allocation does not eliminate connection floods.

## Configuration

This is an APIServer node fragment. Its allowlist assumes an `AuthenticationClient`
named `auth-client` in a loaded configuration whose logical `name` is
`edge-europe`, and an `AuthenticationServer` named `auth-db` in a configuration
named `central`:

```json
{
  "name": "management-api",
  "type": "APIServer",
  "settings": {
    "clients": [
      {
        "name": "monitor",
        "token": "<64 hexadecimal characters representing 32 random bytes>",
        "allow": [
          {"config": "edge-europe", "node": "auth-client", "operations": ["status"]},
          {"config": "central", "node": "auth-db", "operations": ["status", "get-user", "list-users"]}
        ]
      }
    ]
  }
}
```

Replace the token placeholder with a fresh random token, for example from
`python3 -c 'import secrets; print(secrets.token_hex(32))'`. The token is separate
from traffic-user passwords and AuthenticationClient's upstream secret.
Diagnostics remain accessible while AuthenticationClient is offline or rejected.

APIServer clears its owned decoded bodies, request tokens, buffered frame and response bytes,
and configured binary tokens before releasing them. Consumed or discarded input bytes are cleared
before their buffers return to the pool. Complete parsed JSON trees are cleared on both acceptance
and later validation refusal. Detached API jobs clear their owned request/response copies at final
release, including cancellation; returned handler response bytes are cleared before pool reuse.
This does not clear startup configuration trees, parser-internal partial trees from syntax errors,
request buffers transferred to handlers, buffers already transferred to neighboring nodes, OS copies,
or every copy in the process. Handlers remain responsible for the request buffers they consume.

`clients` must be nonempty. Client names and decoded 32-byte tokens must be
unique. Every `allow` entry names one exact logical configuration, public
top-level node and nonempty operation list; wildcard permissions are unsupported.
Startup preparation rejects missing targets or unregistered operations. Runtime
requests without the exact permission return `forbidden`; admitted requests reuse
the immutable descriptor resolved during preparation. An
existing `TunnelApi` symbol does not automatically expose an external operation.
Each write needs its own explicit operation permission; read, edit, create and
password-administration permissions do not imply one another.

Whenever an APIServer is configured, every loaded configuration needs a nonempty
unique logical `name`. Selectors never name files or load another configuration.
Configuration/node labels are case-sensitive and bounded to 256 UTF-8 bytes.
Generated internal child nodes are private. A node-only selector works only when
its name is unique across all declared top-level nodes, before filtering by
registration or permissions. Use qualified selectors when names may repeat.

## Optional Limits

All fields below are positive finite integers. Startup rejects inconsistent geometry that cannot accommodate a bounded request and response. Byte budgets include allocator charge and temporary copies where applicable; envelope limits exclude their four-byte prefixes.

| Setting | Default | Meaning |
| --- | --- | --- |
| `max_request_envelope` | 1048576 | Request JSON envelope bytes. |
| `max_response_envelope` | 1048576 | Encoded response JSON envelope bytes. |
| `max_input_bytes` | 2097152 | Hard input-byte limit per line, including queued requests and incomplete input. |
| `max_line_memory` | 8388608 | Retained allocation charge per line. |
| `max_input_fragments` | 256 | Input fragment/FIFO entries per line. |
| `max_queued_requests` | 8 | Waiting complete requests, in addition to one active request. |
| `max_sessions` | 256 | Live sessions per instance. |
| `max_jobs` | 64 | Admitted unfinished jobs per instance. |
| `handler_working_memory` | 8388608 | Reserved temporary allowance for each handler. |
| `max_memory` | 67108864 | Aggregate retained memory and working reservations per instance. |
| `frame_timeout_ms` | 15000 | Absolute frame assembly deadline from first-fragment arrival, including queue residence. |
| `request_timeout_ms` | 10000 | Complete-request admission through response publication, including FIFO and worker wait. |
| `output_timeout_ms` | 15000 | Response publication through transport handoff, including paused time. |
| `idle_timeout_ms` | 60000 | Idle connection with no frame, request or output in progress. |

A length header records the declared envelope size without allocating its body.
Frame storage grows geometrically for received bytes; reservations cover both old
and new capacities during copying. Parsing separately accounts for the assembled
frame, JSON tree and decoded body, alongside input carriers, output and detached
jobs. Teardown releases actual allocated capacity.

Byte-pressure watermarks exclude only the header and body bytes already copied
into the current incomplete frame: `input_bytes - (header_size + frame_used)`.
Those bytes still count toward the hard input limit. Queued complete requests,
raw backlog and fragment/entry limits continue to exert pressure. Bounded parser
continuations Resume the source when only incomplete input remains, so a permitted
large request can finish even when its size exceeds the high watermark.

Working memory must accommodate the actual worker-pool allocation for a 4096-byte result plus 8192 bytes of parsing metadata. A smaller encoded response cap can still return a bounded `response_too_large` error for a valid result.

Runtime JSON parsing keeps strict UTF-8, NUL, duplicate-key, depth/value and
complete-input checks without configuration-parser stderr diagnostics. Host
configuration/startup parsing retains its diagnostics. Invalid UTF-8 or NUL from
a UTF-8 handler returns `invalid_response` with no result body; a valid oversized
encoded result returns `response_too_large`. Both are post-dispatch errors, so a
write may have committed. Base64 operations may return arbitrary bytes.

Zero does not disable a protection. Trickle input does not reset frame assembly time. Gateway `timeout` and `invalid_encoding` errors close the connection. The request deadline ends when a complete response is published; delivery then has its separate output deadline. Disconnect and timeout abandon execution but retain job reservations until queued cancellation or a running bounded handler actually settles.

## Protocol And Examples

The runnable client and source-checkout instructions live in [examples/README.md](examples/README.md).

Requests and responses use a four-byte big-endian length followed by a UTF-8 JSON
envelope. The envelope identifies the caller, target and operation and carries an
opaque node body. APIServer checks authentication, exact permissions and operation
metadata; the target parses its body. Request IDs correlate replies and do not
make writes idempotent. See the [API protocol guide](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/05-devguides/api/protocol.mdx)
for the complete framing, envelope, error and delivery contract.

- [Run the API client](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/client.mdx): a complete loopback setup,
  token files and the generic Python client.
- [Manage authentication accounts](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/authentication-users.mdx):
  read/list, create, edit/disable and password workflows with explicit recovery
  after uncertain replies.
- [API transports](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/transports.mdx): direct TCP, HTTP/1.1 body
  framing and reliable streams over UDP.
- [Register a node operation](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/05-devguides/api/node-operations.mdx): the
  implementation contract for exposing another node through this gateway.

Operation schemas remain in their owning node references. A lost write reply can
follow a successful in-memory commit; consult that operation's recovery rules
before deciding whether to submit another request.

## Lifecycle And Metadata

APIServer borrows every accepted normal line and never calls `lineDestroy()`. It initializes session state before establishing the previous side and produces replies downstream. One operation executes at a time per connection; admitted pipelined requests wait in FIFO order. Output Pause/Resume controls its reply producer while hard budgets and deadlines remain active. Detached cross-worker jobs carry session/request tokens; only the connection's worker resolves a live session and accesses its line. Shutdown closes global API admission before target quiescence, and actual line owners drain accepted lines before final registry destruction.

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagChainEnd`, `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `false` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayerNone` |
| `required_padding_left` | `0` bytes |
