<!--
Documentation version: 4
Sync note: Keep synchronized with tunnels/APIServer/description.md and the Persian node reference.
-->

# APIServer

`APIServer` exposes explicitly registered node operations over a reliable byte stream. It is a terminal node and opens no socket itself. Registered read-only operations include `AuthenticationClient.status` and `AuthenticationServer.status`, `get-user` and `list-users`; `AuthenticationServer.update-user` is a conditional write and `create-user` creates a fresh account; both require their own explicit permissions. Access uses independent static operator credentials and exact per-operation permissions.

## Placement

```text
TcpListener -> APIServer
TcpListener -> HttpServer -> APIServer
UdpListener -> TcpOverUdpServer -> APIServer
```

Direct `UdpListener -> APIServer` is unsupported: API frames require an ordered reliable stream. For a TCP caller using the reliable UDP transport, use the existing nodes on both sides:

```text
TCP caller -> TcpListener -> TcpOverUdpClient -> UdpConnector
                                      loopback/protected UDP
                            UdpListener -> TcpOverUdpServer -> APIServer
```

APIServer authenticates callers but provides no transport encryption. Bind examples to loopback; remote access requires an appropriately protected stream.

## Configuration

This example belongs to a configuration whose top-level logical `name` is `edge-europe`, with an `AuthenticationClient` named `auth-client` defined in that configuration and an `AuthenticationServer` named `auth-db` in a loaded configuration named `central`:

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
      },
      {
        "name": "editor",
        "token": "<different 64 hexadecimal characters representing 32 random bytes>",
        "allow": [
          {"config": "central", "node": "auth-db", "operations": ["get-user", "update-user"]}
        ]
      },
      {
        "name": "creator",
        "token": "<another distinct 64 hexadecimal characters representing 32 random bytes>",
        "allow": [
          {"config": "central", "node": "auth-db", "operations": ["get-user", "create-user"]}
        ]
      }
    ]
  }
}
```

Replace the placeholder with a fresh random token, for example from `python3 -c 'import secrets; print(secrets.token_hex(32))'`. The token is separate from traffic-user passwords and AuthenticationClient's upstream secret. Diagnostics remain accessible while AuthenticationClient is offline or rejected.

`clients` must be nonempty. Client names and decoded 32-byte tokens must be unique. Every `allow` entry names one exact logical configuration, public top-level node and nonempty operation list; wildcard permissions are unsupported. Startup preparation rejects references to missing targets or unregistered operations. An existing `TunnelApi` symbol does not automatically expose an external operation.

Whenever an APIServer is configured, every loaded configuration needs a nonempty unique logical `name`. Selectors never name files or load another configuration. Configuration/node labels are case-sensitive and bounded to 256 UTF-8 bytes. Generated internal child nodes are private.

## Optional Limits

All fields below are positive finite integers. Startup rejects inconsistent geometry that cannot accommodate a bounded request and response. Byte budgets include allocator charge and temporary copies where applicable; envelope limits exclude their four-byte prefixes.

| Setting | Default | Meaning |
| --- | --- | --- |
| `max_request_envelope` | 1048576 | Request JSON envelope bytes. |
| `max_response_envelope` | 1048576 | Encoded response JSON envelope bytes. |
| `max_input_bytes` | 2097152 | Retained queued input payload per line. |
| `max_line_memory` | 8388608 | Retained allocation charge per line. |
| `max_input_fragments` | 256 | Input fragment/FIFO entries per line. |
| `max_queued_requests` | 8 | Waiting complete requests, in addition to one active request. |
| `max_sessions` | 256 | Live sessions per instance. |
| `max_jobs` | 64 | Admitted unfinished jobs per instance. |
| `handler_working_memory` | 8388608 | Reserved temporary allowance for each handler. |
| `max_memory` | 67108864 | Aggregate retained memory and working reservations per instance. |
| `frame_timeout_ms` | 15000 | Absolute frame assembly deadline from the first byte. |
| `request_timeout_ms` | 10000 | Complete-request admission through response publication, including FIFO and worker wait. |
| `output_timeout_ms` | 15000 | Response publication through transport handoff, including paused time. |
| `idle_timeout_ms` | 60000 | Idle connection with no frame, request or output in progress. |

Working memory must accommodate the actual worker-pool allocation for a 4096-byte result plus 8192 bytes of parsing metadata. A smaller encoded response cap can still return a bounded `response_too_large` error for a valid result.

Zero does not disable a protection. Trickle input does not reset frame assembly time. The request deadline ends when a complete response is published; delivery then has its separate output deadline. Disconnect and timeout abandon execution but retain job reservations until queued cancellation or a running bounded handler actually settles.

## Wire Format

Each request and response consists of a four-byte unsigned big-endian length followed by exactly that many UTF-8 JSON bytes. Length excludes the prefix. There is no newline or terminating NUL. A transport callback, HTTP chunk or UDP packet is not an API message boundary. Prefixes and bodies may be split; several frames may share a read.

Request:

```json
{
  "id": "request-42",
  "auth": {"client": "monitor", "token": "<configured token>"},
  "selector": {"config": "edge-europe", "node": "auth-client"},
  "operation": "status",
  "content_type": "application/json",
  "body_encoding": "utf8",
  "body": "{\"include_accounting\":true}"
}
```

All shown fields are required except `selector.config`. Omission of the configuration works only if the exact node name occurs once across **all declared top-level nodes in all loaded configurations**. Ambiguity is determined before registration or permissions; an allowlist cannot make an ambiguous name unique. Authentication occurs before target lookup, and authorization applies to the resolved exact target and operation.

`id` is a nonempty correlation string of at most 64 UTF-8 bytes. It provides no deduplication or execution checkpoint. Operations are bounded to 64 bytes and content types to 128 bytes. `content_type` must match the registered operation. The outer parser rejects unknown/duplicate keys, wrong types, trailing input, malformed UTF-8, and decoded NUL in metadata or UTF-8 bodies.

`body` is always a JSON string. With `body_encoding: "utf8"`, its decoded UTF-8 bytes are delivered unchanged. With `"base64"`, strict canonical base64 represents arbitrary bytes, including NUL. The gateway does not parse or normalize the node's body. The selected handler owns its command schema; `AuthenticationClient.status` accepts `{}` or `{"include_accounting":true}`.

Successful dispatch, including a node-level error, returns:

```json
{
  "id": "request-42",
  "error": null,
  "result": {
    "code": 0,
    "content_type": "application/json",
    "body_encoding": "utf8",
    "body": "{\"can_authenticate\":true}"
  }
}
```

The `body` above is illustrative; see [AuthenticationClient](AuthenticationClient.mdx) for its status snapshot and [AuthenticationServer](AuthenticationServer.mdx#management-api) for server reads, conditional edits and account creation. Server `status` takes exactly `{}`, `get-user` takes `{"id":"42"}`, and `list-users` takes `{}` or `{"limit":50,"cursor":"<returned opaque cursor>"}`. Unsigned 64-bit values use decimal JSON strings. Every server read includes an opaque `edit_token`; `update-user` requires it as `if_match`. `create-user` takes a caller-supplied nonzero decimal-string `id`, nonempty `password` and optional `config`, without an edit-token precondition. Creation permission is independent of update permission. Server configuration changes invalidate both old edit tokens and list cursors; statistics-only changes allow continuation with newer totals. `result.code` preserves the node handler's success/error meaning. An empty handler result is an empty body with its declared content type and encoding.

A gateway failure returns `result: null`:

```json
{
  "id": "request-42",
  "error": {"code": "ambiguous_target", "message": "Specify the configuration name."},
  "result": null
}
```

The ID is null when no trustworthy bounded ID was recovered. Gateway codes include `invalid_request`, `invalid_encoding`, `unauthorized`, `forbidden`, `target_not_found`, `ambiguous_target`, `unsupported_api`, `unsupported_operation`, `unsupported_content_type`, `busy`, `timeout`, `shutting_down` and `response_too_large`. Messages are fixed and bounded. Unknown clients and wrong tokens share `unauthorized`.

Malformed framing/schema and invalid authentication close the connection after at most one bounded error. Valid authorized target/operation/body errors may continue in FIFO order. Work and output are bounded; refusal may close directly if even an error cannot fit. Once output begins, transport failure or expiry closes the connection without injecting another frame into the partial response. A later queued request expiring behind an earlier pending response closes the line without returning its error out of order.

## HTTP Body Tunnel

Use ordinary HTTP/1.1 single mode for this composition:

```json
{
  "name": "http-body",
  "type": "HttpServer",
  "settings": {
    "http-version": "1.1",
    "http1-mode": "single",
    "upgrade": false,
    "path": "/management",
    "method": "POST"
  },
  "next": "management-api"
}
```

Send framed API bytes in the HTTP request body with Content-Length or valid chunked encoding. Dechunk the HTTP response body before reading API prefixes. A complete API reply is recognizable by its length; do not wait for HTTP EOF or the terminating response chunk. HttpServer's configured method/path select its body tunnel, and APIServer receives body bytes only. API credentials remain in each JSON envelope. This interface does not expose REST request objects, header authentication or per-operation HTTP status codes.

## External Client

The repository's `examples/api_client.py` uses only Python's standard library. Read a token from an environment variable or file; never put it in a command-line argument:

```bash
export WATERWALL_API_TOKEN="$(cat /private/path/operator-token)"
python3 examples/api_client.py --host 127.0.0.1 --port 9080 \
  --client monitor --token-env WATERWALL_API_TOKEN \
  --config edge-europe --node auth-client
```

Alternatively pass `--token-file /private/path/operator-token`. The default opaque status body is `{}`; `--body-file` preserves file bytes, and `--body-encoding base64` supports binary operations. The client validates response length and ID, reads complete frames, and writes the decoded result body to stdout. It makes one attempt and performs no automatic retry. Through TcpOverUdp, point this TCP client at the local TcpListener shown above.

To inspect the authoritative account database, target its server explicitly:

```bash
python3 examples/api_client.py --host 127.0.0.1 --port 9080 \
  --client monitor --token-env WATERWALL_API_TOKEN \
  --config central --node auth-db --operation status
```

For `get-user`, put `{"id":"9007199254740993"}` in a UTF-8 body file and pass
`--operation get-user --body-file /private/path/query.json`. For a first list page,
use `{"limit":50}` with `--operation list-users`; subsequent body files include
the returned opaque `cursor`. A `stale_cursor` node error requires a new traversal
without a cursor. `busy` is a bounded sampling refusal. The example client makes
no automatic retries; callers decide when to repeat reads or restart traversal.

For a conditional edit, use a separately configured editor token with exactly
`get-user` and `update-user` permissions. Keep monitoring tokens read-only. Prepare
`lookup.json` containing `{"id":"42"}`, then read the account once:

```bash
python3 examples/api_client.py --host 127.0.0.1 --port 9080 \
  --client editor --token-file /private/path/editor-token \
  --config central --node auth-db --operation get-user \
  --body-file lookup.json > account.json
```

Review that account and create only the intended sparse patch using the sampled
token; do not copy the complete user object into `patch`:

```python
import json
from pathlib import Path

account = json.loads(Path("account.json").read_text(encoding="utf-8"))
request = {"id": account["user"]["id"], "if_match": account["edit_token"],
           "patch": {"enabled": False}}
Path("update.json").write_text(json.dumps(request), encoding="utf-8")
```

Submit it once:

```bash
python3 examples/api_client.py --host 127.0.0.1 --port 9080 \
  --client editor --token-file /private/path/editor-token \
  --config central --node auth-db --operation update-user \
  --body-file update.json
```

A success body contains exactly `id`, the committed `config_revision` and its
`edit_token`. It acknowledges server memory; periodic saving and ordinary client
refresh remain separate. A node `conflict` means no edit committed: reread and
reconsider the intended change. A lost reply, disconnect or gateway timeout can
follow commitment and leaves the outcome unknown. Reread the account before
choosing another patch, comparing normalized values where appropriate. Never
automatically obtain a fresh token and replay the old patch. The example client
prints conflict/outcome guidance and makes no automatic write retries; request
IDs do not deduplicate mutations.

To provision an account, separately allow `create-user` and usually `get-user`
for a creator. Store the request in a private UTF-8 file `create.json`:

```json
{"id":"43","password":"example-only-secret","config":{"name":"alice","enabled":false}}
```

The caller supplies a permanent unique numeric ID and the initial password; no
edit token is required. An omitted or empty `config` creates an enabled account
with zero unlimited/unset policy limits and expiry, so send `enabled:false` for
staging. Send the private body through the existing generic client once:

```bash
python3 examples/api_client.py --host 127.0.0.1 --port 9080 \
  --client creator --token-file /private/path/creator-token \
  --config central --node auth-db --operation create-user \
  --body-file /private/path/create.json
```

The compact success body contains `id`, committed `config_revision` and
`edit_token`, and acknowledges server memory only. Periodic/final persistence and
client synchronization continue separately. An existing ID returns `id_exists`
without replacement or a successful replay. A returned node-operation failure
publishes no account; a lost reply or post-dispatch gateway timeout leaves the
outcome unknown. Retain the original ID and inputs, then use `get-user` for that
ID. Public configuration confirms existence, but cannot prove who created it or
that its redacted password matches. If absent, explicitly decide whether to
retry the same ID and inputs while the original may still run. Never choose a
new ID automatically, overwrite an account, reset its credentials or treat
`id_exists` as proof of your earlier success. The generic client does not retry;
outer request IDs only correlate replies. Producer credentials and
`allow-user-write` grant no gateway creation permission.

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
