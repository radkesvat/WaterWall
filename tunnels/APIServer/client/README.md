# WaterWall administration client

`ww_admin.py` manages AuthenticationServer accounts through APIServer. It uses
Python 3.10 or newer and only the standard library; no installation or third-party
packages are needed. Keep this directory's Python files together when copying it.
`ww_api.py` owns the shared TCP framing and envelope validation.

From the WaterWall repository root:

```bash
python3 tunnels/APIServer/client/ww_admin.py --help
python3 tunnels/APIServer/client/ww_admin.py \
  --client monitor --token-file /path/to/monitor-token \
  --config central --node auth-db status
```

Connection options go **before** the command. The defaults are
`--host 127.0.0.1 --port 9080 --timeout 10 --max-response-bytes 1048576`.
The response cap can be set from 1 byte through 64 MiB. The timeout is one budget
per request; Python's blocking hostname lookup can exceed it before the client
regains control. Use an IP address when that resolver limitation is unsuitable.
`--client`, `--node`, and one of `--token-file PATH` or `--token-env NAME` are
required. `--config` is the logical configuration name; omitting it requires a
globally unique node name. The client connects over TCP. APIServer must be reached
through an appropriately protected transport for remote use; it does not encrypt
the API token. HTTP and raw UDP are not implemented by this client. An existing
TcpOverUdp bridge can expose a local TCP entry point.

## Commands

Append one of these commands after the connection options:

| Command | Behavior |
| --- | --- |
| `status` | Read the AuthenticationServer status. |
| `users get 42` | Read account details and a current edit token. |
| `users list --limit 50` | Read one compact summary page. |
| `users list --all --limit 50 --max-pages 100` | Follow cursors and print one complete page per JSON line. |
| `users create 42 --set name=alice --set enabled=false` | Create the caller-selected ID and prompt twice for its initial password. |
| `users update 42 --if-match TOKEN --set limit.traffic.total=1000000000` | Apply only the selected configuration fields. |
| `users enable 42 --if-match TOKEN` | Set `enabled` to true. |
| `users disable 42 --if-match TOKEN` | Set `enabled` to false. |
| `users change-password 42 --if-match TOKEN` | Prompt twice for a replacement password. |

The API token needs the exact operation permission for each command. Enable and
disable use `update-user`; permission to read users does not grant write access.

`--set` is repeatable and uses the public API's dotted field names, such as
`time.expire_at_ms`, `limit.traffic.total`, `wireguard_allowed_ips`, and `enabled`.
Numeric policy values are canonical decimal strings; booleans are `true` or
`false`. String values are literal: `--set notes=` clears notes and
`--set wireguard_allowed_ips=10.44.0.1/32` supplies a CIDR string. Unknown or
repeated fields are rejected. See the
[configuration field reference](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/02-noderefs/AuthenticationServer.mdx#update-user)
for all fields, units and limits. Creation without `--set` uses the server's
enabled, unlimited/unset defaults; use `--set enabled=false` to stage an account.

## Passwords, edits and incomplete requests

Creation and password changes use a hidden interactive prompt by default. For
automation, use either `--password-file PATH` or `--password-stdin`. These inputs
are exact UTF-8 bytes: **a final newline is part of the password**. Passwords are
never accepted as command-line values. Do not use `echo` to prepare a password
unless its added newline is intended. Token files instead contain exactly 64
hexadecimal characters, optionally followed by LF or CRLF.

Read an account, review its state, then pass the returned 48-character edit token
to `--if-match`. Edits to any account or a server restart can invalidate it. The
CLI does not obtain a fresh token or retry a write automatically. Account creation
uses uniqueness checks and needs no edit token.

An uncertain write may already have committed. Read the account and explicitly
decide what to do next. A public read cannot confirm which password is installed.
For a password change, explicit resubmission of the desired password with a fresh
token establishes that password only if that new request succeeds. For creation,
keep the original ID; finding it does not prove that this request created it or
that its password matches. A successful write acknowledges an in-memory change,
not a disk save or an AuthenticationClient refresh.

## Output and exit status

Successful commands write JSON to stdout. `users list --all` writes each complete
page as one JSON line as it arrives, without accumulating every account. Its
default cap is 100 pages; `--max-pages` accepts 1 through 10000. A stale/repeated cursor,
cap, or failed later page stops traversal with a nonzero exit status; already
written pages are an incomplete result. Ordinary single-page listing accepts
`--cursor` to continue explicitly. The list is not a frozen usage snapshot.

Errors and recovery guidance go to stderr without printing supplied secrets or
arbitrary server error messages. Check the exit status before treating output as
complete:

| Exit | Meaning |
| --- | --- |
| `0` | Success; an `--all` traversal reached its final page. |
| `1` | The node returned a validated operation failure, such as `conflict`. |
| `2` | Invalid local input, a failed read, a definite gateway refusal, or a local pagination bound/consistency failure. |
| `3` | A write's outcome is uncertain; explicitly reconcile before another write. |

The [administration walkthrough](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/administration-cli.mdx)
has complete commands using the documented demo roles. The
[generic example](../examples/README.md) can invoke other registered operations
and uses the same transport module. Focused tests stay under `tests/` and run
from the repository root:

```bash
python3 tests/api_admin_test.py
python3 tests/api_transport_test.py
python3 tests/api_client_test.py
```

The namespace integration case `waterwall.api_admin_cli` runs the real CLI against
WaterWall; its setup and execution commands live in
[`tests/cases/api_admin_cli/README.md`](../../../tests/cases/api_admin_cli/README.md).
