# APIServer client example

[`api_client.py`](api_client.py) is a generic Python client for calling registered
WaterWall node operations over TCP. It uses only Python's standard library and
shares its transport module with the [administration CLI](../client/README.md).
Keep both `examples/` and `client/` in their sibling locations when copying the
example. Run it from the WaterWall repository root:

```bash
python3 tunnels/APIServer/examples/api_client.py --help
python3 tunnels/APIServer/examples/api_client.py \
  --host 127.0.0.1 --port 9080 \
  --client operator --token-file /path/to/api-token.txt \
  --config main --node accounts --operation status
```

The client name and token must match an APIServer credential whose allowlist permits
the selected configuration, node, and operation. The token file contains exactly
64 hexadecimal characters, optionally followed by CR, LF or CRLF. Token-file input
is bounded to 66 bytes plus one overflow-detection byte; oversized or non-ASCII
files and empty/missing environment names fail before transport use. You can use
`--token-env VARIABLE_NAME` instead. The default operation body is `{}`; supply
`--body-file request.json` for another body.

The client sends one request and performs no automatic retries. It connects over
TCP; HTTP and reliable UDP require the transport arrangements described below.
A definite pre-send transport failure did not execute a write. Once sending begins,
a malformed reply or post-dispatch error such as `invalid_response` leaves a
mutation's outcome unknown. The client never automatically retries. For uncertain
`create-user`, retain the original ID and inputs and read that ID before deciding
whether to submit again; existence alone does not prove this request created it.
For updates and password changes, reread and explicitly reconsider the write.

The maintained guides and walkthroughs live in **WaterWall-Docs**:

- [API protocol](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/05-devguides/api/protocol.mdx): framing, envelopes, selectors, permissions, and results.
- [Implementing node operations](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/05-devguides/api/node-operations.mdx): registering handlers and their execution contract.
- [Client walkthrough](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/client.mdx): server configuration and a first request.
- [Administration CLI](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/administration-cli.mdx): account commands, explicit edit tokens, pagination and password input.
- [Managing authentication users](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/authentication-users.mdx): reads, creation, account edits, and password changes.
- [API transports](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/03-examples/api/transports.mdx): TCP, HTTP body tunnels, and TcpOverUdp.

This directory holds the executable example; the docs repository links to this
copy. Its regression tests remain in [`tests/api_client_test.py`](../../../tests/api_client_test.py):

```bash
python3 tests/api_client_test.py
```
