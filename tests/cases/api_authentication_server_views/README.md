# api_authentication_server_views

Topology: `TcpListener -> APIServer` queries a separate `AuthenticationServer`;
a second private loopback `TcpListener -> AuthenticationServer` supplies real
`Authenticate`, `UpdateUser` and `PushUserStats` setup transactions. No
AuthenticationClient is required. Two event workers are active.

The probe checks exact status/detail/summary schemas, credential omission, IDs
above 2^53 and UINT64_MAX, complete multi-page traversal, status-only token
permissions, a cursor that remains usable after a usage batch and exact replay,
and a stale cursor after an accepted configuration edit. Reads must leave save
history unattempted; the existing periodic save is set to 60 seconds, beyond the
30-second probe deadline. Authentication protocol ACKs retain their existing
server-memory meaning.

Run through `waterwall.api_authentication_server_views` with the normal namespace
harness. It requires Linux network-namespace privileges and uses only loopback.
All credentials are deliberate public fixture values. The shared case runner
copies the database before startup and removes its private runtime files.
