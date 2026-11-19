# TesterClient through a sniffing Router

Runs `TesterClient -> Router -> TesterServer` with one worker and three chunks
in each direction. The Router inspects the first request bytes for TLS before
initializing its default branch. The request uses the tester's plain byte pattern,
so the Router forwards it to TesterServer after sniffing.

The case uses no sockets and runs inside the functional lane's network namespace.
Success requires the tester's response verification marker and a successful runner
verdict within ten seconds. Run
`ctest --preset linux --output-on-failure -R '^waterwall\.tester_client_router_sniffing_direct$'`.
