# Administration CLI against AuthenticationServer

`waterwall.api_admin_cli` runs the actual Python administration program as a child
process against `TcpListener -> APIServer` and a real AuthenticationServer inside
the existing private network namespace. Fixture tokens/passwords are public test
values. Only startup connection readiness is retried; submitted operations are
never retried.

The probe covers status, exact large IDs, creation from stdin, sparse updates,
disable/enable, password input from a file, paginated JSON-lines traversal,
conflict and uniqueness refusals, and operation permissions. It checks that
stdout/stderr expose no credentials. Deterministic support tests separately
cover lost replies, invalid input/responses and pagination termination.
