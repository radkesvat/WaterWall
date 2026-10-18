# AuthenticationServer administrative audit

`waterwall.api_authentication_audit` uses the ordinary private namespace probe
runner with two event workers. It exercises actual API create/edit/password
commits, conflict and malformed-input refusals, producer AddNewUser/UpdateUser
success and failure, and a committed edit whose reply is discarded. Read-only
status polling waits for the bounded background writer, then checks the JSONL
record schema, exact actor/gateway identity, sequence and revision order, and
omission of passwords, tokens and field values. No mutation is retried.

Run after the production build:

```bash
ctest --test-dir build/linux -C Release --output-on-failure -R '^waterwall\.api_authentication_audit$'
```

The fixture is copied into a private directory; its audit files and database are
removed with that directory. Native audit tests separately cover shutdown drain,
startup failures and file failures/rotation. This case does not claim crash
recovery, guaranteed delivery, or durable storage after a power loss.
