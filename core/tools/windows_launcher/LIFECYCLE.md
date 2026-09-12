# Public Windows lifecycle interface

The packed `Waterwall.exe` owns its session. No client Job, service, descendant
inventory, or shared console is required. Use an already elevated compatible
launch identity; the EXE does not perform a second interactive elevation.

## Arguments

Ordinary `-c:PATH` / `--config:PATH`, `-c:stdin`, `WW_CORE_JSON_INPUT`, the default
`core.json`, and `--restricted-config` retain their meanings. The optional
Windows arguments are independent:

| Argument | Meaning |
| --- | --- |
| `--stop-event:DECIMAL` | Wait capability for a fresh manual-reset event. Repeated/early stop is supported. |
| `--ready-event:DECIMAL` | Signal capability for a separate fresh manual-reset event. The inner runtime commits startup before signaling. |
| `--controller-process:DECIMAL` | `SYNCHRONIZE` capability for the exact designated controller process; controller death requests stop. |
| `--console:hidden` | Detach WaterWall from its console; captured pipe output remains usable. |
| `--console:visible` | Detach from a shared console, allocate a separate console when needed, and route stdout/stderr there. Preserve redirected configuration stdin. |
| `--session-file:PATH` | Create a new private recovery record, before any runtime creation. Its parent directory must already protect the identity against unrelated readers and writers. Never reuse a record path. |
| `--recover:PATH` | Standalone operation, with no other arguments: stop the identified session, observe containment, and emit its recovery result. |

Handles use unsigned decimal digits, with no signs or suffixes. Zero, unusable
handles, wrong object types, insufficient access, duplicates, and conflicting
options fail startup. Clients supply distinct event objects and retain their own
handles. An event's manual-reset/fresh state is a client precondition; wait-only
and signal-only capabilities do not confer event-query access. Native object
queries validate types and existing access before duplication; failure to resolve
that OS facility fails closed.

Clients must use an explicit inheritance list. Only wait access is needed for
stop/controller capabilities, and only `EVENT_MODIFY_STATE` for readiness. The
launcher consumes its inherited copies and forwards reduced-access copies plus
private snapshot/completion/effect-inventory capabilities through its own explicit
list. The runtime closes inherited transport handles and retains only the views
and non-inheritable controls it needs. It never receives a Job handle. No access
to terminate, modify, or duplicate handles from the controller is requested.

Without controller binding, exit of the launching client does not request stop.
Readiness is optional and means startup committed, not endpoint reachability,
encryption, or leak protection. A client must also observe termination: readiness
is a milestone and does not promise that a runtime remains alive afterward.
Configuration EOF is independent of stop. No console input consumes configuration
while the inner runtime receives its immutable snapshot.

Without a console argument, preserve launch presentation and standard streams.
Visible mode uses a console separate from any console shared at launch. Supply
configuration through a file or redirected stdin in this mode. It deliberately
sends diagnostics to one WaterWall console instead of
the client's capture pipes. Hidden clients must continuously drain captured
output. Internal DNS helpers use no console. Existing generated Internal, Core,
Network and DNS files retain their independent configuration/redaction behavior.
Console close/Ctrl+C requests the same stop path where Windows allows it; an OS
forced close is handled as abrupt termination. Client firewall policy is never
removed by these operations.

## Containment and deadlines

Before creating any descendant, the public process assigns **itself** to its
private kill-on-close Job, with neither breakaway flag. Descendants inherit that
membership at creation, including a suspended child whose `CreateProcess` has not
returned. There is no create-then-assign child gap. The launcher retains the sole
ordinary Job handle until process termination. Closing it explicitly during normal
cleanup would kill the launcher itself, so it is intentionally process-lifetime
storage. This uses Windows 7 Job inheritance, not Windows 8 nested-Job admission.
An enclosing Job that prevents self-admission is an explicit launch failure;
Windows 7 clients must launch outside such a Job. No client containment fallback
is used. See [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

A process-lifetime observer is armed before configuration reading and extraction.
It observes the designated controller and translates cancellation into the private
stop event. The controller capability also reaches runtime startup checkpoints.
The observer does not use runtime locks, logging, stdin, or output writes.

Budgets are fixed maxima, not per-node timers:

- Startup: 60 seconds from observer admission through runtime readiness.
- Stop, controller loss, or post-runtime launcher cleanup: 15 seconds from the
  first observation, with 25 ms polling. Repeated requests do not extend it.
- Startup expiration initiates stop, giving a total startup ceiling of approximately
  75 seconds under normal OS scheduling.
- Recovery: 15 seconds graceful wait within one 20-second observation budget;
  a separate 25-second recovery-process deadline covers blocked I/O/output.

At expiry the observer terminates its own process without relying on CRT/loader
cleanup. Handle teardown initiates Job termination. Initiation is not completion.
Kernel/driver operations that cannot settle are not reported as completed merely
because a deadline elapsed. The recovery interface returns unverified when it
cannot establish the facts below. Native scheduling, console-close OS deadlines,
and driver behavior still require platform qualification.

## Restart after a crash

Starting a new session does not require a successful historical recovery result.
The launcher never scans old journals or maintains an `unverified` session
blacklist. Use a new protected `--session-file` path for each launch; retain an
old record for diagnostics instead of overwriting it. An optional recovery call
can stop the identified old session, but its exit status is not permission to
start a replacement. New startup checks current resource ownership and reports
current failures through normal startup status and diagnostics.

On Windows, each TunDevice reserves its case-insensitive `device-name` before
egress-interface selection or socket preparation. A SHA-256 digest of the
invariant-uppercase UTF-16 name identifies a machine-wide named-pipe server
instance created with `FILE_FLAG_FIRST_PIPE_INSTANCE`. Its protected ACL permits
administrators and SYSTEM. This is an ownership
handle, with no pipe traffic or background service. The runtime retains it
through device teardown. Each built-in DNS helper inherits only a reduced
duplicate of that handle, so runtime death does not free the device for reuse
while that helper retains ownership. Closing the last handle releases ownership
automatically, including after a crash. Different device names remain independent.
See [Windows pipe creation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).

While holding ownership, startup enumerates present network devices and removes
only the exact WaterWall ownership tag for that name with Wintun hardware
identity, including the empty/missing hardware identity of its creation stub.
The tag is supplied as Wintun's tunnel type during creation and becomes the
device description; it does not depend on a completed journal write or graceful
return. Untagged devices and devices belonging to other names are not reclaimed.
Inactive PnP records are not a prerequisite for startup. Normal adapter creation,
IP assignment, route installation, DNS configuration and readiness follow this
preparation. An already occupied interface alias fails startup instead of being
deliberately reused or renamed. Choose a device name reserved for this application.

Ownership acquisition and stale-device removal each have a five-second retry
budget between OS calls. Creation retries up to three times for selected busy,
sharing, existing-device, or temporarily unavailable-device errors. An individual
blocked driver/PnP call remains subject to the public startup/termination deadline.
Stale-device removal uses the Windows class installer and requires an executable
matching the OS architecture (for example, x64 on x64 Windows). An unsupported
WOW64 removal reports `ERROR_IN_WOW64` with that instruction. A removal that
requires a system restart reports `ERROR_SUCCESS_REBOOT_REQUIRED`; neither is
reported as completed preparation.
In-use ownership, access denial, failed device operations, or failed configuration
can still prevent a connection. These are current resource errors, not a permanent
decision recorded in an old journal. Native qualification of the shipped Wintun
and Windows versions remains required.

These restart guarantees cover built-in operations. Applications relying on them
should use `--restricted-config`; arbitrary scripts or external nodes can change
resources outside this ownership protocol. Client firewall policy retains its
own lifetime and must not be cleared merely because another launch is attempted.

## Completion and recovery

Retain the protected record path, not internal PIDs or executable names. The
record binds a random 128-bit private Job name to the public process's PID and
creation time. Its binary layout is internal; clients invoke `--recover` instead
of parsing or editing it. Recovery requires the same Windows session and an
identity allowed by the original record/object ACLs. Cross-desktop presentation
must still permit console allocation for visible mode. Across Windows sessions,
or with inaccessible/missing/corrupt metadata, report unverified.

Recovery retains a read-only mapped view of the record through settlement, so
its final snapshot sees the same mapped pages used by the runtime's effect
inventory. It does not mix mapped writes with `ReadFile` reads, whose coherence
Windows does not guarantee. Record reads and final identity validation must
succeed before they can authenticate cleanup. See
[Microsoft's mapped-view coherence contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile).

Recovery opens only that private Job and stop event, verifies any matching public
process's creation time, requests stop, and then terminates remaining Job members.
While it holds an extra Job handle it assumes responsibility for this bounded
termination. It checks Job active-process accounting, rather than treating a
successful termination call or wait on a Job as settlement. A missing Job name is not evidence of inactivity: Windows removes a temporary
object's name at last-handle close even while kernel references can remain.
Before finalizing a normal receipt, the public process detaches its console and
records an observed one-member Job barrier. It creates no descendants afterward.
Only that barrier plus proof that the exact public process exited can substitute
for live Job accounting. Otherwise process completion remains unverified. See
[Microsoft object lifetime](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/life-cycle-of-an-object).
No process-name scans are used.

The runtime records adapter-creation intent before calling Wintun and publishes
its actual GUID before returning the created adapter to callers. Recovery checks
only those GUIDs against a successfully queried `GetIfTable2` interface table.
Their absence establishes the network-interface boundary; inactive PnP registry
residue may remain. A GUID-conversion error is not used as proof of removal. Incomplete creation identity remains unverified.
The inventory supports 512 adapter creation attempts per process; overflow refuses
untracked creation. Built-in TUN routes are attached to the owned adapter.
Loop prevention selects the physical interface on participating outbound sockets
through egress pin; it does not install physical-interface host routes.
Recovery never deletes an unrelated adapter, route, driver, file, or firewall rule.

An internal event records a runtime's orderly return; immediate fatal exit and
external termination do not signal it. A record is finalized only after launcher
cleanup. Normal full DWORD runtime status is relayed unchanged by the public EXE.
The public deadline exit status is `0xe0570001`; a blocked recovery exits with
`0xe0570002`. Other startup failures use status 1. An exit code alone is not the
session-completion API: clients requiring verified completion use the record and
`--recover`, including after normal public exit. A nonzero runtime status can still have
settled cleanup when the independent cleanup observations succeed.

Recovery emits one JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `reason` | 0 unspecified; 1 requested stop; 2 controller loss; 3 startup failure; 4 runtime failure; 5 deadline; 6 abrupt/unrecorded termination. |
| `runtime_status` | Full DWORD runtime status when `runtime_status_known` is true. Otherwise the value is diagnostic only and may describe a launcher failure. |
| `runtime_status_known` | Whether a final receipt includes a status actually obtained from the runtime process. False when no runtime ran. |
| `termination` | `orderly`, `abrupt`, or `unverified`, separate from the original reason. |
| `processes_inactive` | Whether the bound containment has been observed inactive. |
| `cleanup` | `settled` when process inactivity and the built-in interface boundary are verified; otherwise `unverified`. Independent of graceful versus abrupt termination and file residue. |
| `cleanup_detail` | The first unmet completion condition, listed below, or `settled`. |
| `file_residue` | Known extraction/driver-file deletion failure, or possible residue after missing launcher finalization or abrupt runtime exit. May be true with settled cleanup. This is not an inventory of shared OS driver installations. |

Recovery exit 0 means settled; exit 2 means incomplete/unverified, including
unreadable metadata (which may prevent a JSON result). A pre-runtime startup
failure or an abrupt runtime exit can have settled cleanup and nonzero status.
An orderly runtime receipt is diagnostic evidence, not a prerequisite for
settlement. Recovery must still authenticate the record, establish process
inactivity, resolve every recorded adapter identity, and observe those adapters
absent from `GetIfTable2`. A driver-file deletion failure is reported as residue
and does not prevent settlement after these checks succeed.

For configurations limited to built-in behavior, settled completion permits
retirement of client-owned session inputs. A new launch can also be attempted
when historical cleanup is unverified; its resource checks determine whether
startup succeeds. Settled completion does not
require deletion of leftover WaterWall extraction directories or shared drivers;
the OS or other instances may still use driver files. Keep client firewall policy
under the application's own connection/security policy. Logs never authenticate
a result. User scripts and external nodes have effects outside this inventory;
applications relying on this built-in completion boundary should launch with
`--restricted-config`, which rejects those extensions.

`cleanup_detail` distinguishes `processes_unverified`, `record_unverified`,
`adapter_identity_unverified`, `adapter_query_failed`, and `adapter_present`.
Process termination and adapter removal may still
be progressing; a later public recovery invocation can observe them again.
Uncertain adapter identities and missing process evidence retain the
recovery limitations below. Clients do not need private process or adapter
identities to interpret these results.
`record_unverified` means the final record refresh could not be read or validated
against the original session identity. It never authenticates a runtime status or
cleanup result, even if live Job accounting separately established process exit.

Creation intent remains published across `CreateProcessW`. If that call fails,
or a child is canceled while still suspended, the launcher clears the intent only
after proving that runtime code never ran and any created child has terminated.
These startup failures can therefore settle without inventing a runtime receipt
or runtime exit status. Failure after resume must still satisfy the process and
interface checks, even when orderly runtime cleanup did not run.

### Application flow

1. Keep the previous session identity. If that session may still be running,
   request stop or invoke `--recover:PATH` with a bounded wait.
2. Record the recovery diagnostic. `settled` permits retirement of client-owned
   session inputs; `unverified`, a timeout, or an unreadable result means retaining
   the old record and uncertain resources. None is a permanent restart veto.
3. Launch the replacement with a fresh journal and the desired configuration.
   WaterWall acquires current ownership, prepares its own stale device if needed,
   and attempts initialization. Wait for readiness or the actual startup failure.
   Report that failure with its diagnostics; use bounded retries for transient
   busy conditions. Do not require old recovery to become `settled` first.
4. Keep crash diagnostics and file cleanup separate from connection state.
   Removing client firewall protection remains an application policy decision;
   a successful new launch does not certify every old resource as retired.

Recovery does not write a substitute launcher receipt into the record. Retain
the successful result with the application's session state until retirement.
If only live Job accounting supplied process evidence, a later invocation after
that Job's name disappears cannot reconstruct the same observation.

### What remains after forced termination

These boundaries apply to the packed Windows executable's built-in runtime and
TUN configuration, excluding user scripts and external nodes. They distinguish
the runtime process, its contained helpers, the Wintun packet session, and the
adapter's operating-system representation. A termination request or public
launcher exit alone does not establish that every boundary has been reached.

| Resource | What termination establishes | What may remain |
| --- | --- | --- |
| Runtime threads, process memory, and socket handles | Windows ends the terminated process's threads, releases its address-space resources, and closes its handles. Its per-socket egress-pin settings end with those sockets. | Other processes and remote peers have their own lifetimes; existing connections and application work are interrupted. |
| Runtime/helper process group | The private Job contains descendants. Last-handle close initiates their termination; recovery can observe inactive Job accounting. | A termination request can still be in progress. A missing Job name alone does not establish completion. |
| Wintun packet session | Wintun's driver handles owner-process exit and device-handle closure, unregistering the session's packet buffers and reporting the adapter disconnected. WaterWall's graceful handlers are not required for this driver teardown. | An inactive adapter/device record can outlive the packet session. Session disconnection is a different observation from adapter removal. |
| Built-in TUN IP, routes, and DNS | WaterWall configures these on its own Wintun interface. Egress pin adds no physical-interface host routes, and built-in DNS setup does not overwrite physical-adapter DNS settings. | Interface configuration and device properties can remain while removal is pending or as inactive residue. Process exit alone is not a measurement of effective system routing or resolver behavior. |
| Extracted runtime, driver files, and OS driver installation | Termination releases the exiting processes' file handles. | Forced exit can skip file deletion. Extracted files, installed/shared drivers, and inactive PnP properties may remain; the OS or other instances may still use driver files. |
| Logs, configuration, session record, and client firewall policy | These have separate owners and retention rules. | Logs, inputs, and the recovery record remain until their owner retires them. Client-owned firewall/Kill Switch policy is not cleared by WaterWall's exit or recovery. |

The process-resource guarantees follow the
[Windows termination contract](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process).
The vendored AMD64 Wintun DLL matches the official 0.14.1 distribution;
[`TunProcessNotification`, `TunDispatchClose`, and `TunUnregisterBuffers`](https://github.com/WireGuard/wintun/blob/0.14.1/driver/wintun.c#L674)
implement packet-session teardown in that driver. This is source and artifact
evidence; native crash qualification remains pending for the supported OS rows.

On the software-device path used by modern Windows, closing the device handle
initiates asynchronous PnP removal. A removed device can retain persisted
properties. Windows 7 uses a separate adapter-creation and orphan-cleanup path;
modern software-device behavior must not be treated as proof of identical removal
timing there. See
[Microsoft's device-removal contract](https://learn.microsoft.com/en-us/windows/win32/api/swdevice/nf-swdevice-swdeviceclose)
and [Wintun's Windows 7 implementation](https://github.com/WireGuard/wintun/blob/0.14.1/api/adapter_win7.h#L239).

The supported claim is automatic process-resource and Wintun packet-session
teardown at their respective lifetime boundaries, with TUN IP/route/DNS operations
scoped to the owned interface. It is not a promise of instantaneous adapter
disappearance, complete disk/registry cleanup, or uninterrupted system networking.
Qualifying an absence of lasting routing/DNS disruption requires native tests
of the shipped artifact during adapter creation, DNS/route setup, operation,
and shutdown on each claimed Windows version.

### What recovery can currently certify

A record with no runtime-creation admission can settle after a bootstrap crash
only if recovery actually observes its Job inactive. A missing Job name does not
supply that observation. The admission bit is published before `CreateProcess`.
After forced runtime termination, recovery can settle when containment is
independently proven inactive and every recorded adapter GUID is absent from
`GetIfTable2`. It reports `termination: "abrupt"` and possible file residue
without requiring a graceful runtime receipt. If the launcher also died before
finalization, this requires recovery to have opened the Job while its name was
still available. A killed launcher with neither accessible Job accounting nor a
final one-member barrier remains unverified, even when the OS has likely already
terminated its children.

An incomplete adapter identity, failed interface query, or present adapter still
leaves `cleanup` unverified. This includes a disconnected adapter: packet-session
disconnection alone does not supply the interface-removal observation. A retained
driver file does not veto independently verified process and interface settlement.

`unverified` means that this completion rule was not satisfied. It does not prove
that the Wintun packet session survived, physical DNS was changed, or active
network damage remains. Recovery requests graceful cleanup if the runtime is
alive; it does not repair arbitrary device state after that runtime has died.
Clients use this result to describe historical completion and decide what can be
retired. It is not a global restart authorization. A new session follows the
ownership and preparation flow above, which can remove its own stale device
while preserving unrelated resources. Recovery continues to require interface
absence for `settled`; startup performs its own current operations. Native
qualification of the shipped artifact remains necessary; a source change or
Wine run does not supply it.

## Permissions and extraction

Both packed and embedded executables retain the administrator manifests and
existing toolchain policies. Temporary extraction requires local ACL-capable
storage, writable by the selected token; canonical ancestors are pinned and
reparse roots refused. Private session-object and extraction-file ACLs admit the current user and SYSTEM
with the token's integrity label. The record parent, inputs, executable bytes,
CWD, TEMP/TMP, and output directories remain the client's responsibility.
Restricted tokens whose restricted SID checks cannot access this private ACL are
unsupported; elevation alone does not imply compatibility. Driver installation,
TUN creation, adapter-scoped DNS and route operations require the corresponding
OS privileges. Denial fails without a hidden second UAC interaction.

The target range is updated Windows 7 SP1 x64 through Windows 11, including
Windows 8/8.1. Actual compiler CRT imports, signing/driver updates, embedded DLL/SYS
variants and desktop/token combinations must be qualified for the exact artifact.
No unrestricted-token or private-desktop compatibility is inferred. Driver and
native OS qualification is recorded separately from the source contract.

## Examples and hosted consumer removal

The supplied `example/core.json` and `example/nodes.json` use only an in-process
TesterClient/BlackHole chain. The client example selects the config directory as
CWD so relative node and log paths resolve there.

Use `client.py independent EXE --config example/core.json` (visible console by
default), or
`client.py attached EXE --config example/core.json --journal PRIVATE/new-session --console hidden`
(and repeat with `visible`). `--exit-controller` exercises exit without explicit
stop. A later `client.py recover EXE --journal PRIVATE/new-session` uses only the
public boundary. The attached example transfers config on stdin and drains
output in bounded chunks with explicit discarded-byte counts. Run it from an
already elevated environment with a protected journal directory.
An independent hidden launch requires `--journal` so a later `recover` command
can stop it. The attached example observes early public exit while waiting for
readiness and invokes recovery after startup/stop errors and interruption as
well as after an ordinary stop.

For a reconnect, pass `--previous-journal PRIVATE/old-session` with the launch
command. The example requests bounded public recovery, reports any incomplete
result as a diagnostic, and continues to new startup. If the requested new
`--journal` path already exists, it selects a unique sibling and prints the actual
path; persist that path as the new session identity. It never overwrites the old
record. Attached-mode success reflects startup/runtime completion rather than
requiring historical cleanup success. The explicit `recover` mode still returns
the recovery exit status.

The former `--hosted`, `--host-stop-event`, and `--host-ready-event` arguments are
removed, without aliases. Consumers must switch to independent lifecycle controls
and WaterWall-owned containment; their former Job-settlement obligations are not
retained under another name. Release publication and downstream adoption require
native qualification of the replacement artifact.
