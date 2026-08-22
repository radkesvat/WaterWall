# AGENTS.md — WaterWall

Operating manual for AI coding agents (and new contributors) working on
**WaterWall**, a modular, chain-based tunneling runtime written in C.

This file is the field manual: the rules you must follow, the commands you must
run, and where to look. For the full reasoning behind every rule, read the
seven-part **Developer Guide** in `WaterWall-Docs/docs/05-devguides/` (linked at the
[end of this file](#deep-dive-index)). When this file and the guide disagree, the
**source code in `ww/net/` wins** — it owns every contract.

---

## 0. TL;DR — Read This First

WaterWall composes **tunnel instances** into an ordered **chain**:

```text
TcpListener -> ObfuscatorClient -> TlsClient -> TcpConnector
  (adapter)       (middle)         (middle)      (adapter)
```

A correct tunnel is never "just" a parser or encoder. It must preserve callback
**direction**, line **lifetime**, per-line **state**, buffer **padding**,
**packet-line** semantics, and **composability** with any neighbors.

### The golden rules (non-negotiable)

1. **Do not invent a new lifecycle model.** Copy the closest mature tunnel. In
   this codebase, correctness comes from matching the existing pattern.
2. **Read the contract source before editing:** `ww/net/tunnel.h`,
   `ww/net/line.h`, `ww/net/chain.c`, and the tunnel you are changing plus its
   neighbors.
3. **Initialize per-line state in `Init`.** Later callbacks may assume it exists.
   **Do not** add an `initialized` flag to paper over unsafe control flow.
4. **Direction is sacred:** forward upstream with `tunnelNextUpStream*`, downstream
   with `tunnelPrevDownStream*`. Never reverse them. Paired client/server tunnels
   often transform in *opposite* directions.
5. **Inter-tunnel callbacks can destroy the line before they return.** After one,
   the line and your line-state may be dead. Protect with `withLineLocked()` or a
   manual `lineLock` + `lineIsAlive()` check if you need to continue.
6. **`Finish` is the one non-re-entrant callback.** When you *receive* `Finish`
   from a side, you are guaranteed not to be called back on that side — so you must
   send **nothing** back toward it (no `Payload`/`Est`/`Pause`/`Resume`/`Finish`).
   Destroy local state first, then propagate. Most tunnels need **no**
   `prev_finished`/`next_finished` flag — add directional-close state *only* if you
   must send final bytes before closing.
7. **Only the tunnel that created a line may call `lineDestroy()`.**
8. **An owner's `Finish` must leave its own normal line dead.** When you receive
   `Finish` for a normal line *you* created, the handler may not return while the
   line is still logically alive: `assert(! lineIsAlive(line))` must hold at
   `return`. Detach producers, destroy your line state, propagate away from the
   sender, then `lineDestroy()`. Outstanding `lineLock()` references may still
   delay the physical free — that is fine, logical death is what the contract
   requires.
9. **`requestProgramShutdown()` is not line destruction.** A terminal failure in
   an owner's `Finish` still has to close its own line before returning; worker 0
   tears the process down long after this callback unwinds.
10. **Prepend only within your advertised `required_padding_left`.**
11. **Never destroy a packet line at runtime; never treat it as per-connection.**
    A packet line belongs to the chain, so rule 8 does not apply to it and only
    `tunnelchainDestroy()` may release it. Classify `Finish` by the exact handler
    role and direction: a packet-lifecycle anchor for which close is impossible
    must `LOGF` + `abortProgramNow(1)`; a transparent middle transform forwards
    it in the same direction; an intentional terminal absorber documents why
    there is nothing to forward or release. `PacketSender` downstream and
    `PacketReceiver` are absorbers, not fatal anchors. Never `lineDestroy()` in
    any category.
12. **Validate through the CMake preset**, not hand-rolled compiler commands.
    Start with the cheapest relevant check and prefer existing focused tests for
    the files, tunnel, and behavior changed. Do not create or update a test merely
    because a file changed; add coverage only when it provides meaningful regression
    protection for new or changed behavior. On Linux, deterministic integration
    tests run in private user + network namespaces with loopback-only isolation
    via `tests/run_in_network_namespace.sh`; the functional lane normally finishes
    in about 20–30 seconds on the 4-CPU reference host with 16 CTest jobs (~71s on 1 CPU).
    The serial support lane (13 production policy/harness tests) takes about 55
    seconds, the external lane takes about one second, the serial speed lane takes
    about 45–50 seconds, and the privileged lane takes about 15 seconds. The ordinary
    non-privileged production sequence (`all` lane: support + functional + external + speed,
    170 tests total) finishes in roughly 2 minutes (~127s). Deterministic cases must
    not use public DNS or depend on host-network port availability. Use the full functional
    lane freely for shared tunnel/network behavior or changes spanning several cases,
    and all integration lanes for broad tunnel or harness work. Complete production
    plus native-unit validation (a median ~74s across three warm
    `linux-unit-release` runs) now takes about 3.5 minutes including the privileged
    lane rather than 30 minutes or more; prefer it for shared-core,
    lifecycle/concurrency, multi-subsystem, or uncertain-scope changes, not only for
    releases. Timings are planning values and vary with hardware and build warmth.
13. **Worker identity is explicit (`WID`) and invalid by default (`kInvalidWID`).**
    WID represents a registered worker slot index (`0 .. WORKERS_COUNT - 1`), not
    an OS thread ID (`getTID()`). Unregistered threads (device reader/writer
    threads, helper threads, plain pthreads) observe `getWID() == kInvalidWID`. Never
    index worker-owned arrays without checking identity predicates
    (`currentThreadIsEventWorker()`, `workerWIDIsRegistered(wid)`). Auxiliary threads
    must post work to an event worker loop and must never borrow a worker-local pool.
14. **Use the narrowest worker-context helper; never compare or index with a raw
    `getWID()`.** Prefer, in this order: the line you were given
    (`lineIsOnCurrentEventWorker()`, `lineGetBufferPool()`, `lineReuseBuffer()`),
    the `worker_t *` a worker message handed you (`worker->wid`), the loop the
    event came from (`getLoopEventWorkerWID()`), then the checked current-worker
    accessors (`getCurrentEventWorker*()`). Those accessors abort rather than fall
    back to worker 0, so anything externally reachable must instead branch on
    `tryGetCurrentEventWorker()` / `currentThreadIsEventWorkerWID(wid)` and fail
    cleanly, return `NULL`, or queue to an explicit worker. Worker-0 ownership is
    `currentThreadIsEventWorkerWID(0)`, never `getWID() == 0`. Raw `getWID()` is
    for diagnostics only — pass it through `workerWIDForLog()` and print with `%d`
    (`-1` means an unregistered thread). See
    §"Choosing a Worker-Context Helper" in the developer guide;
    `tests/worker_identity_source_policy_test.py` enforces it.
15. **Every autonomous normal-line owner must be shutdown-complete.** Publish a
    newly created line in exactly one owner-worker inventory before any
    re-entrant `Init`/publication, remove it exactly once before invoking
    `Finish`, and drain every remaining slot while the event loop, chain, tunnel
    state, and line pools are alive. Connection-admitting/source owners finish
    and destroy their own lines; connection-holding tail adapters enumerate
    every line whose `Init` reached them, close their OS state, destroy adapter
    state, and send exactly one downstream `Finish` to the true owner. A tail is
    not responsible before its `Init`; the upstream/autonomous owner covers that
    interval. Source inventories drain before middle/end `onWorkerStop` hooks.
    A shared idle table indexing worker-owned lines remains alive through every
    worker's drain; drain its worker items in `onWorkerStop`, then destroy its
    owner-loop timer and table in main-thread `onStop`.
    Middle tunnels never duplicate inventories for borrowed lines, but remain
    responsible for internal normal lines they create. Packet lines and
    documented resource-free terminal absorbers are explicit exceptions.
16. **Do not create proofs of proofs.** Validation must directly protect product
    behavior or make a bounded performance decision. A defect in optional test,
    benchmark, parser, provenance, or evidence machinery is normally a reason to
    simplify or remove that machinery, not to add another validator. Optimization
    review must end in a terminal keep/revert/defer/inconclusive disposition; a
    harness failure alone does not authorize another implementation plan. See
    [§6](#6-validation-and-optimization-review-stop-rules) for the mandatory stop
    rules.
17. **Application termination has one coordinator.** Leaf callbacks close their
    local ownership, publish a typed orderly request, and unwind; they do not
    inspect a global termination phase or assume the request ran cleanup.
    Origin and cleanup scope are separate: requests before the explicit runtime
    commit select `StartupRollback`, requests after it select `ProcessShutdown`.
    Startup failures propagate through explicit stage results to the top
    boundary. A synchronous top-level startup stage may use the nested,
    thread-local startup result collector; it is restored before runtime and is
    not process-termination state. Immediate delayed-message refusal retains
    caller ownership when that API is selected, while accepted work always
    settles through callback or cleanup. Nested normal-callback authority is
    valid only for the exact event loop that admitted it; independent WIO writes
    acquire that target loop's admission across send and queue/publication, and
    synchronous write callbacks run with target-loop authority. Custom-event
    authority comes from its destination, while control callbacks inherit no
    normal authority. Canceled or staging-refused IdleTable delivery restores an
    attached item, and item creation publishes its map and heap entries
    atomically. POSIX startup-failure arbitration keeps graceful signals blocked
    across mailbox take and controller publication. `abortProgramNow()` uses
    only an always-lock-free relaxed status atomic and deliberately skips orderly
    cleanup and logging.
18. **`Pause` is backpressure, not proof of a zero-byte pipeline.** Once a
    producer receives `Pause`, it must stop initiating new `Payload` callbacks
    toward that consumer until `Resume`. The consumer may nevertheless retain
    bytes it already accepted, and adapters may deliberately absorb a small,
    bounded queue before emitting `Pause`. Do not "fix" an adapter by forcing
    pause at its first queued byte without reading its write-queue policy. Any
    tolerance must remain bounded, FIFO-preserving, accounted, and paired with a
    clear resume or overflow/close path.

> If a proposed change cannot explain how it preserves all of the above, it is not
> ready.

---

## 1. Repository Map

| Path | What lives here |
| --- | --- |
| `ww/net/` | **Core contracts.** `tunnel.{h,c}`, `line.{h,c}`, `chain.{h,c}`, `packet_tunnel.{h,c}`. Read these first. |
| `ww/bufio/` | Buffers: `shiftbuffer.{h,c}` (`sbuf_t`), `buffer_pool.{h,c}`. |
| `ww/objects/` | `node.h` (node metadata, flags, layer groups), user/auth handles. |
| `tunnels/` | Tunnel implementations, one directory each. `tunnels/template/` is the skeleton. |
| `tests/` | Integration harness. `tests/cases/<case>/`, `tests/run_waterwall_case.sh`. |
| `WaterWall-Docs/docs/05-devguides/` | The full seven-part Developer Guide. |
| `WaterWall-Docs/docs/02-noderefs/` | Per-node reference docs (user-facing settings). |
| `core/`, `scripts/` | Runtime entry and helper scripts. |
| `CMakePresets.json`, `ww/cmake/preset/` | Build presets (`linux`, `linux-gcc-x64`, …). |

**Reference tunnels** to copy from:

| Need | Look at |
| --- | --- |
| Adapter that **creates and destroys** its lines | `TcpListener`, `UdpListener` |
| Adapter that **owns a socket but borrows** its line | `TcpConnector`, `UdpConnector` |
| Stateful protocol wrapping, clean finish w/ final bytes | `TlsClient`, `EncryptionClient` |
| Internal line ownership, re-entrant safety | `MuxClient` |
| Packet/stream bridges | `PacketsToStream`, `StreamToPackets`, `PacketsToConnection` |
| Direct paired packet transforms | `PingClient`, `PingServer` |
| Minimal skeleton | `template` |

---

## 2. Architecture In One Screen

**Adapters** sit at the chain head/tail and own an OS resource (TCP/UDP socket,
TUN device, raw socket). They are the only nodes that touch the outside world.
**Middle tunnels** transform callbacks/payloads and must work regardless of which
adapter is on either side.

**OS-resource ownership is not `line_t` ownership.** A chain-head adapter such as
`TcpListener` calls `lineCreate()` for every accepted connection and is that
line's owner. A chain-end adapter such as `TcpConnector` owns a socket but calls
neither `lineCreate()` nor `lineDestroy()` — it consumes a line created upstream.
Middle tunnels are usually borrowers, but several own *specific internal line
roles* (a mux carrier, an HTTP split transport, a UDP remote flow) while
borrowing the application line that passes through them. Always classify the
**exact line instance**, never the node type or its name.

**Four core objects:**

| Object | Meaning | Defined in |
| --- | --- | --- |
| `node_t` | Parsed config + metadata (`type`, `next`, `flags`, `layer_group`, `required_padding_left`, `createHandle`). | `ww/objects/node.h` |
| `tunnel_t` | Runtime instance: 12 callback pointers, `next`/`prev`, tunnel state, line-state size/offset. | `ww/net/tunnel.h` |
| `line_t` | One connection (or a worker packet line): routing context, auth markers, `wid`, refcount, `alive`, and **every tunnel's per-line state**. | `ww/net/line.h` |
| `tunnel_chain_t` | Ordered tunnels; computes total line-state size, total padding, per-worker packet lines. | `ww/net/chain.h` |

**State — two kinds, two helpers:**

```c
my_tstate_t *ts = tunnelGetState(t);     // per-instance, shared by all lines
my_lstate_t *ls = lineGetState(line, t); // per-line, private to this tunnel
```

`lineGetState` returns `line->tunnels_line_state + t->lstate_offset`; the offset is
assigned once during chain indexing. This is why line state must be initialized in
`Init` and treated as dead/zeroed after you destroy it.

**Directions & forwarding helpers** (`tunnelNextUpStreamPayload(t,l,b)` just calls
`t->next->fnPayloadU(...)`):

| Flow | Meaning | Forward with |
| --- | --- | --- |
| Upstream | request / outbound / toward `next` | `tunnelNextUpStream{Init,Est,Payload,Pause,Resume,Finish}` |
| Downstream | response / inbound / toward `prev` | `tunnelPrevDownStream{Init,Est,Payload,Pause,Resume,Finish}` |

A callback you don't override defaults to a pass-through to the same-direction
neighbor.

**Lifecycle hooks** (per tunnel, not per packet), assigned in `create.c`:

```text
createHandle -> onChain -> [solve -> onSolvedTopology]* -> onIndex -> onPrepare -> onStart -> onQuiesceRequest
             -> onWorkerQuiesce -> onQuiesceWait -> onWorkerStop -> onStop -> onDestroy
```

Shutdown uses lifecycle ABI v2 and an explicit context. `onQuiesceRequest` is a
main-thread, nonblocking source-to-tail pass that closes component and external
producer admission. Every owner worker then runs `onWorkerQuiesce` to detach its
timers and watchers before generic pending-work cancellation and the `Quiesced`
acknowledgement. Once all workers are quiesced, `onQuiesceWait` joins or detaches
external callback roots without releasing resources required by line closure.

The drain phase first closes SocketManager's worker-owned UDP source inventory,
then invokes `onWorkerStop` source-to-tail. Source hooks drain owned normal lines
before middle hooks validate that borrowed children are gone. Tail resources,
the loop, tunnel state, and line/buffer pools remain alive through this pass.
After every worker acknowledges `Drained`, main-thread `onStop` releases remaining
shared resources; `onDestroy` reclaims instances only after workers and external
producers can no longer reference them. Startup rollback, owned-child stop, and
device restart use their corresponding explicit lifecycle contexts rather than
ambient process state.

Most tunnels override only `onPrepare`, `onStart`, `onStop`, `onDestroy`, and the
flow callbacks; `onChain`/`onIndex` keep the framework defaults and
`onSolvedTopology` remains `NULL`. A tunnel whose private topology depends on
solved adjacent edge domains may set `onSolvedTopology`. The hook sees the
current solved snapshot, not necessarily the final topology, and may run more
than once. It must return `true` if and only if it changed topology; that makes
the snapshot stale and NodeManager solves again before invoking another hook.
After a complete pass reports no changes, `onIndex` runs once over immutable
topology. It and all later lifecycle callbacks may consume the final solved edge
domains. Static internal topology known before solving remains the responsibility
of `onChain`.

---

## 3. The Contracts You Must Not Break

### 3.1 Line lifetime & re-entrancy → [Part 2](WaterWall-Docs/docs/05-devguides/part2-lines-and-callbacks.mdx)

- **Logical death and physical reclamation are two different events.**
  `lineDestroy()` clears `alive` and drops the creator's reference; the
  allocation returns to its worker pool only when the last `lineLock()` is
  released. So a line can be `! lineIsAlive(line)` while its memory is still
  readable to whoever holds a reference — that is the normal shape when a nested
  callback closes a line under an outer frame.
- `lineLock()`/`lineUnlock()` adjust that refcount and keep the **memory** valid;
  they do **not** mean the line is logically alive. After a re-entrant call,
  re-check `lineIsAlive()`.
- A logically dead line must never receive a new flow callback, and its
  `tunnels_line_state` must already be zeroed — `lineUnRefInternal()` asserts
  exactly that when the allocation is finally reclaimed.
- These calls can close the line before returning — treat them as dangerous:
  `tunnelNextUpStream*` / `tunnelPrevDownStream*` for `Init`, `Payload`, `Est`,
  `Pause`, `Resume`.
- Preferred guard:

  ```c
  if (! withLineLocked(line, tunnelNextUpStreamInit, t)) {
      return;   // line died: do NOT touch line, ls, or LinestateDestroy()
  }
  my_lstate_t *ls = lineGetState(line, t);   // safe again; re-read state
  ```

- On a `false` return, the close path already destroyed your line state. Only
  recycle buffers you still own.
- You do **not** need the wrapper if you simply forward and `return`.

### 3.2 Finish — directional, destructive, and the ONE non-re-entrant callback → [Part 2](WaterWall-Docs/docs/05-devguides/part2-lines-and-callbacks.mdx)

**Every other callback can re-enter your tunnel and close the line before it
returns. `Finish` cannot.** That single guarantee is what makes the next rule safe
to rely on — and mandatory to obey:

> **If Tunnel A sends `Finish` to Tunnel B for a `line_t`, then B must send nothing
> back to A for that line — not `Payload`, not `Est`, not `Pause`/`Resume`, not even
> another `Finish`.**

- **Receiving `Finish` closes that direction, permanently, for that line.** A tunnel
  that **received upstream `Finish`** must not call any `tunnelPrevDownStream*` for
  that line; one that **received downstream `Finish`** must not call any
  `tunnelNextUpStream*`. Sending a callback back toward the finished side
  ("reflection") is a top crash source — that side already destroyed its line state.
  Because `Finish` is non-re-entrant you are promised you won't be called back on the
  finished side; extend the same promise and call back nothing.

- **Simplest clean finish** (what most tunnels do): destroy local state, then
  propagate. Nothing else.

  ```c
  myLinestateDestroy(ls);          // first
  tunnelNextUpStreamFinish(t, l);  // then propagate
  ```

- **Closing from the middle:** destroy local state → finish **upstream first** →
  finish **downstream second** (line may die here) → `return` immediately.

- **Owner termination — the postcondition.** The three cases above are about
  *propagation*. If the line you were finished on is a **normal line you created**,
  propagation is not enough: that handler must not return while the line is still
  alive.

  ```c
  // fnFinU: prev sent this Finish, so nothing may travel back toward prev.
  void ownerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
  {
      owner_lstate_t *ls = lineGetState(l, t);

      ownerDetachIo(t, l, ls);        // io callbacks, timers, idle items, maps
      bool propagate = ls->next_init_sent;
      ownerLinestateDestroy(ls);      // exactly once

      if (propagate)
      {
          tunnelNextUpStreamFinish(t, l);   // away from the sender only
      }
      if (lineIsAlive(l))             // a nested path may have killed it already
      {
          lineDestroy(l);
      }
  }                                   // assert(! lineIsAlive(l)) holds here
  ```

  The downstream mirror (`fnFinD`, sent by **next**) is the same code with
  `tunnelPrevDownStreamFinish()`. An **endpoint** owner — a chain head such as
  `TcpListener` or `UdpStatelessSocket` — has no prev at all and propagates
  nothing; it only detaches, destroys its state, and destroys the line.

  The caller may rely on it:

  ```c
  lineLock(l);
  owner->fnFinU(owner, l);    // or fnFinD, whichever side is finishing it
  assert(! lineIsAlive(l));   // logical death is immediate
  lineUnlock(l);              // physical free may happen here
  ```

  This is what closes the gap where a middle tunnel's nested `Finish` destroyed
  its line state while an outer callback frame still saw `lineIsAlive(line)` and
  resumed on freed state. Exceptions, and only these: **borrowed lines** (destroy
  your own state, propagate away from the sender, never `lineDestroy()`) and
  **packet lines** (§3.5).

- **A shutdown request does not close a line.** `requestProgramShutdown()`
  schedules global teardown on worker 0; the current callback still unwinds
  through every suspended frame first. An owner that fails terminally inside
  `Finish` must detach, destroy its state and mark the line dead *and then*
  request the shutdown.

- **Do NOT add `prev_finished` / `next_finished` (or `can_upstream` /
  `can_downstream`) flags by default.** Because `Finish` is non-re-entrant, a tunnel
  that merely forwards `Finish` will never be called back on the finished side, so it
  has nothing to remember. A speculative "did this side finish?" boolean is almost
  always a control-flow bug being patched instead of fixed.

  You need a directional-close flag **only** when your tunnel must **send final bytes
  before closing** (TLS alert/close, a flush/ack, an HTTP trailer). That send
  re-enters the adapter, which may emit `Pause`/`Resume`; the flag lets your
  pause/resume handlers drop anything that would reflect toward the already-finished
  side. Real tunnels carry exactly this state and nothing more — names vary, role is
  identical: `TlsServer` (`upstream_finished`, `downstream_finishing`),
  `TcpOverUdpClient` (`can_downstream`), `TcpOverUdpServer` (`can_upstream`),
  `HttpClient` / `HttpServer` / `Socks5Server` (`prev_finished`, `next_finished`).

- **Final-bytes pattern:** `lineLock` → **mark the sender side finished first** (set
  that directional flag) → send the bytes → destroy local state → propagate `Finish`
  → `lineUnlock` → return. The mark must precede the send so reflected `Pause`/`Resume`
  is dropped.

- **Never read `ls` after `LinestateDestroy(ls)`** — assume it is zeroed.

### 3.3 Pause / Resume and bounded tolerance → [Part 2](WaterWall-Docs/docs/05-devguides/part2-lines-and-callbacks.mdx)

There are two different moments in backpressure, and confusing them produces
overly strict or unsafe implementations:

- **After receiving `Pause`:** the producer must not initiate another `Payload`
  toward the paused side until it receives `Resume`. `Pause` is not merely a hint
  and does not authorize bypassing that neighbor. A queue that must drain through
  the paused side waits; a terminal path either retains the accepted bytes under
  its close policy or takes its documented overflow/abort path.
- **Before emitting `Pause`:** a consumer, especially an adapter writing to an OS
  resource, may accept a bounded amount of data before signaling backpressure.
  `TcpListener`, `TcpConnector`, and `UdpConnector` use local write queues and
  thresholds to absorb short stalls and callback/event-loop latency. This does
  not violate the contract: those bytes were accepted before the producer saw
  `Pause`.

Therefore, neither `Pause` nor `Resume` proves that every adapter, event-loop, OS,
or middle-tunnel queue is empty. It changes permission for **future** payload
delivery at that chain edge. Payload already handed to a callback remains owned
by the receiver and may be queued according to that node's policy.

Do not generalize adapter tolerance into arbitrary buffering in transparent
middle tunnels. A tunnel with no explicit queue normally forwards `Pause` and
`Resume` immediately. If a node intentionally absorbs pressure, its queue must:

- preserve payload order and buffer ownership;
- have an explicit byte/item bound and an overflow or close policy;
- resume the producer only when the node can accept payload again; and
- remain correct if the pause callback re-enters and destroys the line.

Treat numeric thresholds and hysteresis as implementation details: read the
target adapter's `payload.c`, `helpers.c`, and `structure.h` rather than copying a
value into this guide or assuming every adapter has the same tolerance.

### 3.4 Buffers & padding (`sbuf_t`) → [Part 3](WaterWall-Docs/docs/05-devguides/part3-buffers-and-padding.mdx)

- `sbuf_t` is a padded, shiftable buffer: `curpos` (payload start), `len`,
  `capacity`, `l_pad` (reserved left padding).
- Prepend a header by shifting the cursor left into reserved padding:

  ```c
  assert(sbufGetLeftCapacity(buf) >= header_len);
  sbufShiftLeft(buf, header_len);   // curpos -= header_len; len += header_len
  ```

- You may only rely on padding you advertised in `node.c`
  (`.required_padding_left = ...`). The runtime sums these across the chain. Prepend
  beyond your budget and the tunnel will break in some chain layouts.
- Get working buffers from the **line's worker pool**, and recycle exactly on paths
  you still own:

  ```c
  sbuf_t *b = bufferpoolGetLargeBuffer(lineGetBufferPool(line));
  lineReuseBuffer(line, b);   // or bufferpoolReuseBuffer(pool, b)
  ```

- A forwarding callback **takes ownership** of the buffer you pass it — do not
  reuse or free it afterward. On error paths, recycle any buffer you still hold.

### 3.5 Packet lines & packet tunnels → [Part 4](WaterWall-Docs/docs/05-devguides/part4-packet-tunnels.mdx)

- A packet line is one persistent `line_t` **per worker** for a chain containing a
  layer-3 node. Allocated in `tunnelchainFinalize()`, destroyed only in
  `tunnelchainDestroy()`. **Never** `lineDestroy()` it at runtime.
- **The owner postcondition in §3.2 does not apply to a packet line.** Whatever
  else a handler does, it must never `lineDestroy()` one.
- **Classify packet-line `Finish` per handler and direction:**
  1. A **packet-lifecycle anchor** for which close is impossible fails loudly
     with `LOGF` + `abortProgramNow(1)`. Examples include `TunDevice`,
     `RawSocket`, the packet sides of `PacketsToConnection`,
     `PacketsToStream`, `StreamToPackets`, and `PacketSplitStream`, and the
     packet modes of the tester nodes.
  2. A **transparent middle transform** forwards unrelated lifecycle callbacks
     in the same direction. `PingClient` inherits the standard pass-throughs
     and `PingServer` spells them out, which permits compositions such as
     `UdpListener <-> PingServer <-> UdpConnector`.
  3. An **intentional terminal absorber** owns no relevant per-line state and has
     no onward direction, so it documents why doing nothing is correct.
     `PacketSender` downstream absorbs the close emitted when its
     `UdpConnector` peer expires; `PacketReceiver` is also an absorber.
  Chain position alone does not select a category, and the same tunnel may use
  different categories for different directions or line roles.
- Use `tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l)` when one handler can
  see both a normal transport line and the packet line — `WireGuardDevice` owns
  per-worker transport lines *and* sits on the packet line, so it must branch on
  the exact role before doing anything.
- **A `Finish` handler that does nothing must say why.** Propagate the close,
  release what you own, report a violation, or document that you own no per-line
  state and have no onward direction so absorbing it is the whole job.
  `tests/line_ownership_policy_test.py` rejects any `fin.c` whose body is nothing
  but `discard` statements unless it is registered in `SILENT_FINISH_ALLOWED` with
  a rationale.
- Its state is **worker-local scratch**, reused across unrelated packets. Do not
  treat `routing_context`, `recalculate_checksum`, or stored state as stable
  per-flow identity. For per-flow behavior, create normal lines *behind* the packet
  side.
- **Pure packet tunnels** use `packettunnelCreate()` (asserts `lstate_size == 0`,
  no per-line state) and must override the packet payload callbacks; several default
  stream-style callbacks deliberately abort. Examples: `IpOverrider`,
  `IpManipulator`, `PingClient`, `PingServer`, `WireGuardDevice`.
- **Packet-line bridges** are normal `tunnelCreate()` tunnels that anchor
  worker-local bridge state on the packet line (`PacketsToStream`, `StreamToPackets`,
  `PacketsToConnection`, `PacketSplitStream`).
- **Direction:** draw the packet flow first and keep transform role separate from
  callback forwarding direction. In a direct `PingClient -> PingServer` pair,
  PingClient encodes upstream and PingServer decodes upstream; both forward with
  `tunnelNextUpStreamPayload()`. PingServer encodes downstream and PingClient
  decodes downstream; both forward with `tunnelPrevDownStreamPayload()`

---

## 4. Anatomy Of A Tunnel → [Part 5](WaterWall-Docs/docs/05-devguides/part5-tunnel-anatomy.mdx)

```text
tunnels/MyTunnel/
  CMakeLists.txt   description.md
  include/MyTunnel/{interface.h, structure.h}   # API prototypes; tstate/lstate structs
  instance/
    create.c    # tunnelCreate(node, sizeof(tstate), sizeof(lstate)); assign callbacks; parse+validate settings; cleanup-on-error
    node.c      # node metadata: type, flags, required_padding_left, layer_group, createHandle
    chain.c index.c        # onChain/onIndex (usually the framework default)
    prepair.c start.c stop.c destroy.c   # preparation/start and lifecycle-v2 shutdown hooks
    api.c       # tunnelApi runtime entry (must recycle the message buffer)
  common/
    line_state.c  # LinestateInitialize (from Init) + LinestateDestroy (zero aligned region)
    helpers.c     # shared protocol/state-machine + close/finish helpers
  upstream/{init,est,payload,pause,resume,fin}.c
  downstream/{init,est,payload,pause,resume,fin}.c
```

Notes that bite people: the prepare file is spelled **`prepair.c`** (`...OnPrepair`);
finish files are **`fin.c`**; every tunnel has an **`api.c`**. Destroy line state
with `memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)))`.

`node.c` flags: `kNodeFlagChainHead`, `kNodeFlagChainEnd`, `kNodeFlagNoChain`,
`kNodeFlagSingleton`. Layer groups: `kNodeLayer3` (packet), `kNodeLayer4` (stream),
`kNodeLayerAnything`. A `kNodeLayer3` node makes the chain a packet chain.
A bridge between the two layers states which side is which rather than claiming
`kNodeLayerAnything`: `ConnectionToPackets` is L4 on `prev` and L3 on `next`,
`PacketsToConnection` is L3 on `prev` and L4 on `next`.

`tunnelCreate()`, `adapterCreate()` and `packettunnelCreate()` all return `NULL` on
a state-size overflow or a failed allocation. A constructor must check the result
before touching any callback or `tunnelGetState()`, and return `NULL` itself.
Under lifecycle-v2, framework-owned worker messages and timers settle before
component destruction, so worker-to-worker messages pass the tunnel pointer directly
with owner-worker validation. External callback roots (such as background reader
threads) must use a quiescence gate (`quiescence_gate_t`) to close admission and wait
for active operations before reclamation.

**HTTP tunnels** (`HttpClient`/`HttpServer`): HTTP/1.x and **single-stream** HTTP/2
only. No HTTP/3, no multiple H2 streams. For h2c upgrade, stream `1` is the original
request (no synthetic second request/response); reject upgrade-with-body.

---

## 5. Build, Test, Validate → [Part 6](WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx)

Prefer the `linux` preset. (The readme's fresh-VPS path uses `linux-gcc-x64`; both
are valid — don't mix trees in one verification flow.)

```bash
# Production lane: configure once, then build the shipped executable/tests.
cmake --preset linux
cmake --build --preset linux -j8

# focused build of one changed tunnel (fast iteration)
cmake --build --preset linux --target TlsClient -j8

# preferred: run the registered test(s) related to the change
ctest --preset linux --output-on-failure -R '^waterwall\.tls_roundtrip$'

# Fast full deterministic integration lane (normally 20–30 seconds on 4 CPUs).
bash tests/run_test_lane.sh functional build/linux Release

# All ordinary non-privileged production lanes (normally about 2 minutes).
bash tests/run_test_lane.sh all build/linux Release

# Complete production tree, including policy and harness checks.
ctest --preset linux --output-on-failure

# Native units have a separate Release/no-LTO tree.
cmake --preset linux-unit-tests
cmake --build --preset linux-unit-release -j8
ctest --preset linux-unit-release --output-on-failure

# run a single integration case directly while debugging
tests/run_waterwall_case.sh build/linux/Release/Waterwall tests/cases/tls_roundtrip 60
```

`linux-unit-release` builds the runnable Release unit aggregate in the dedicated
tree where IPO is disabled before project targets are created. The focused
no-LTO policy checks the configured cache, reachable build commands, and a small
set of representative linked archives. It is a regression check, not a build
attestation system. `linux-unit-debug` remains an optional diagnostic preset.

Build/validation rules:

- The production binary is at `build/linux/Release/Waterwall` (also `Debug/`,
  `RelWithDebInfo/`). `ctest --preset linux` is production-only; complete
  validation additionally uses `linux-unit-tests` / `linux-unit-release`.
- **Use the smallest validation that gives useful evidence.** Prefer an existing
  focused test, target build, policy check, or direct integration case that covers
  the affected behavior. Documentation-only, comment-only, and other clearly
  non-behavioral edits may need only inspection or a diff check. Do not run a full
  test lane merely because code changed, because the lane is available, or as a
  habitual final step.
- **Use the faster broad lanes when they add useful confidence.** The functional
  integration lane normally takes 20–30 seconds on the 4-CPU reference host, and
  all ordinary non-privileged production lanes take about 2 minutes. Run them
  readily for shared networking or tunnel behavior, cross-tunnel changes, and test
  harness work. Complete production plus native-unit validation takes about 3.5 minutes
  and is encouraged for shared-core contracts, lifecycle/concurrency work,
  multi-subsystem changes, or any change whose impact is hard to bound. Focused
  validation is still preferable for narrow changes; speed alone is not a reason
  to run unrelated tests. Treat every timing as hardware- and build-dependent.
- **Keep validation proportional and finite.** Do not turn a build-property test
  into a general supply-chain, reproducibility, CI-authority, process-tracing, or
  object-format verification system. If the requested invariant can be checked
  from CMake cache values, generated commands, representative artifacts, and the
  relevant tests, that is sufficient unless an explicit threat model says
  otherwise. Review the product change; do not recursively review and harden the
  proof mechanism without a separate request.
- **Add or update tests only when they are valuable.** Tests make sense for new
  behavior, bug fixes that need regression protection, meaningful edge cases, or
  changed contracts. They are not mandatory for every implementation task. Prefer
  extending an existing focused test over creating a new test harness, and skip
  test changes when existing coverage is sufficient or the change is mechanical,
  documentary, or otherwise has no meaningful behavior to assert.
- **Run clang-format on every C/header file you modify**, using the project's
  `.clang-format` file. The executable in this environment is `clang-format-19`:

  ```bash
  clang-format-19 -i --style=file path/to/changed_file.c            # apply
  clang-format-19 --dry-run -Werror --style=file path/to/changed_file.c  # verify
  ```

  Some legacy files (e.g. `ww/event/overlapio.c`) are not fully conformant; do not
  reformat untouched code wholesale — at minimum your added/changed lines must be
  clean (`--lines=<from>:<to>` checks a range). New files must be fully conformant.
- **Do not hand-assemble compile commands.** For a syntax-only check, reuse the exact
  flags from `build/linux/compile_commands.json`. Beware the `structure.h` collision:
  adding multiple tunnels' `include/` dirs to one command can include the wrong
  `structure.h`. Validate one tunnel in isolation.
- A GCC **internal compiler error / bus error** (often in core files like
  `ww/libc/wlibc.c`) is a build-environment problem first, **not** evidence your
  tunnel is wrong. Reconfigure with the `linux` preset before debugging source.
- Fallback order when blocked: preset configure → preset target build → full preset
  build → if GCC still crashes, report it and fall back to syntax-only checks +
  focused review.

---

## 6. Validation And Optimization Review Stop Rules

Validation is support work, not a second product. Its purpose is to catch a
realistic regression or answer a predeclared engineering question. It is not a
request to prove that every tool involved in answering the question is itself
perfect.

### 6.1 Classify findings before requesting work

Every review finding must fit one of these categories:

1. **Production correctness:** a concrete contract, ownership, lifetime,
   concurrency, portability, or user-visible behavior defect in shipped code.
2. **Direct regression coverage:** a realistic missing test for changed product
   behavior that is likely to regress.
3. **Performance decision:** evidence that a specific production candidate
   meets, misses, or cannot be measured against a predeclared workload and gate.
4. **Support-machinery quality:** a defect or possible hardening opportunity in
   a benchmark runner, result parser, manifest, test seam, artifact collector,
   or other evidence tooling.

Categories 1 and 2 may require implementation. Category 3 must produce a
terminal candidate disposition. Category 4 is non-blocking once the direct
product question can be answered; simplify, replace, or remove the machinery
instead of recursively repairing it. Do not describe a support-machinery issue
as a production blocker without demonstrating how it can produce a wrong
decision for the current scoped candidate.

### 6.2 Optimization work must terminate

Before collecting performance data, freeze the workload, metrics, thresholds,
sample/order count, host requirements, and candidate boundaries. Then apply
these rules:

- Give every isolated optional optimization one of **keep**, **revert/defer**, or
  **inconclusive on this host**. Do not leave an implemented optional candidate
  indefinitely "pending" while expanding the acceptance system around it.
- A measured regression or failure to earn the predeclared gain selects the
  simpler baseline. An inconclusive result also defaults to the simpler baseline
  for production; the candidate may be deferred for a better benchmark host.
- A host that cannot reliably execute the frozen workload is
  **non-decision-capable** for that workload. Preserve the observation and stop.
  Do not create another harness identity, tune the workload after seeing the
  result, retry until favorable, or weaken a gate to force a decision.
- By default, allow at most **one bounded harness-repair pass** after the first
  end-to-end attempt. Any further repair requires explicit maintainer approval
  for a separately scoped benchmark-infrastructure task. It may not silently
  extend the production optimization review.
- Once direct correctness checks pass and the terminal performance disposition
  is recorded, stop reviewing the acceptance machinery. Run broad product
  validation once on the final retained production set, not after every
  evidence-tool revision.

A reviewer whose remaining findings concern only evidence machinery must not
write another implementation/fix/readiness plan. Report the support-tool
limitations and the terminal product disposition instead. Reopen implementation
only for an independently reproducible production defect or an explicit
maintainer request to build reusable benchmark infrastructure.

### 6.3 Forbidden recursive validation

Unless the maintainer explicitly approves a separate security or reproducible-
build threat model, do not add or require:

- verifier replay, validator self-validation, test-of-test mutation frameworks,
  or attestations of the acceptance transaction;
- binary/tool/source hashes, copied verifier source in every result directory,
  child-process ancestry proofs, filesystem provenance, or CI-runner identity;
- general shell/CMake command parsers whose purpose is to prove that recorded
  commands match recorded flags;
- exhaustive fail-closed schemas for diagnostic fields that cannot change the
  scoped keep/revert or correctness decision; or
- a new product setting, protocol field, runtime branch, counter, or lifecycle
  hook solely to make optional evidence tooling easier to authenticate.

One direct check of a build option, path, ownership balance, timeout, or emitted
metric is enough when it demonstrates the relevant invariant. If optional proof
machinery becomes difficult to trust, prefer deleting it and retaining the
direct check.

### 6.4 Keep support code and artifacts subordinate

- Prefer existing tests and small benchmark fixtures. If new validation/evidence
  code materially exceeds the production change or introduces a new framework,
  stop and obtain maintainer approval before expanding it.
- Test seams and counters must compile out of ordinary production builds.
  Non-compile-gated product API added only for a benchmark requires explicit
  maintainer approval and a separate product justification.
- Raw benchmark output, copied manifests, temporary state trees, and repeated
  runner snapshots are generated artifacts, not normal source. Keep one concise
  results summary in the repository and store bulky reproducibility bundles
  outside the main source history unless maintainers explicitly request them.
- A review prompt asking for production review does not authorize cleanup or
  redesign of benchmark infrastructure. Conversely, a benchmark cleanup must
  not change production behavior merely to make evidence pass.

---

## 7. Implementation Workflow

**Planning may include a short developer interview.** When asked to write an
implementation-plan Markdown file (often in the repository root), inspect the
code and documentation first. If a consequential requirement, trade-off, scope
boundary, or compatibility decision remains that the repository cannot answer
reliably, ask the developer focused questions before finalizing the plan. Do not
delegate routine implementation details back to the developer; make and record
reasonable assumptions for low-risk choices.

1. **Draw the chain flow**; mark upstream/downstream and which direction owns the
   transformation.
2. **Classify every line your change touches** — before editing any `Finish`
   path — as **owned normal**, **borrowed normal**, or **packet**. Find the exact
   `lineCreate()`/`lineCreateForWorker()` site, not the node name; one tunnel can
   own some roles and borrow others. `tests/line_ownership_policy_test.py` holds
   the classification of every production creation site and fails on a new
   unclassified one.
3. **Read** the target tunnel + neighbors, then `line.h`, `tunnel.h`, `chain.c`.
4. If framing/prepending: read `shiftbuffer.h`, `buffer_pool.h`, and nearby `node.c`
   padding.
5. **Pick the closest mature tunnel** and stay close to it.
6. **Implement the smallest change** that preserves composition. Avoid speculative
   abstractions.
7. **Decide whether test coverage is warranted.** Add or update a focused test
   only for meaningful new/changed behavior, a regression-prone bug fix, an edge
   case, or a contract change. Reuse existing coverage where it is sufficient;
   do not manufacture a test for a simple, mechanical, or documentation-only task.
8. **Validate proportionally.** Start with inspection and the smallest relevant
   preset target/test. Expand to the fast broad lanes when the change is shared,
   cross-cutting, concurrency-sensitive, or difficult to bound, as described in
   §§5–6; do not run unrelated tests merely because they are available.

---

## 8. Review Checklist

- `Init` initializes this tunnel's line state before any callback can use it.
- Upstream forwarded only with `tunnelNextUpStream*`; downstream only with
  `tunnelPrevDownStream*`.
- Every re-entrant callback either returns immediately or protects the line; on a
  `false` from `withLineLocked()`, no further touch of `line`/`ls`/`LinestateDestroy`.
- `Finish` destroys local state before propagating; middle teardown finishes
  upstream then downstream then returns; no `Pause`/`Resume`/`Finish` reflection
  toward a finished side.
- Only the line **owner** calls `lineDestroy()`.
- Every owner `Finish` path for a normal line returns with `! lineIsAlive(line)`
  — including error, timeout, and terminal-verdict branches.
- A borrowed-line `Finish` path never calls `lineDestroy()`.
- A packet-line `Finish` path never destroys the packet line and follows its
  exact handler role: fatal rejection at an anchor, same-direction forwarding
  through a transparent middle transform, or a documented terminal absorption.
- `requestProgramShutdown()` is never used in place of closing an owned line.
- Producers (io callbacks, timers, idle-table items, maps, queues) are detached
  before the owner's line state and line are destroyed.
- A producer stops new payload delivery after receiving `Pause`; any intentional
  pre-Pause tolerance is bounded, FIFO-preserving, accounted, and has a clear
  Resume or overflow/close path. Transparent middle tunnels do not invent
  buffering merely because adapters have it.
- Every prepend fits inside `required_padding_left`; `sbufShiftLeft` only with
  enough left capacity; buffers recycled exactly on paths that own them.
- Packet lines stay alive at runtime; packet-line state treated as worker-local;
  packet-line init source verified.
- No `initialized` flag added that the source does not require.
- When tests were warranted, the chosen focused coverage exercises the changed
  behavior and likely regressions; otherwise, the reason existing coverage or
  non-test validation is sufficient is clear. Validation scope follows §§5–6:
  focused for narrow work and broad/full for shared or difficult-to-bound work.
  Compilation used preset build metadata.

---


If something is unclear, infer conservatively from the source and existing patterns.
**Do not invent a new lifecycle model.**

---

## Deep-Dive Index

The full Developer Guide (source-grounded, with code excerpts and worked examples):

1. [Part 1 — Overview & Mental Model](WaterWall-Docs/docs/05-devguides/doc1.mdx)
2. [Part 2 — Lines, Callbacks & Lifetime Safety](WaterWall-Docs/docs/05-devguides/part2-lines-and-callbacks.mdx)
3. [Part 3 — Buffers, Padding & Shift Buffers](WaterWall-Docs/docs/05-devguides/part3-buffers-and-padding.mdx)
4. [Part 4 — Packet Lines & Packet Tunnels](WaterWall-Docs/docs/05-devguides/part4-packet-tunnels.mdx)
5. [Part 5 — Anatomy of a Tunnel & Workflow](WaterWall-Docs/docs/05-devguides/part5-tunnel-anatomy.mdx)
6. [Part 6 — Building, Testing & Reviewing](WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx)
7. [Part 7 — Shutdown & Signals](WaterWall-Docs/docs/05-devguides/part7-shutdown-and-signals.mdx)
