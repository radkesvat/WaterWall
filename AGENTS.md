# AGENTS.md — WaterWall

Operating manual for AI coding agents (and new contributors) working on
**WaterWall**, a modular, chain-based tunneling runtime written in C.

This file is the field manual: the rules you must follow, the commands you must
run, and where to look. For the full reasoning behind every rule, read the
six-part **Developer Guide** in `WaterWall-Docs/docs/05-devguides/` (linked at the
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

> If a proposed change cannot explain how it preserves all of the above, it is not
> ready.

---

## 1. Repository Map

| Path | What lives here |
| --- | --- |
| `ww/net/` | **Core contracts.** `tunnel.{h,c}`, `line.{h,c}`, `chain.{h,c}`, `packet_tunnel.{h,c}`. Read these first. |
| `ww/bufio/` | Buffers: `shiftbuffer.{h,c}` (`sbuf_t`), `buffer_pool.{h,c}`. |
| `ww/objects/` | `node.h` (node metadata, flags, layer groups), user/auth handles. |
| `tunnels/` | All 70 tunnels, one directory each. `tunnels/template/` is the skeleton. |
| `tests/` | Integration harness. `tests/cases/<case>/`, `tests/run_waterwall_case.sh`. |
| `WaterWall-Docs/docs/05-devguides/` | The full six-part Developer Guide. |
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
createHandle -> onChain -> onIndex -> onPrepare -> onStart -> ... -> onStop/onWorkerStop -> onDestroy
```

Most tunnels override only `onPrepare`, `onStart`, `onStop`, `onDestroy`, and the
flow callbacks; `onChain`/`onIndex` keep the framework defaults.

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
  **packet lines** (§3.4).

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

### 3.3 Buffers & padding (`sbuf_t`) → [Part 3](WaterWall-Docs/docs/05-devguides/part3-buffers-and-padding.mdx)

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

### 3.4 Packet lines & packet tunnels → [Part 4](WaterWall-Docs/docs/05-devguides/part4-packet-tunnels.mdx)

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
    prepair.c start.c stop.c destroy.c   # onPrepare/onStart/onStop/onDestroy
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

**HTTP tunnels** (`HttpClient`/`HttpServer`): HTTP/1.x and **single-stream** HTTP/2
only. No HTTP/3, no multiple H2 streams. For h2c upgrade, stream `1` is the original
request (no synthetic second request/response); reject upgrade-with-body.

---

## 5. Build, Test, Validate → [Part 6](WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx)

Prefer the `linux` preset. (The readme's fresh-VPS path uses `linux-gcc-x64`; both
are valid — don't mix trees in one verification flow.)

```bash
# configure once, then build everything
cmake --preset linux
cmake --build --preset linux -j8

# focused build of one changed tunnel (fast iteration)
cmake --build --preset linux --target TlsClient -j8

# tests: all, or one case by registered name
ctest --preset linux --output-on-failure
ctest --preset linux --output-on-failure -R '^waterwall\.tls_roundtrip$'

# run a single integration case directly while debugging
tests/run_waterwall_case.sh build/linux/Release/Waterwall tests/cases/tls_roundtrip 60
```

Build/validation rules:

- The binary is at `build/linux/Release/Waterwall` (also `Debug/`, `RelWithDebInfo/`).
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

## 6. Implementation Workflow

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
7. **Add/update a focused test** — ideally one that fails if a direction is reversed.
8. **Validate** with the preset build and relevant tests.

---

## 7. Review Checklist

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
- Every prepend fits inside `required_padding_left`; `sbufShiftLeft` only with
  enough left capacity; buffers recycled exactly on paths that own them.
- Packet lines stay alive at runtime; packet-line state treated as worker-local;
  packet-line init source verified.
- No `initialized` flag added that the source does not require.
- Tests exercise the intended direction; validation used preset build metadata.

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
