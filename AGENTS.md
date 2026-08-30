# AGENTS.md — WaterWall

Operating policy for AI coding agents and contributors working on **WaterWall**,
a modular, chain-based tunneling runtime written in C.

This always-loaded kernel routes detailed contracts and examples from
`WaterWall-Docs/docs/05-devguides/`. Keep it below 16 KiB.

## 1. Task Authority, Scope, And Evidence

### What a request authorizes

- For requests to **review, diagnose, explain, or plan**, inspect the relevant code,
  history, tests, and documentation and report the result. Do not modify files unless
  the request also asks for changes.
- For requests to **fix, change, build, implement, or review-and-fix**, make the
  requested in-scope local changes and run relevant non-destructive validation. Do
  not stop at a plan when a safe, complete in-scope fix is available.
- Read-only investigation, in-scope edits, builds, tests, and formatting need no
  further confirmation. Ask only for an unresolved consequential decision or a
  destructive, external, or materially broader action. An explicit request is
  maintainer authorization; do not seek duplicate approval.
- Preserve unrelated work in a dirty worktree. Do not discard, overwrite, or
  reformat user changes outside the task.

### Where the tunnel contracts apply

The domain contracts apply to `ww/net/`, `tunnels/`, and their callers. Unrelated
documentation, build, packaging, script, or tooling work uses only relevant
repository-wide rules. Preserve every **applicable** invariant; do not force
irrelevant tunnel analysis into a task.

### Durable project knowledge

The Developer Guide is durable project memory, not a task journal. During
implementation, update its canonical section when in-scope work changes a contract
or confirms reusable knowledge whose omission would mislead. Documentation is not
redesign authority.

Never record speculation, pending ideas, review history, artifacts, or one-off
details as contracts, or promote patterns without confirming intent. Report
conflicting or unclear evidence.

Read-only tasks only propose doc edits. Implementation may sync related guide text;
report unrelated findings. Change `AGENTS.md` only if authorized work changes
always-on policy, a catastrophic guardrail, or routing, using a short rule/link;
otherwise the guide is enough. Explicit contract/lifecycle redesign updates affected
code, callers, guide text, and tests.

## 2. Repository Map And Mandatory Reading

Core paths: `ww/net/` owns networking mechanics, `ww/bufio/` owns buffers,
`tunnels/` contains implementations, `tests/` contains native/integration coverage,
and `CMakePresets.json` plus `ww/cmake/preset/` define supported builds. Developer
contracts live in `WaterWall-Docs/docs/05-devguides/`; user-facing node settings live
in `WaterWall-Docs/docs/02-noderefs/`.

The routing table is mandatory, not advisory. Before substantive work, read every
row matching the expected or discovered scope. The guide's normative
`must` and `never` statements then become part of this policy. If investigation
expands the scope, read the newly applicable material before continuing.

| Trigger | Required sources |
| --- | --- |
| Any behavioral work in `tunnels/`, `ww/net/`, or code invoking tunnel/line contracts | Target, immediate neighbors, `ww/net/tunnel.h`, `ww/net/line.h`, `ww/net/chain.c`, [Part 1](WaterWall-Docs/docs/05-devguides/doc1.mdx), and [Part 2](WaterWall-Docs/docs/05-devguides/part2-lines-and-callbacks.mdx) |
| Worker identity/WID, worker-local storage, or cross-thread posting | [Part 1](WaterWall-Docs/docs/05-devguides/doc1.mdx), especially “Choosing a Worker-Context Helper,” plus the relevant worker/runtime implementation |
| Framing, prepend, padding, buffer pools, or buffer ownership | `ww/bufio/shiftbuffer.h`, `ww/bufio/buffer_pool.h`, relevant `node.c`, and [Part 3](WaterWall-Docs/docs/05-devguides/part3-buffers-and-padding.mdx) |
| Layer-3 nodes, packet lines, or packet/stream bridges | `ww/net/packet_tunnel.{h,c}` and [Part 4](WaterWall-Docs/docs/05-devguides/part4-packet-tunnels.mdx) |
| New/structurally changed tunnel, constructor, node metadata, or HTTP tunnel | [Part 5](WaterWall-Docs/docs/05-devguides/part5-tunnel-anatomy.mdx) |
| Build, formatting, tests, code review, benchmark, or validation infrastructure | [Part 6](WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx) |
| Shutdown, signals, lifecycle-v2, worker messages, quiescence/drain, or external callback roots | [Part 7](WaterWall-Docs/docs/05-devguides/part7-shutdown-and-signals.mdx) and relevant core implementation |

Documentation-only and unrelated tooling work need not load networking contracts
unless they describe or exercise them. For a new or structurally changed tunnel,
compare more than one mature implementation when practical; Part 1 lists useful
references. Existing patterns remain evidence, not proof.

## 3. Always-On WaterWall Safety Kernel

These guardrails do not replace the mandatory guide reading:

1. Classify each exact line as **owned normal**, **borrowed normal**, or **packet**.
   Owning an OS resource does not imply owning its `line_t`.
2. Upstream means toward `next` and uses `tunnelNextUpStream*`; downstream means
   toward `prev` and uses `tunnelPrevDownStream*`. Transform role never reverses
   callback direction.
3. Initialize per-line state in `Init`. Do not add an `initialized` flag to conceal
   unsafe ordering.
4. Inter-tunnel `Init`, `Payload`, `Est`, `Pause`, and `Resume` may destroy the line
   before returning. If work continues, hold a temporary line reference across
   the call and re-check `lineIsAlive()`; a reference preserves allocation memory,
   not logical life. After a failed `lineCallWithRef()`, touch neither the line
   nor its destroyed state.
5. Receiving `Finish` closes the sender's direction. Send no callback back toward
   that side; destroy local state first and propagate only away from it. Only a
   normal line's creator calls `lineDestroy()`, and an owner receiving `Finish` must
   return with its line logically dead. `requestProgramShutdown()` does not satisfy
   that obligation.
6. Never call `lineDestroy()` on a packet line; only `tunnelchainDestroy()` releases
   it. Read Part 4 before deciding whether packet-line `Finish` is fatal, forwarded,
   or intentionally absorbed.
7. Forwarding transfers `sbuf_t` ownership. Recycle only buffers still locally
   owned, use the line's pool, and prepend only within advertised
   `required_padding_left` after checking capacity.
8. Never compare or index worker-owned state with raw `getWID()`. Use line, supplied
   worker, event-loop, or checked current-worker context; unregistered threads queue
   work to an explicit event worker and never borrow its local pool.
9. Every autonomous normal-line owner must inventory and drain its lines while the
   required loops, chains, tunnel state, and pools remain alive. Termination has one
   coordinator; a shutdown request is not cleanup.
10. After `Pause`, initiate no new payload toward that consumer until `Resume`.
    Deliberate tolerance is bounded, FIFO-preserving, accounted, and has a resume or
    overflow/close path.
11. Tunnel constructors may return `NULL`; check before assigning callbacks or
    accessing state. External callback roots must close admission and quiesce before
    their reachable state is reclaimed.
12. Line scheduling transfers any buffer on every result. A non-null cancellation
    callback is task-XOR-cancel and may run synchronously, on a foreign or teardown
    thread, or with the line logically dead. Treat cancellation as notification only;
    never access owner-only state without an independent context proof.
13. Avoid speculative sanity checks in every added function,
    its the caller's responsibility to understand the requirements of the function they call.
    use assert() for debug-only invariants prerebaly;
    for Release invariants, use LOGF/LOGE/LOGW based on severity, with `abortProgramNow()` or `requestProgramShutdown()` when appropriate;
    the meaning of these functions is explained in the Developer's Guide, Part 7;
    use ordinary checks only for expected or fallible inputs, including valid nullable values;
    use LIKELY/UNLIKELY only for meaningful branch expectations.

## 4. Implementation Workflow

1. Classify the task and load every source required by §2 before substantive work;
   repeat if the discovered scope expands.
2. Inspect the requested scope, current worktree, relevant diff/history, and nearby
   callers/callees. Search with `rg`/`rg --files` first.
3. Trace concrete behavior and error paths. For tunnel work, draw chain flow, mark
   callback direction and transformation ownership, and classify each line as
   **owned normal**, **borrowed normal**, or
   **packet** by finding its actual `lineCreate()`/`lineCreateForWorker()` site.
4. Compare relevant mature implementations, but verify them against the
   contracts and callers. A repeated pattern may contain a repeated bug.
5. Implement the smallest **complete root-cause fix**. Do not minimize the diff by
   preserving a known defect, duplicating unsafe logic, or patching only a symptom.
   Avoid unrelated cleanup and speculative abstractions.
6. For a reproducible behavior bug, normally add or update a focused regression test
   that fails before the fix and passes afterward. Skip a new test when existing
   coverage already proves the behavior, reproduction is impractical, or the test
   would provide little durable protection; state the reason.
7. Format every modified C/header file with `clang-format`, then validate in
   proportion to risk and blast radius.
8. Review the final diff for accidental changes, ownership errors, missing cleanup,
   and whether the selected validation actually exercises the changed behavior.

## 5. Code Review Rules

- The checklist guides **defect discovery**; it does not expand accepted requirements
  or make optional work blocking. Inspect changed behavior, dependencies, and error
  paths for undefined behavior, bounds/integer errors, races, leaks, DoS, security,
  invalid configuration, compatibility, portability, and build/test defects.
- The stable baseline is the request and criteria, accepted plan and clarifications,
  applicable contracts/tests, and required compatibility/security behavior. Search
  broadly for defects; never invent later success criteria.
- A **blocker** cites its file/line, concrete trigger and impact, and the violated
  baseline or evidenced bug, regression, vulnerability, or material risk. Patterns,
  tests, policy checks, and comments are evidence, not proof; categories never
  suppress real defects.
- Report all known blockers together with severity, a safe correction, and finite
  acceptance conditions. Separate optional, stylistic, speculative, unmeasured,
  and out-of-scope findings; do not extend scope without authorization.
- Accepted decisions and resolved blockers stay closed unless new evidence
  contradicts the earlier conclusion; preference or reinterpretation is insufficient.
- Follow-ups verify requested fixes and delta regressions, not restart design review.
  Keep a finite, shrinking blocker list; reopening one requires new material evidence.
- End each review with **accepted**, **accepted with optional follow-ups**, **changes
  required**, or **inconclusive**. `changes required` gives remaining blockers
  and finite acceptance conditions. `inconclusive` names the exact missing evidence
  and authorizes no recursive proof work. When no evidenced blocker remains, say:
  **“The implementation satisfies the required contract. No further blocking changes
  are necessary.”** Optional ideas stay separate and do not extend the loop without
  explicit authorization.
- For tunnel-related changes, verify every applicable rule in §3, especially exact
  line ownership, re-entrant callback continuation, no reflection after `Finish`,
  owner death on `Finish`, packet-line classification, padding, buffer transfer,
  WID use, shutdown inventories, and bounded backpressure.

## 6. Build, Format, Test, And Validate

Part 6 is the canonical source for complete commands, lane meanings, and current
timings. Use CMake presets and project scripts, not hand-built compiler commands.
Prefer the `linux` production tree and do not mix it with `linux-gcc-x64` in one
validation flow.

```bash
cmake --preset linux
cmake --build --preset linux -j8
```

### Required C formatting

Invoke portable `clang-format`; each environment must map that name to its installed
project-compatible formatter. Do not pin a distribution-specific executable name.

```bash
clang-format -i --style=file path/to/changed_file.c
clang-format --dry-run -Werror --style=file path/to/changed_file.c
```

- Format every modified C/header file; new files must be fully conformant. Do not
  reformat unrelated legacy code. For a nonconformant legacy file, format and verify
  changed ranges with `--lines=<start>:<end>`.
- If the tool is unavailable, report it and any formatting left unverified.

### Validation policy

- Start with the smallest direct check. Expand to the functional lane for shared
  tunnel/network behavior and to all production lanes plus native units for
  shared-core, lifecycle/concurrency, multi-subsystem, or uncertain-scope changes.
- When native Linux units are relevant, normally exercise the focused coverage in
  both `linux-unit-debug` and `linux-unit-release`. Prefer Debug first during
  behavioral iteration because assertions and guardrails are active, but never use
  it as a substitute for optimized `NDEBUG` Release behavior. Broad/shared changes
  run the complete unit suite in both configurations.
- Documentation and clearly non-behavioral changes may need only inspection or
  relevant link/policy checks. Tests are expected for new observable behavior,
  meaningful edge cases, changed contracts, and reproducible bugs likely to regress;
  do not manufacture tests when existing coverage already proves the result.
- Deterministic integration cases use the namespace harness and loopback only, never
  public DNS or host-network port availability.
- For syntax diagnostics, reuse `build/linux/compile_commands.json`; syntax-only
  review never replaces required link/runtime validation. Compiler crashes, timeouts,
  missing privilege, or broken environments are **inconclusive**, not passed. Report
  exactly what remains unverified.
- Keep validation finite, but use repetition, sanitizers, stress, or broader tests
  for nondeterministic, concurrent, or security-sensitive failure modes.

## 7. Optional Optimization And Evidence Work

This section applies only to an in-scope optimization candidate or its evidence. It
does not limit ordinary product review or an explicitly requested infrastructure task.

- Before measuring, freeze the workload, metrics, thresholds, sample/order count,
  host requirements, and candidate boundaries.
- Give every candidate a terminal **keep**, **revert/defer**, or **inconclusive on
  this host** disposition. Regression, failure to earn the declared gain, or
  inconclusive evidence defaults production to the simpler baseline.
- A host unable to run the frozen workload reliably is non-decision-capable. Record
  that; do not retune after results, retry until favorable, weaken gates, or create
  alternate harness identities to force a decision.
- Allow one bounded incidental harness-repair pass after the first end-to-end
  attempt. More infrastructure work requires explicit separate scope.
- Report support-tool defects. They block only when they can skip relevant behavior,
  create false results, corrupt a metric, or change the decision; otherwise label
  them non-blocking rather than expanding the task.
- Do not create proofs of proofs: verifier replay, validator self-validation,
  test-of-test systems, broad provenance/identity attestation, or product hooks only
  to authenticate optional evidence. Direct checks may prove narrow invariants;
  timing, concurrency, and nondeterminism may need repeated or independent evidence.
- Prefer existing tests and small fixtures. If new evidence machinery materially
  exceeds the product change or adds a framework, stop unless explicitly authorized.
  Keep bulky generated artifacts outside source history unless requested.
- Once correctness checks pass and the terminal candidate disposition is recorded,
  run broad validation once on the final retained production set and stop reviewing
  incidental acceptance machinery.
