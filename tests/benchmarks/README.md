# Diagnostic benchmarks

These targets are excluded from ordinary builds and have no CTest performance
threshold. Build the selected target with `cmake --build --preset linux --target
<target> -j8`; binaries are under `build/linux/tests/benchmarks/Release/`.
Run on an idle, comparable host with the same preset, workload and arguments.

| Source/target | Workload and reported metrics |
| --- | --- |
| [bufferstream_optimization_benchmark.c](bufferstream_optimization_benchmark.c) | Fixed coalescing geometries, copy crossover and padding cases; one warmup and seven samples, medians/spread in ns/byte and MiB/s, byte digests, copy counts and retained capacity. CLI selects a suite and labels the source/build context. |
| [device_writer_channel_benchmark.c](device_writer_channel_benchmark.c) | Producer contention with mostly empty and saturated queues, then closed-channel observation; accepts duration in milliseconds (default 1000). Reports throughput and process CPU time with send/refusal disposition counts. |
| [users_benchmark.c](users_benchmark.c) | Pre-generated user corpora at the selected sizes; construction/feed/validation, indexed lookup/copy/mutation, Allowed-IP and adaptive admission/release costs in ns/op. Uses the preset's crypto backend. |
| [wfrand_benchmark.c](wfrand_benchmark.c) | Fixed fast-random/range/percentage and byte-fill loops; one warmup and five timed samples, median ns/op. The source lists the exact operation counts. |
| [streamtopackets_selection_benchmark.c](streamtopackets_selection_benchmark.c) | Full return-line selection across pools of 1/4/16/64, plus four concurrent readers and a writer on a pool of eight; accepts iterations (default two million). Reports selection and contention timing. |
| [tcp_relay.go](tcp_relay.go) | Standalone Go TCP relay for throughput comparisons. `io.Copy` may use splice; this is not a guaranteed userspace-copy baseline. Its header gives the build/listen/target invocation. |

The C source headers describe fixture ownership and CLI details. Timings describe
these workloads and their compiler/backend/host context; they do not establish
application throughput, security, or a portable speedup. Keep source workloads,
sample counts and correctness checks unchanged when comparing results. Generated
reports belong outside the source tree. See [Developer Guide Part 6](../../WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx)
for validation and performance-decision policy.
