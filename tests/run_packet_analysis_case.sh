#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
timeout_seconds=$3

run_dir=$case_dir
generated_core_json="$run_dir/core.json"
core_created=0
pid=""

dump_logs() {
  local path
  for path in "$run_dir/stdout.log" "$run_dir"/log/*.log; do
    [[ -f "$path" ]] || continue
    echo "===== $(basename "$path") =====" >&2
    cat "$path" >&2
  done
}

show_stdout_on_success() {
  case "${WATERWALL_TEST_SHOW_STDOUT_ON_SUCCESS:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

finish_success() {
  if show_stdout_on_success; then
    dump_logs
  fi

  exit 0
}

cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi

  if [[ $core_created -eq 1 ]]; then
    rm -f "$generated_core_json"
  fi
}

trap cleanup EXIT

if [[ -e "$generated_core_json" ]]; then
  echo "Refusing to overwrite existing generated core.json in case directory: $generated_core_json" >&2
  exit 2
fi

# Keep generated logs and packet reports in the case directory, but make sure
# stale output cannot satisfy this run.
rm -rf "$run_dir/stdout.log" "$run_dir/log" "$run_dir/packet-receiver-report.txt"

workers=2
if [[ -f "$run_dir/workers.txt" ]]; then
  workers=$(tr -d '[:space:]' < "$run_dir/workers.txt")
  if [[ ! "$workers" =~ ^[1-9][0-9]*$ ]]; then
    echo "Invalid workers.txt in case directory: expected a positive integer, got '$workers'" >&2
    exit 2
  fi
fi

core_created=1
cat >"$generated_core_json" <<EOF
{
  "log": {
    "path": "log/",
    "internal": { "loglevel": "DEBUG", "file": "internal.log", "console": false },
    "core":     { "loglevel": "DEBUG", "file": "core.log",     "console": false },
    "network":  { "loglevel": "DEBUG", "file": "network.log",  "console": false },
    "dns":      { "loglevel": "DEBUG", "file": "dns.log",      "console": false }
  },
  "configs": [
    "config.json"
  ],
  "misc": {
    "workers": $workers,
    "ram-profile": "client",
    "mtu": 1500,
    "try-enabling-bbr": false
  }
}
EOF

(
  cd "$run_dir"
  "$binary_path" >stdout.log 2>&1
) &
pid=$!

deadline=$((SECONDS + timeout_seconds))

while kill -0 "$pid" 2>/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "Timed out after ${timeout_seconds}s waiting for Waterwall to exit" >&2
    dump_logs
    exit 1
  fi

  sleep 0.2
done

set +e
wait "$pid"
status=$?
set -e
pid=""

if [[ $status -ne 0 ]]; then
  echo "Waterwall exited with non-zero status=$status" >&2
  dump_logs
  exit 1
fi

report_file="$run_dir/packet-receiver-report.txt"
if [[ ! -f "$report_file" ]]; then
  echo "Missing packet receiver report file" >&2
  dump_logs
  exit 1
fi

if [[ ! -f "$run_dir/expected-report.txt" ]]; then
  echo "Missing expected-report.txt in case directory" >&2
  exit 2
fi

while IFS= read -r expected_line || [[ -n "$expected_line" ]]; do
  [[ -n "$expected_line" ]] || continue
  if ! grep -qF "$expected_line" "$report_file"; then
    echo "Report did not contain expected line: $expected_line" >&2
    cat "$report_file" >&2
    exit 1
  fi
done < "$run_dir/expected-report.txt"

if grep -qF "PacketReceiver report" "$run_dir/stdout.log"; then
  echo "PacketReceiver report leaked to stdout" >&2
  cat "$run_dir/stdout.log" >&2
  exit 1
fi

finish_success
