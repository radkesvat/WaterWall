#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

readonly SIGTERM_EXIT_STATUS=$((128 + 15))

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
case_dir=$(realpath "$2")
timeout_seconds=$3

run_dir=$(mktemp -d)
pid=""

cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi

  rm -rf "$run_dir"
}

trap cleanup EXIT

cp -R "$case_dir"/. "$run_dir"/

workers=2
if [[ -f "$run_dir/workers.txt" ]]; then
  workers=$(tr -d '[:space:]' < "$run_dir/workers.txt")
fi

cat >"$run_dir/core.json" <<EOF
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
    "mtu": 1500
  }
}
EOF

(
  cd "$run_dir"
  "$binary_path" >"$run_dir/stdout.log" 2>&1
) &
pid=$!

deadline=$((SECONDS + timeout_seconds))

while kill -0 "$pid" 2>/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "Timed out after ${timeout_seconds}s waiting for Waterwall to exit" >&2
    cat "$run_dir/stdout.log" >&2
    for path in "$run_dir"/log/*.log; do
      [[ -f "$path" ]] && { echo "===== $(basename "$path") =====" >&2; cat "$path" >&2; }
    done
    exit 1
  fi

  sleep 0.2
done

set +e
wait "$pid"
status=$?
set -e
pid=""

if [[ $status -ne 0 && $status -ne $SIGTERM_EXIT_STATUS ]]; then
  echo "Waterwall exited with non-zero status=$status" >&2
  cat "$run_dir/stdout.log" >&2
  for path in "$run_dir"/log/*.log; do
    [[ -f "$path" ]] && { echo "===== $(basename "$path") =====" >&2; cat "$path" >&2; }
  done
  exit 1
fi

report_file="$run_dir/packet-receiver-report.txt"
if [[ ! -f "$report_file" ]]; then
  echo "Missing packet receiver report file" >&2
  cat "$run_dir/stdout.log" >&2
  exit 1
fi

if ! grep -qF "sent-total-packets: 6" "$report_file"; then
  echo "Report did not contain the expected sent packet count" >&2
  cat "$report_file" >&2
  exit 1
fi

if ! grep -qF "received-total-packets: 6" "$report_file"; then
  echo "Report did not contain the expected total packet count" >&2
  cat "$report_file" >&2
  exit 1
fi

if ! grep -qF "lost-total-packets: 0" "$report_file"; then
  echo "Report did not show zero loss" >&2
  cat "$report_file" >&2
  exit 1
fi

if ! grep -qF "198.51.100.0 | 3 | 3 | 0" "$report_file"; then
  echo "Report did not contain the first expected IP line" >&2
  cat "$report_file" >&2
  exit 1
fi

if ! grep -qF "198.51.100.1 | 3 | 3 | 0" "$report_file"; then
  echo "Report did not contain the second expected IP line" >&2
  cat "$report_file" >&2
  exit 1
fi

if ! grep -qF "source-ip | sent | received | lost | loss-percent | histogram" "$report_file"; then
  echo "Report did not contain the histogram header" >&2
  cat "$report_file" >&2
  exit 1
fi

if ! grep -qF "| [################################]" "$report_file"; then
  echo "Report did not contain a rendered histogram bar" >&2
  cat "$report_file" >&2
  exit 1
fi

if grep -qF "PacketReceiver report" "$run_dir/stdout.log"; then
  echo "PacketReceiver report leaked to stdout" >&2
  cat "$run_dir/stdout.log" >&2
  exit 1
fi

exit 0
