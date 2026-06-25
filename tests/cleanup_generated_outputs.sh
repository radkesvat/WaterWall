#!/usr/bin/env bash

# Remove generated outputs left by the Waterwall test runners.
#
# This script is intentionally manual. CTest does not call it.

set -euo pipefail
shopt -s nullglob

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
dry_run=0
removed=0

usage() {
  cat <<EOF
usage: $0 [--dry-run]

Deletes generated test-runner artifacts ignored by git:
  - tests/cases/*/{core.json,stdout.log,log/,packet-receiver-report.txt,users.json.backup}
  - generated probe cert/key copies in probe case directories
  - tests/speedtests/*/{core.json,stdout.log,log/,server.crt,server.key}, excluding _shared
  - tests/unittests/log/
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--dry-run)
      dry_run=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

display_path() {
  local path=$1
  printf '%s' "${path#"$repo_root"/}"
}

remove_path() {
  local path=$1
  local display

  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return 0
  fi

  display=$(display_path "$path")
  if [[ $dry_run -eq 1 ]]; then
    printf 'would remove %s\n' "$display"
  else
    rm -rf -- "$path"
    printf 'removed %s\n' "$display"
  fi

  removed=$((removed + 1))
}

for case_dir in "$script_dir"/cases/*; do
  [[ -d "$case_dir" ]] || continue
  remove_path "$case_dir/core.json"
  remove_path "$case_dir/stdout.log"
  remove_path "$case_dir/log"
  remove_path "$case_dir/packet-receiver-report.txt"
  remove_path "$case_dir/users.json.backup"
done

remove_path "$script_dir/cases/tls_handshake_timeout_slow_drip/server.crt"
remove_path "$script_dir/cases/tls_handshake_timeout_slow_drip/server.key"
remove_path "$script_dir/cases/tls_tlslike_invalid_probe_does_not_fallback/server.crt"
remove_path "$script_dir/cases/tls_tlslike_invalid_probe_does_not_fallback/server.key"
remove_path "$script_dir/cases/tls_tlslike_oversized_probe_does_not_fallback/server.crt"
remove_path "$script_dir/cases/tls_tlslike_oversized_probe_does_not_fallback/server.key"

for speedtest_dir in "$script_dir"/speedtests/*; do
  [[ -d "$speedtest_dir" ]] || continue
  [[ "$(basename -- "$speedtest_dir")" != "_shared" ]] || continue

  remove_path "$speedtest_dir/core.json"
  remove_path "$speedtest_dir/stdout.log"
  remove_path "$speedtest_dir/log"
  remove_path "$speedtest_dir/server.crt"
  remove_path "$speedtest_dir/server.key"
done

remove_path "$script_dir/unittests/log"

if [[ $removed -eq 0 ]]; then
  echo "No generated test artifacts found."
elif [[ $dry_run -eq 1 ]]; then
  echo "Found $removed generated test artifact path(s)."
else
  echo "Removed $removed generated test artifact path(s)."
fi
