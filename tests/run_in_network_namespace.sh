#!/usr/bin/env bash

# Network namespace wrapper for WaterWall integration tests.
# Runs the requested command in a private Linux network namespace with only
# the loopback ('lo') interface brought up. Unprivileged callers also receive
# a private user namespace so they can configure the network namespace.

set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "error: network namespace isolation requires Linux" >&2
  exit 1
fi

unshare_bin=${WATERWALL_UNSHARE:-$(command -v unshare 2>/dev/null || true)}
ip_bin=${WATERWALL_IP:-$(command -v ip 2>/dev/null || true)}
bash_bin=${WATERWALL_BASH:-$(command -v bash 2>/dev/null || true)}

if [[ -z "$unshare_bin" || ! -x "$unshare_bin" ]]; then
  echo "error: 'unshare' not found or not executable" >&2
  exit 1
fi

if [[ -z "$ip_bin" || ! -x "$ip_bin" ]]; then
  echo "error: 'ip' not found or not executable" >&2
  exit 1
fi

if [[ -z "$bash_bin" || ! -x "$bash_bin" ]]; then
  echo "error: 'bash' not found or not executable" >&2
  exit 1
fi

unshare_args=(--net)
if ((EUID != 0)); then
  unshare_args=(--user --map-root-user --net)
fi

# The inner script is deliberately single-quoted so its positional parameters
# are expanded only after unshare starts the inner shell. A caller that already
# has root authority must remain in its current user namespace: nested namespace
# root cannot override permissions on runner-owned workspace paths.
# shellcheck disable=SC2016
exec "$unshare_bin" "${unshare_args[@]}" -- \
  "$bash_bin" -c '
    set -euo pipefail
    "$1" link set dev lo up
    shift 2
    exec "$@"
  ' waterwall-netns "$ip_bin" "$bash_bin" "$@"
