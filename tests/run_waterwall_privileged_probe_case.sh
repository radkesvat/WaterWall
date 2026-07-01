#!/usr/bin/env bash

set -euo pipefail

readonly SKIP_STATUS=77

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <waterwall-binary> <case-dir> <timeout-seconds> <python3>" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case_dir=$(realpath "$2")
python_path=$4
config_tun_names=()

skip() {
  printf '%s\n' "$1"
  exit "$SKIP_STATUS"
}

cleanup_preflight_tun() {
  if ! command -v ip >/dev/null 2>&1; then
    return 0
  fi

  if [[ -n "${preflight_tun_name:-}" ]]; then
    ip link delete "$preflight_tun_name" >/dev/null 2>&1 || true
  fi

  local dev
  for dev in "${config_tun_names[@]}"; do
    ip link delete "$dev" >/dev/null 2>&1 || true
  done
}

trap cleanup_preflight_tun EXIT

if [[ "$(uname -s)" != "Linux" ]]; then
  skip "privileged socket-manager TUN tests require Linux"
fi

if [[ "$(id -u)" != "0" ]]; then
  skip "privileged socket-manager TUN tests require root or an equivalent CAP_NET_ADMIN environment"
fi

if [[ ! -c /dev/net/tun ]]; then
  skip "privileged socket-manager TUN tests require /dev/net/tun"
fi

if ! command -v ip >/dev/null 2>&1; then
  skip "privileged socket-manager TUN tests require the ip command"
fi

mapfile -t config_tun_names < <(
  "$python_path" - "$case_dir/config.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    config = json.load(fh)

for node in config.get("nodes", []):
    if node.get("type") == "TunDevice":
        name = node.get("settings", {}).get("device-name")
        if name:
            print(name)
PY
)

for dev in "${config_tun_names[@]}"; do
  ip link delete "$dev" >/dev/null 2>&1 || true
done

preflight_tun_name="wwsmpf$$"
if ! ip tuntap add dev "$preflight_tun_name" mode tun >/dev/null 2>&1; then
  skip "privileged socket-manager TUN tests could not create a preflight TUN interface"
fi

ip link delete "$preflight_tun_name" >/dev/null 2>&1 || true
preflight_tun_name=""

bash "${script_dir}/run_waterwall_probe_case.sh" "$@"
