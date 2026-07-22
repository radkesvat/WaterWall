#!/usr/bin/env bash

set -euo pipefail

readonly SKIP_STATUS=77

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <waterwall-binary> <python3>" >&2
  exit 2
fi

binary_path=$(realpath "$1")
python_path=$(realpath "$2")
script_path=$(realpath "$0")

skip() {
  printf '%s\n' "$1"
  exit "$SKIP_STATUS"
}

fail() {
  printf 'iptables crash-recovery integration failure: %s\n' "$1" >&2
  exit 1
}

if [[ "${WATERWALL_IPTABLES_NETNS_INNER:-0}" != "1" ]]; then
  [[ "$(uname -s)" == "Linux" ]] || skip "iptables crash-recovery integration requires Linux"
  [[ "$(id -u)" == "0" ]] || skip "iptables crash-recovery integration requires root/CAP_NET_ADMIN"
  command -v unshare >/dev/null 2>&1 || skip "iptables crash-recovery integration requires unshare"
  command -v iptables >/dev/null 2>&1 || skip "iptables crash-recovery integration requires iptables"
  command -v ip6tables >/dev/null 2>&1 || skip "iptables crash-recovery integration requires ip6tables"

  real_iptables=$(command -v iptables)
  real_ip6tables=$(command -v ip6tables)
  if ! unshare --net --fork /bin/true >/dev/null 2>&1; then
    skip "iptables crash-recovery integration cannot create a network namespace"
  fi

  exec unshare --net --fork env \
    WATERWALL_IPTABLES_NETNS_INNER=1 \
    WATERWALL_REAL_IPTABLES="$real_iptables" \
    WATERWALL_REAL_IP6TABLES="$real_ip6tables" \
    "$BASH" "$script_path" "$binary_path" "$python_path"
fi

real_iptables=${WATERWALL_REAL_IPTABLES:?}
real_ip6tables=${WATERWALL_REAL_IP6TABLES:?}
original_path=$PATH
temp_dir=$(mktemp -d)
trace_path="$temp_dir/iptables.trace"
failure_path="$temp_dir/fail-delete-jump"
wrapper_dir="$temp_dir/bin"
disabled_path="$temp_dir/no-iptables"
mkdir -p "$wrapper_dir" "$disabled_path"
process_ids=()

cleanup() {
  local pid
  for pid in "${process_ids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  for pid in "${process_ids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$temp_dir"
}
trap cleanup EXIT

if ! "$real_iptables" -w -t nat -S >/dev/null 2>&1; then
  skip "iptables NAT table is unavailable in the test network namespace"
fi
if ! "$real_ip6tables" -w -t nat -S >/dev/null 2>&1; then
  skip "ip6tables NAT table is unavailable in the test network namespace"
fi

cat >"$wrapper_dir/iptables" <<'WRAPPER'
#!/usr/bin/env bash
set -u
printf 'CMD %s\n' "$*" >>"${WATERWALL_IPTABLES_TRACE:?}"

if [[ -s "${WATERWALL_IPTABLES_FAIL_DELETE_JUMP_FILE:?}" ]]; then
  fail_chain=$(<"${WATERWALL_IPTABLES_FAIL_DELETE_JUMP_FILE}")
  if [[ "$*" == "-w -t nat -D PREROUTING -j $fail_chain" ]]; then
    printf 'FORCED_DELETE_JUMP_FAILURE %s\n' "$fail_chain" >>"${WATERWALL_IPTABLES_TRACE:?}"
    exit 4
  fi
fi

chain=""
for ((i = 1; i <= $#; ++i)); do
  if [[ "${!i}" == "-X" ]] && ((i < $#)); then
    next=$((i + 1))
    chain=${!next}
    break
  fi
done

if [[ "$chain" =~ ^WW2_([0-9A-F]{16})_4$ ]]; then
  token=${BASH_REMATCH[1]}
  if "${WATERWALL_TEST_PYTHON:?}" - "$token" <<'PY'
import errno
import socket
import sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.bind("\0waterwall.iptables.owner.v2." + sys.argv[1])
except OSError as exc:
    if exc.errno == errno.EADDRINUSE:
        raise SystemExit(1)
    raise
raise SystemExit(0)
PY
  then
    printf 'LEASE_FREE %s\n' "$chain" >>"${WATERWALL_IPTABLES_TRACE:?}"
  else
    printf 'LEASE_IN_USE %s\n' "$chain" >>"${WATERWALL_IPTABLES_TRACE:?}"
  fi
fi

exec "${WATERWALL_REAL_IPTABLES:?}" "$@"
WRAPPER

cat >"$wrapper_dir/ip6tables" <<'WRAPPER'
#!/usr/bin/env bash
set -u
printf 'CMD6 %s\n' "$*" >>"${WATERWALL_IPTABLES_TRACE:?}"
exec "${WATERWALL_REAL_IP6TABLES:?}" "$@"
WRAPPER
chmod +x "$wrapper_dir/iptables" "$wrapper_dir/ip6tables"

write_core_config() {
  local run_dir=$1
  cat >"$run_dir/core.json" <<'JSON'
{
  "log": {
    "path": "log/",
    "internal": { "loglevel": "DEBUG", "file": "internal.log", "console": true },
    "core":     { "loglevel": "DEBUG", "file": "core.log", "console": true },
    "network":  { "loglevel": "DEBUG", "file": "network.log", "console": true },
    "dns":      { "loglevel": "DEBUG", "file": "dns.log", "console": true }
  },
  "configs": ["config.json"],
  "misc": {
    "workers": 1,
    "ram-profile": "client",
    "mtu": 1500,
    "try-enabling-bbr": false
  }
}
JSON
}

write_instance_config() {
  local run_dir=$1
  local label=$2
  local port_min=$3
  local port_max=$4
  local backend=$5
  local port_setting
  if [[ "$port_min" == "$port_max" ]]; then
    port_setting="\"port\": $port_min"
  else
    port_setting="\"port-range\": [$port_min, $port_max], \"multiport-backend\": \"$backend\""
  fi

  cat >"$run_dir/config.json" <<JSON
{
  "name": "$label",
  "nodes": [
    {
      "name": "$label-listener",
      "type": "TcpListener",
      "settings": {
        "address": "0.0.0.0",
        $port_setting,
        "nodelay": true
      },
      "next": "$label-sink"
    },
    {
      "name": "$label-sink",
      "type": "BlackHole",
      "settings": { "mode": "passive" }
    }
  ]
}
JSON
}

start_instance() {
  local label=$1
  local port_min=$2
  local port_max=$3
  local backend=$4
  local instance_path=$5
  local run_dir="$temp_dir/$label"
  mkdir -p "$run_dir"
  write_core_config "$run_dir"
  write_instance_config "$run_dir" "$label" "$port_min" "$port_max" "$backend"
  (
    cd "$run_dir"
    exec env \
      PATH="$instance_path" \
      WATERWALL_IPTABLES_TRACE="$trace_path" \
      WATERWALL_IPTABLES_FAIL_DELETE_JUMP_FILE="$failure_path" \
      WATERWALL_REAL_IPTABLES="$real_iptables" \
      WATERWALL_REAL_IP6TABLES="$real_ip6tables" \
      WATERWALL_TEST_PYTHON="$python_path" \
      "$binary_path" >stdout.log 2>&1
  ) &
  STARTED_PID=$!
  process_ids+=("$STARTED_PID")
}

stop_instance() {
  local pid=$1
  local status
  kill -TERM "$pid"
  set +e
  wait "$pid"
  status=$?
  set -e
  forget_process "$pid"
  if [[ $status -ne 0 && $status -ne 143 ]]; then
    fail "WaterWall exited with status $status during graceful shutdown"
  fi
}

forget_process() {
  local forgotten_pid=$1
  local i
  for i in "${!process_ids[@]}"; do
    if [[ "${process_ids[$i]}" == "$forgotten_pid" ]]; then
      process_ids[$i]=""
    fi
  done
}

wait_for_chain() {
  local pid=$1
  local port_range=$2
  local chain=""
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      fail "WaterWall exited before publishing the rule for $port_range"
    fi
    chain=$("$real_iptables" -w -t nat -S | awk -v wanted="$port_range" '
      $1 == "-A" && $2 ~ /^WW2_[0-9A-F]+_4$/ {
        for (i = 3; i < NF; ++i) {
          if ($i == "--dport" && $(i + 1) == wanted) {
            print $2
            exit
          }
        }
      }
    ')
    if [[ -n "$chain" ]]; then
      FOUND_CHAIN=$chain
      return 0
    fi
    sleep 0.1
  done
  fail "timed out waiting for the WaterWall chain for $port_range"
}

assert_chain_active() {
  local chain=$1
  "$real_iptables" -w -t nat -S "$chain" >/dev/null || fail "missing active chain $chain"
  "$real_iptables" -w -t nat -S PREROUTING | grep -Fx -- "-A PREROUTING -j $chain" >/dev/null ||
    fail "missing active PREROUTING jump for $chain"
}

assert_chain_absent() {
  local chain=$1
  if "$real_iptables" -w -t nat -S | grep -F -- "$chain" >/dev/null; then
    fail "chain or reference still exists for $chain"
  fi
}

trace_line() {
  local pattern=$1
  local line
  line=$(grep -nF -- "$pattern" "$trace_path" | tail -n 1 | cut -d: -f1 || true)
  [[ -n "$line" ]] || fail "missing trace entry: $pattern"
  TRACE_LINE=$line
}

assert_publication_order() {
  local chain=$1
  trace_line "CMD -w -t nat -N $chain"
  local create_line=$TRACE_LINE
  trace_line "CMD -w -t nat -A $chain "
  local populate_line=$TRACE_LINE
  trace_line "CMD -w -t nat -A PREROUTING -j $chain"
  local publish_line=$TRACE_LINE
  ((create_line < populate_line && populate_line < publish_line)) ||
    fail "publication order was not create, populate, link for $chain"
}

assert_owner_lease_active() {
  local chain=$1
  local token=${chain#WW2_}
  token=${token%_4}
  grep -F -- "@waterwall.iptables.owner.v2.$token" /proc/net/unix >/dev/null ||
    fail "owner lease is not active for $chain"
}

active_path="$wrapper_dir:$original_path"

# No iptables capability: startup must perform no firewall command or ownership-socket operation.
start_instance "disabled" 40000 40000 "socket" "$disabled_path"
disabled_pid=$STARTED_PID
sleep 0.5
kill -0 "$disabled_pid" 2>/dev/null || fail "capability-disabled instance exited early"
[[ ! -s "$trace_path" ]] || fail "capability-disabled startup executed an iptables command"
if grep -F -- "@waterwall.iptables." /proc/net/unix >/dev/null; then
  fail "capability-disabled startup acquired an iptables lease"
fi
stop_instance "$disabled_pid"

# Preserve administrator-managed and legacy artifacts byte-for-byte.
"$real_iptables" -w -t nat -N WW_ADMIN_KEEP
"$real_iptables" -w -t nat -A WW_ADMIN_KEEP -j RETURN
"$real_iptables" -w -t nat -A PREROUTING -p tcp --dport 39999 -j WW_ADMIN_KEEP
"$real_iptables" -w -t nat -N WW_00000001_00000002_4
"$real_iptables" -w -t nat -A WW_00000001_00000002_4 -j RETURN
admin_before=$("$real_iptables" -w -t nat -S WW_ADMIN_KEEP)
legacy_before=$("$real_iptables" -w -t nat -S WW_00000001_00000002_4)

start_instance "owner-a" 41000 41001 "iptables" "$active_path"
owner_a_pid=$STARTED_PID
wait_for_chain "$owner_a_pid" "41000:41001"
owner_a_chain=$FOUND_CHAIN
assert_publication_order "$owner_a_chain"
assert_owner_lease_active "$owner_a_chain"

start_instance "owner-b" 42000 42001 "iptables" "$active_path"
owner_b_pid=$STARTED_PID
wait_for_chain "$owner_b_pid" "42000:42001"
owner_b_chain=$FOUND_CHAIN

start_instance "owner-c" 43000 43001 "iptables" "$active_path"
owner_c_pid=$STARTED_PID
wait_for_chain "$owner_c_pid" "43000:43001"
owner_c_chain=$FOUND_CHAIN
assert_chain_active "$owner_a_chain"
assert_chain_active "$owner_b_chain"
assert_chain_active "$owner_c_chain"

# A duplicate exact jump must also be removed after the owner crashes.
"$real_iptables" -w -t nat -A PREROUTING -j "$owner_a_chain"
kill -KILL "$owner_a_pid"
wait "$owner_a_pid" 2>/dev/null || true
forget_process "$owner_a_pid"

# A goto reference is unexpected: reconciliation must refuse publication and leave the chain untouched.
"$real_iptables" -w -t nat -N WW_ADMIN_GOTO
"$real_iptables" -w -t nat -A WW_ADMIN_GOTO -g "$owner_a_chain"
owner_a_before_guard=$("$real_iptables" -w -t nat -S "$owner_a_chain")
start_instance "goto-guard" 44000 44001 "iptables" "$active_path"
guard_pid=$STARTED_PID
for _ in $(seq 1 100); do
  if grep -F -- "refusing to install ipv4 iptables rules after failed startup recovery" \
      "$temp_dir/goto-guard/stdout.log" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
grep -F -- "refusing to install ipv4 iptables rules after failed startup recovery" \
  "$temp_dir/goto-guard/stdout.log" >/dev/null 2>&1 ||
  fail "goto-referenced stale chain did not fail startup promptly"
set +e
wait "$guard_pid"
guard_status=$?
set -e
forget_process "$guard_pid"
((guard_status != 0)) || fail "goto-referenced stale chain did not block publication"
owner_a_after_guard=$("$real_iptables" -w -t nat -S "$owner_a_chain")
[[ "$owner_a_before_guard" == "$owner_a_after_guard" ]] ||
  fail "goto-referenced stale chain was mutated"
"$real_iptables" -w -t nat -F WW_ADMIN_GOTO
"$real_iptables" -w -t nat -X WW_ADMIN_GOTO

start_instance "owner-d" 45000 45001 "iptables" "$active_path"
owner_d_pid=$STARTED_PID
wait_for_chain "$owner_d_pid" "45000:45001"
owner_d_chain=$FOUND_CHAIN
assert_chain_absent "$owner_a_chain"
assert_chain_active "$owner_b_chain"
assert_chain_active "$owner_c_chain"
assert_chain_active "$owner_d_chain"

admin_after=$("$real_iptables" -w -t nat -S WW_ADMIN_KEEP)
legacy_after=$("$real_iptables" -w -t nat -S WW_00000001_00000002_4)
[[ "$admin_before" == "$admin_after" ]] || fail "administrator-managed chain changed during reconciliation"
[[ "$legacy_before" == "$legacy_after" ]] || fail "legacy WaterWall chain changed during reconciliation"
"$real_iptables" -w -t nat -S PREROUTING | grep -Fx -- \
  "-A PREROUTING -p tcp -m tcp --dport 39999 -j WW_ADMIN_KEEP" >/dev/null ||
  fail "administrator-managed PREROUTING rule changed during reconciliation"

stop_instance "$owner_d_pid"
assert_chain_absent "$owner_d_chain"
trace_line "CMD -w -t nat -D PREROUTING -j $owner_d_chain"
unlink_line=$TRACE_LINE
trace_line "CMD -w -t nat -F $owner_d_chain"
flush_line=$TRACE_LINE
trace_line "CMD -w -t nat -X $owner_d_chain"
delete_line=$TRACE_LINE
((unlink_line < flush_line && flush_line < delete_line)) ||
  fail "shutdown order was not unlink, flush, delete for $owner_d_chain"
grep -Fx -- "LEASE_IN_USE $owner_d_chain" "$trace_path" >/dev/null ||
  fail "owner lease was released before chain deletion for $owner_d_chain"

# Normal shutdown must not flush a still-linked chain when jump deletion fails.
start_instance "owner-e" 46000 46001 "iptables" "$active_path"
owner_e_pid=$STARTED_PID
wait_for_chain "$owner_e_pid" "46000:46001"
owner_e_chain=$FOUND_CHAIN
owner_e_before_failure=$("$real_iptables" -w -t nat -S "$owner_e_chain")
printf '%s\n' "$owner_e_chain" >"$failure_path"
stop_instance "$owner_e_pid"
owner_e_after_failure=$("$real_iptables" -w -t nat -S "$owner_e_chain")
[[ "$owner_e_before_failure" == "$owner_e_after_failure" ]] ||
  fail "shutdown mutated a chain after jump deletion failed"
grep -Fx -- "FORCED_DELETE_JUMP_FAILURE $owner_e_chain" "$trace_path" >/dev/null ||
  fail "shutdown jump-deletion failure was not injected"
if grep -F -- "CMD -w -t nat -F $owner_e_chain" "$trace_path" >/dev/null ||
   grep -F -- "CMD -w -t nat -X $owner_e_chain" "$trace_path" >/dev/null; then
  fail "shutdown flushed or deleted a chain after jump deletion failed"
fi

: >"$failure_path"
start_instance "owner-f" 47000 47001 "iptables" "$active_path"
owner_f_pid=$STARTED_PID
wait_for_chain "$owner_f_pid" "47000:47001"
owner_f_chain=$FOUND_CHAIN
assert_chain_absent "$owner_e_chain"
stop_instance "$owner_f_pid"
assert_chain_absent "$owner_f_chain"

stop_instance "$owner_b_pid"
stop_instance "$owner_c_pid"
assert_chain_absent "$owner_b_chain"
assert_chain_absent "$owner_c_chain"

printf 'iptables crash-recovery integration test passed\n'
